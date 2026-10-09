"""Offline regression checks for the demo's permission and authentication boundaries."""

import fnmatch
import json
import re
import unittest
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = json.loads(
    (ROOT / "practice/templates/parts-stock-demo.cfn.json").read_text()
)
OPENAPI = json.loads((ROOT / "practice/schemas/graph-me.openapi.json").read_text())
CONTEXT_KEY = "kms:EncryptionContext:aws:logs:arn"


def render(value, partition="aws-cn", region="cn-north-1"):
    """Resolve the intrinsics used by these policies; this is not an IAM simulator."""
    substitutions = {
        "AWS::Partition": partition,
        "AWS::Region": region,
        "AWS::AccountId": "123456789012",
        "AWS::URLSuffix": "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com",
        "PracticeName": "security-test",
    }
    if isinstance(value, dict):
        if set(value) == {"Fn::Sub"}:
            return re.sub(
                r"\$\{([^}]+)\}",
                lambda match: substitutions[match[1]],
                value["Fn::Sub"],
            )
        if set(value) == {"Fn::GetAtt"}:
            if value["Fn::GetAtt"] != ["StockEncryptionKey", "Arn"]:
                raise AssertionError("Review newly referenced permission resources")
            return f"arn:{partition}:kms:{region}:123456789012:key/demo-key"
        return {key: render(item, partition, region) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, partition, region) for item in value]
    return value


class PracticeSecurityTests(unittest.TestCase):
    def test_logs_permissions_cannot_reach_other_groups_or_accounts(self):
        policies = TEMPLATE["Resources"]["StockExecutionRole"]["Properties"]["Policies"]
        log_statements = [
            statement
            for policy in policies
            for statement in policy["PolicyDocument"]["Statement"]
            if any(action.startswith("logs:") for action in statement["Action"])
        ]
        self.assertTrue(log_statements)
        for partition, region in (
            ("aws-cn", "cn-north-1"),
            ("aws-cn", "cn-northwest-1"),
            ("aws", "us-east-1"),
        ):
            group = (
                f"arn:{partition}:logs:{region}:123456789012:"
                "log-group:/aws/lambda/security-test-stock"
            )
            for raw in log_statements:
                statement = render(raw, partition, region)
                self.assertEqual(statement["Effect"], "Allow")
                self.assertEqual(
                    set(statement["Action"]), {"logs:CreateLogStream", "logs:PutLogEvents"}
                )
                self.assertTrue(
                    fnmatch.fnmatchcase(group + ":log-stream:2026/10/09/stream", statement["Resource"])
                )
                for forbidden in (
                    group,
                    group + "-other:log-stream:stream",
                    group.replace("123456789012", "999999999999") + ":log-stream:stream",
                ):
                    self.assertFalse(fnmatch.fnmatchcase(forbidden, statement["Resource"]))

    def test_key_use_is_scoped_to_logs_and_exact_encryption_context(self):
        resources = TEMPLATE["Resources"]
        key_policy = resources["StockEncryptionKey"]["Properties"]["KeyPolicy"]
        self.assertTrue(resources["StockEncryptionKey"]["Properties"]["EnableKeyRotation"])
        for partition, region in (
            ("aws-cn", "cn-north-1"),
            ("aws-cn", "cn-northwest-1"),
            ("aws", "us-east-1"),
        ):
            group = (
                f"arn:{partition}:logs:{region}:123456789012:"
                "log-group:/aws/lambda/security-test-stock"
            )
            statements = render(key_policy["Statement"], partition, region)
            delegated = next(s for s in statements if "AWS" in s["Principal"])
            self.assertEqual(
                delegated["Principal"]["AWS"], f"arn:{partition}:iam::123456789012:root"
            )
            service = next(s for s in statements if "Service" in s["Principal"])
            suffix = "amazonaws.com.cn" if partition == "aws-cn" else "amazonaws.com"
            self.assertEqual(service["Principal"]["Service"], f"logs.{region}.{suffix}")
            self.assertEqual(service["Condition"]["ArnEquals"][CONTEXT_KEY], group)
            role = render(resources["StockExecutionRole"]["Properties"], partition, region)
            crypto = [
                statement
                for policy in role["Policies"]
                for statement in policy["PolicyDocument"]["Statement"]
                if any(action.startswith("kms:") for action in statement["Action"])
            ]
            self.assertTrue(crypto)
            for statement in crypto:
                self.assertEqual(
                    statement["Resource"],
                    f"arn:{partition}:kms:{region}:123456789012:key/demo-key",
                )
                self.assertEqual(statement["Condition"]["ArnEquals"][CONTEXT_KEY], group)
                self.assertEqual(
                    statement["Condition"]["StringEquals"]["kms:ViaService"],
                    f"logs.{region}.amazonaws.com",
                )
                self.assertLessEqual(
                    set(statement["Action"]),
                    {
                        "kms:Encrypt", "kms:Decrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo",
                        "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext",
                    },
                )

    def test_precreated_logs_and_encryption_are_wired_to_function(self):
        resources = TEMPLATE["Resources"]
        function = resources["StockFunction"]
        self.assertIn("StockLogs", function["DependsOn"])
        log_name = resources["StockLogs"]["Properties"]["LogGroupName"]["Fn::Sub"]
        function_name = function["Properties"]["FunctionName"]["Fn::Sub"]
        self.assertEqual(log_name, "/aws/lambda/" + function_name)
        key = {"Fn::GetAtt": ["StockEncryptionKey", "Arn"]}
        self.assertEqual(resources["StockLogs"]["Properties"]["KmsKeyId"], key)
        self.assertEqual(function["Properties"]["KmsKeyArn"], key)
        self.assertGreater(function["Properties"]["ReservedConcurrentExecutions"], 0)

    def test_exceptions_remain_local_and_documented(self):
        resources = TEMPLATE["Resources"]
        self.assertNotIn("checkov", TEMPLATE.get("Metadata", {}))
        self.assertNotIn("cfn_nag", TEMPLATE.get("Metadata", {}))
        for name, resource in resources.items():
            metadata = resource.get("Metadata", {})
            if name != "StockFunction":
                self.assertNotIn("checkov", metadata)
                self.assertNotIn("cfn_nag", metadata)
                continue
            skips = metadata["checkov"]["skip"]
            self.assertEqual({s["id"] for s in skips}, {"CKV_AWS_116", "CKV_AWS_117"})
            self.assertTrue(all(s["comment"] for s in skips))
            nag = metadata["cfn_nag"]["rules_to_suppress"]
            self.assertEqual({s["id"] for s in nag}, {"W58", "W89"})
            self.assertTrue(all(s["reason"] for s in nag))

    def test_every_operation_requires_bearer_without_anonymous_alternative(self):
        schemes = OPENAPI["components"]["securitySchemes"]
        levels = [OPENAPI]
        for path in OPENAPI["paths"].values():
            levels.extend(
                operation
                for method, operation in path.items()
                if method in {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
            )
        self.assertGreater(len(levels), 1)
        for level in levels:
            self.assertTrue(level["security"])
            for alternative in level["security"]:
                self.assertTrue(alternative, "An empty security object allows anonymous access")
                for name, scopes in alternative.items():
                    self.assertEqual(schemes[name]["type"], "http")
                    self.assertEqual(schemes[name]["scheme"], "bearer")
                    self.assertEqual(
                        schemes[name].get("bearerFormat", "opaque").casefold(), "opaque"
                    )
                    self.assertEqual(scopes, [])

    def assert_https_graph_servers(self, document):
        """Check transport independently of the legacy CKV_OPENAPI_3 exception."""
        self.assertTrue(document.get("servers"), "The default server must be explicit")
        levels = [document]
        for path in document["paths"].values():
            levels.append(path)
            levels.extend(
                operation
                for method, operation in path.items()
                if method in {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
            )
        for level in levels:
            if "servers" not in level:
                continue
            self.assertTrue(level["servers"], "An empty override removes the HTTPS guarantee")
            for server in level["servers"]:
                url = urlsplit(server["url"])
                self.assertEqual(url.scheme, "https")
                self.assertEqual(url.hostname, "microsoftgraph.chinacloudapi.cn")
                self.assertIn(url.port, (None, 443))
                self.assertIsNone(url.username)
                self.assertIsNone(url.password)
                self.assertFalse(url.query, "Credentials must not be supplied in the URL")
                self.assertFalse(url.fragment)

    def test_graph_servers_use_https_without_url_credentials(self):
        self.assert_https_graph_servers(OPENAPI)

    def test_transport_guard_rejects_insecure_server_overrides(self):
        for scope in ("document", "path", "operation"):
            for replacement in (
                # Negative-only transport fixture; never used for a network request.
                [{"url": "http://microsoftgraph.chinacloudapi.cn/v1.0"}],
                [],
            ):
                with self.subTest(scope=scope, servers=replacement):
                    document = deepcopy(OPENAPI)
                    level = {
                        "document": document,
                        "path": document["paths"]["/me"],
                        "operation": document["paths"]["/me"]["get"],
                    }[scope]
                    level["servers"] = replacement
                    with self.assertRaises(AssertionError):
                        self.assert_https_graph_servers(document)

    def test_openapi_exception_is_limited_to_the_known_bearer_false_positive(self):
        annotation = OPENAPI["components"]["securitySchemes"]["GraphBearerAuth"]["x-checkov"]
        self.assertTrue(annotation.startswith("checkov:skip=CKV_OPENAPI_3:"))
        self.assertEqual(
            re.findall(r"checkov:skip=([^:\s\"]+)", json.dumps(OPENAPI)), ["CKV_OPENAPI_3"]
        )


if __name__ == "__main__":
    unittest.main()
