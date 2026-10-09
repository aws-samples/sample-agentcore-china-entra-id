# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Regression checks for OAuth Gateway resource tracking and credential boundaries."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import gateway_oauth
import lab


class GatewayOAuthTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {
            "account_id": "123456789012", "region": "cn-north-1", "tenant_id": "tenant",
            "api_app_id": "api", "client_app_id": "api", "machine_client_app_id": "api",
            "machine_role": "Mcp.Tools.Invoke", "scope": "agent.invoke",
            "authority_host": "https://login.partner.microsoftonline.cn",
            "gateway_prefix": "sample", "runtime_prefix": "sample", "project_tag": "sample",
        }
        base = "arn:aws-cn:bedrock-agentcore:cn-north-1:123456789012"
        self.provider = {
            "name": "sample-provider", "arn": base + ":token-vault/default/oauth2credentialprovider/sample",
            "client_secret_arn": "arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:sample",
        }
        self.runtime = {"id": "runtime", "arn": base + ":runtime/runtime"}
        self.runtime["url"] = lab.runtime_url(self.cfg, self.runtime["arn"])
        self.created = {
            "gatewayId": "sample-oauth-id", "gatewayArn": base + ":gateway/sample-oauth-id",
            "gatewayUrl": "https://sample-oauth-id.gateway.bedrock-agentcore.cn-north-1.amazonaws.com.cn/mcp",
        }
        self.workload = base + ":workload-identity-directory/default/workload-identity/sample-oauth-id"
        self.role = "arn:aws-cn:iam::123456789012:role/sample_gateway_oauth_role"
        self.control = MagicMock()
        self.control.get_agent_runtime.return_value = {
            "status": "READY", "agentRuntimeArn": self.runtime["arn"],
            "authorizerConfiguration": lab.authorizer(self.cfg, "app"),
        }
        self.control.get_oauth2_credential_provider.return_value = {
            "credentialProviderArn": self.provider["arn"],
            "clientSecretArn": {"secretArn": self.provider["client_secret_arn"]},
            "oauth2ProviderConfigOutput": {"customOauth2ProviderConfig": {"clientId": "api"}},
        }
        self.control.get_paginator.return_value.paginate.return_value = [{"items": []}]
        self.control.create_gateway.return_value = self.created
        self.control.get_gateway.return_value = {
            **self.created, "status": "READY", "roleArn": self.role, "authorizerType": "AWS_IAM",
            "workloadIdentityDetails": {"workloadIdentityArn": self.workload},
        }
        self.control.create_gateway_target.return_value = {"targetId": "target"}
        self.control.get_gateway_target.return_value = {
            **gateway_oauth.oauth_target(self.cfg, self.provider, self.runtime["url"]), "status": "READY",
        }
        self.session = MagicMock()
        self.session.client.return_value = self.control

    def test_create_without_workload_details_is_saved_before_waiting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_file = root / ".state/gateway.json"

            def ready(get, label):
                if label == "OAuth Gateway":
                    saved = json.loads(state_file.read_text())
                    self.assertEqual(saved["id"], self.created["gatewayId"])
                    self.assertNotIn("workload_arn", saved)
                return get()

            with patch.object(gateway_oauth, "STATE", state_file), \
                 patch.object(lab, "ROOT", root), \
                 patch.object(gateway_oauth, "provider_state", return_value=self.provider), \
                 patch.object(lab, "read_state", return_value={"runtimes": {"app": self.runtime}}), \
                 patch.object(lab, "ensure_role", return_value=self.role), \
                 patch.object(gateway_oauth, "wait_ready", side_effect=ready):
                state = gateway_oauth.deploy(self.cfg, self.session)
            self.assertEqual(state["workload_arn"], self.workload)
            self.assertEqual(state["target_id"], "target")
            self.control.create_gateway.assert_called_once()

    def test_unrelated_endpoint_stops_before_provider_and_gateway_operations(self):
        altered = {**self.runtime, "url": "https://unrelated.example/mcp"}
        with patch.object(gateway_oauth, "provider_state", return_value=self.provider), \
             patch.object(lab, "read_state", return_value={"runtimes": {"app": altered}}):
            with self.assertRaisesRegex(RuntimeError, "endpoint differs"):
                gateway_oauth.deploy(self.cfg, self.session)
        self.control.get_oauth2_credential_provider.assert_not_called()
        self.control.create_gateway.assert_not_called()
        self.control.create_gateway_target.assert_not_called()

    def test_service_role_has_only_scoped_identity_and_secret_permissions(self):
        policy = gateway_oauth.service_policy(self.cfg, self.provider, self.workload)
        actions = {action for statement in policy["Statement"] for action in statement["Action"]}
        self.assertEqual(actions, {
            "bedrock-agentcore:GetWorkloadAccessToken",
            "bedrock-agentcore:GetResourceOauth2Token",
            "secretsmanager:GetSecretValue",
        })
        for statement in policy["Statement"]:
            resources = statement["Resource"]
            if isinstance(resources, str):
                resources = [resources]
            self.assertTrue(all("*" not in resource for resource in resources))
        self.assertEqual(policy["Statement"][-1]["Resource"], self.provider["client_secret_arn"])


class GatewayReadinessTests(unittest.TestCase):
    def test_ready_result_returns_without_waiting(self):
        get = MagicMock(return_value={"status": "READY", "gatewayId": "tracked"})
        with patch.object(gateway_oauth.time, "sleep") as sleep:
            result = gateway_oauth.wait_ready(get, "Gateway")
        self.assertEqual(result["gatewayId"], "tracked")
        get.assert_called_once()
        sleep.assert_not_called()

    def test_waits_between_status_checks_until_ready(self):
        get = MagicMock(side_effect=[{"status": "CREATING"}, {"status": "READY"}])
        with patch.object(gateway_oauth.time, "sleep") as sleep:
            self.assertEqual(gateway_oauth.wait_ready(get, "Gateway")["status"], "READY")
        self.assertEqual(get.call_count, 2)
        sleep.assert_called_once_with(5)

    def test_terminal_failure_never_waits_or_reports_success(self):
        for status in ("FAILED", "CREATE_FAILED", "UPDATE_UNSUCCESSFUL"):
            with self.subTest(status=status):
                with patch.object(gateway_oauth.time, "sleep") as sleep:
                    with self.assertRaisesRegex(RuntimeError, "failed"):
                        gateway_oauth.wait_ready(lambda: {"status": status}, "Gateway")
                sleep.assert_not_called()

    def test_provisioning_timeout_is_bounded_and_does_not_sleep_after_last_check(self):
        get = MagicMock(return_value={"status": "CREATING"})
        with patch.object(gateway_oauth.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "still provisioning"):
                gateway_oauth.wait_ready(get, "Gateway")
        self.assertEqual(get.call_count, 30)
        self.assertEqual(sleep.call_count, 29)
        self.assertTrue(all(call.args == (5,) for call in sleep.call_args_list))


if __name__ == "__main__":
    unittest.main()
