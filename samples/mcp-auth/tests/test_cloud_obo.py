# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Local checks for header propagation, user binding and credential boundaries."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from starlette.testclient import TestClient

import cloud_obo_client as employee
import cloud_obo_core as core
import cloud_obo_server as server
import obo

CFG = {
    "account_id": "123456789012", "region": "cn-north-1",
    "tenant_id": "00000000-0000-0000-0000-000000000003",
    "api_app_id": "00000000-0000-0000-0000-000000000004",
    "client_app_id": "00000000-0000-0000-0000-000000000004",
    "authority_host": "https://login.partner.microsoftonline.cn", "scope": "agent.invoke",
}


class CloudOboTests(unittest.TestCase):
    def test_no_authorization_does_not_load_credentials(self):
        with patch.object(core, "load_secret") as secret:
            report = core.run_identity_check("")
        secret.assert_not_called()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["stage"], "request_authorization")

    def test_token_a_must_validate_before_secrets_manager(self):
        with patch.dict(os.environ, {"CLOUD_OBO_CONFIG": json.dumps(CFG)}), \
             patch.object(obo.entra, "verify", side_effect=ValueError("sensitive-token")), \
             patch.object(core, "load_secret") as secret:
            report = core.run_identity_check("Bearer sensitive-token")
        secret.assert_not_called()
        self.assertEqual(report["status"], "failed")
        self.assertNotIn("sensitive-token", json.dumps(report))

    def test_secret_must_be_in_expected_account_region_and_partition(self):
        with patch.dict(os.environ, {"CLOUD_OBO_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:other"}), \
             patch.object(core.boto3, "client") as client:
            with self.assertRaises(ValueError):
                core.load_secret(CFG)
        client.assert_not_called()

    def test_secret_is_bound_to_middle_tier_application(self):
        client = Mock()
        client.get_secret_value.return_value = {"SecretString": json.dumps({
            "client_id": "different-app", "tenant_id": CFG["tenant_id"],
        })}
        with patch.dict(os.environ, {"CLOUD_OBO_SECRET_ARN": "arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:test"}), \
             patch.object(core.boto3, "client", return_value=client):
            with self.assertRaises(ValueError):
                core.load_secret(CFG)

    def test_streamable_http_context_header_and_no_token_argument(self):
        app = server.server.streamable_http_app(
            json_response=True, stateless_http=True, host="127.0.0.1",
        )
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json", "MCP-Protocol-Version": "2025-03-26",
            "Authorization": "Bearer transient-user-assertion",
        }
        with TestClient(app, base_url="http://127.0.0.1:8000") as client, \
             patch.object(server, "run_identity_check", return_value={"status": "local_stub"}) as run:
            def rpc(method, params):
                return client.post("/mcp", headers=headers, json={
                    "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
                })
            initialized = rpc("initialize", {
                "protocolVersion": "2025-03-26", "capabilities": {},
                "clientInfo": {"name": "local-boundary-test", "version": "1"},
            })
            self.assertEqual(initialized.status_code, 200)
            listed = rpc("tools/list", {})
            self.assertEqual(listed.status_code, 200)
            tools = listed.json()["result"]["tools"]
            self.assertEqual(len(tools), 1)
            self.assertEqual(tools[0]["name"], core.TOOL_NAME)
            self.assertFalse(tools[0]["inputSchema"].get("properties"))
            called = rpc("tools/call", {"name": core.TOOL_NAME, "arguments": {}})
            self.assertEqual(called.status_code, 200)
            self.assertFalse(called.json()["result"].get("isError"))
            self.assertEqual(employee.safe_cloud_result(called.json()["result"])["status"], "local_stub")
            run.assert_called_once_with("Bearer transient-user-assertion")
            self.assertNotIn("transient-user-assertion", called.text)

    def test_cloud_result_saves_only_allowlisted_evidence(self):
        safe = employee.safe_cloud_result({"structuredContent": {
            "status": "failed", "access_token": "private-token",
            "cases": [{"http_status": 200, "id": "private-user-id", "private_key": "private-key"}],
        }})
        self.assertEqual(safe, {"status": "failed", "cases": [{"http_status": 200}]})

    def test_http_200_with_incomplete_graph_call_is_not_success(self):
        response = Mock(status_code=200, headers={})
        mcp = Mock()
        mcp.initialize.return_value = response, {"result": {}}
        mcp.rpc.side_effect = [
            (response, {"result": {"tools": [{"name": core.TOOL_NAME, "inputSchema": {"properties": {}}}]}}),
            (response, {"result": {"structuredContent": {
                "status": "passed", "agentcore_runtime_used": True, "agentcore_identity_used": False,
                "execution_location": "agentcore_runtime", "client_authentication": "certificate",
                "token_a_validated": True, "obo_access_token_received": True,
                "cases": [{"http_status": 200, "same_user_as_verified_token_a": False}],
            }}}),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".state").mkdir()
            (root / ".state/cloud-obo-deployment.json").write_text(json.dumps({"runtime": {"url": "placeholder"}}))
            with patch.object(employee.local, "ROOT", root), \
                 patch.object(employee.entra, "verify"), patch.object(employee, "MCPClient", return_value=mcp):
                rows = employee.test_cloud(CFG, "transient")
        self.assertEqual(len(rows), 3)
        self.assertFalse(rows[-1]["passed"])


if __name__ == "__main__":
    unittest.main()
