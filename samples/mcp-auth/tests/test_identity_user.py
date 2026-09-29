"""Local security and integration contract checks; these do not prove cloud OAuth."""
import copy
import json
import os
import time
import unittest
from unittest.mock import Mock, patch

from starlette.testclient import TestClient

import identity_user_core as core
import identity_user_server as server
import identity_user_web as web

CFG = {
    "account_id": "123456789012", "region": "cn-north-1",
    "tenant_id": "00000000-0000-0000-0000-000000000003",
    "api_app_id": "00000000-0000-0000-0000-000000000004",
    "client_app_id": "00000000-0000-0000-0000-000000000004",
    "authority_host": "https://login.partner.microsoftonline.cn", "scope": "agent.invoke",
    "workload_name": "test-custom-workload", "provider_name": "test-provider",
    "application_return_url": "https://test.execute-api.cn-north-1.amazonaws.com.cn/test/identity/callback",
    "runtime_url": "https://bedrock-agentcore.cn-north-1.amazonaws.com.cn/test",
}
ENV = {"IDENTITY_USER_CONFIG": json.dumps(CFG),
       "PORTAL_BASE_URL": "https://test.execute-api.cn-north-1.amazonaws.com.cn/test",
       "IDENTITY_USER_LOCATION": "agentcore_runtime"}


class NativeIdentityTests(unittest.TestCase):
    def test_invalid_employee_does_not_request_identity_token(self):
        with patch.dict(os.environ, ENV), patch.object(core.entra, "verify", side_effect=ValueError("raw-token")), \
                patch.object(core, "identity_client") as client:
            report = core.run("Bearer raw-token")
        client.assert_not_called()
        self.assertEqual(report["stage"], "inbound_token")
        self.assertNotIn("raw-token", json.dumps(report))

    def test_user_federation_uses_jwt_identity_and_native_token_for_graph(self):
        client = Mock()
        client.get_workload_access_token_for_jwt.return_value = {
            "workloadAccessToken": "workload-private", "ResponseMetadata": {"RequestId": "workload-request"},
        }
        client.get_resource_oauth2_token.return_value = {
            "accessToken": "graph-private", "ResponseMetadata": {"RequestId": "identity-request"},
        }
        with patch.dict(os.environ, ENV), patch.object(core.entra, "verify", return_value={"oid": "employee"}), \
                patch.object(core, "identity_client", return_value=client), \
                patch.object(core.obo, "graph_me", return_value={"http_status": 200, "passed": True}) as graph:
            report = core.run("Bearer employee-private")
        self.assertEqual(report["status"], "passed")
        client.get_workload_access_token_for_jwt.assert_called_once_with(
            workloadName="test-custom-workload", userToken="employee-private",
        )
        self.assertEqual(client.get_resource_oauth2_token.call_args.kwargs["oauth2Flow"], "USER_FEDERATION")
        graph.assert_called_once_with("graph-private", "employee")
        self.assertNotIn("-private", json.dumps(report))

    def test_begin_contains_state_and_forces_new_user_authorization(self):
        client = Mock()
        client.get_workload_access_token_for_jwt.return_value = {
            "workloadAccessToken": "workload", "ResponseMetadata": {},
        }
        client.get_resource_oauth2_token.return_value = {
            "authorizationUrl": CFG["authority_host"] + "/authorize",
            "sessionUri": "session-uri", "ResponseMetadata": {},
        }
        with patch.dict(os.environ, ENV), patch.object(core.entra, "verify", return_value={"oid": "employee"}), \
                patch.object(core, "identity_client", return_value=client):
            result = core.run("Bearer token", begin=True)
        sent = client.get_resource_oauth2_token.call_args.kwargs
        self.assertTrue(sent["forceAuthentication"])
        self.assertEqual(sent["customState"], result["custom_state"])
        self.assertEqual(result["session_uri"], "session-uri")
        self.assertNotIn("authorization_url", web.safe_report(result))

    def test_authorization_redirect_is_china_allowlisted(self):
        for url in ("https://evil.test", "https://login.partner.microsoftonline.cn.evil.test",
                    "https://user@login.partner.microsoftonline.cn", "http://login.partner.microsoftonline.cn"):
            with self.assertRaises(ValueError):
                core.validate_authorization_url(url, CFG)

    def test_mcp_tools_obtain_token_from_request_not_arguments(self):
        app = server.server.streamable_http_app(json_response=True, stateless_http=True, host="127.0.0.1")
        headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-03-26",
                   "Authorization": "Bearer private-employee-token"}
        with TestClient(app, base_url="http://127.0.0.1:8000") as client, \
                patch.object(server, "run", return_value={"status": "local_stub"}) as run:
            listed = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1,
                                                               "method": "tools/list", "params": {}})
            self.assertEqual(listed.status_code, 200)
            tools = listed.json()["result"]["tools"]
            self.assertEqual({tool["name"] for tool in tools}, {core.BEGIN_TOOL, core.CHECK_TOOL})
            self.assertTrue(all(not tool["inputSchema"].get("properties") for tool in tools))
            called = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 2,
                "method": "tools/call", "params": {"name": core.CHECK_TOOL, "arguments": {}}})
            self.assertEqual(called.status_code, 200)
            run.assert_called_once_with("Bearer private-employee-token")
            self.assertNotIn("private-employee-token", called.text)


class BrowserBindingTests(unittest.TestCase):
    def setUp(self):
        self.pending = {"session_uri": "session-one", "custom_state": "state-one",
                        "expires_at": int(time.time()) + 300}
        self.session = {"phase": "authorization_ready", "pending": self.pending, "csrf": "csrf-one"}
        self.params = {"session_id": "session-one", "state": "state-one"}

    def test_callback_requires_current_browser_cookie(self):
        with patch.dict(os.environ, ENV), patch.object(web, "Store") as store:
            result = web.handler({"path": "/identity/callback", "httpMethod": "GET",
                                  "queryStringParameters": self.params}, None)
        self.assertEqual(result["statusCode"], 401)
        store.return_value.get.assert_not_called()

    def test_callback_requires_matching_state_and_uri_and_not_replayed(self):
        self.assertEqual(web.callback_transaction(self.session, self.params), self.pending)
        for params in ({}, {"session_id": "session-one", "state": "other"},
                       {"session_id": "other", "state": "state-one"},
                       {**self.params, "customState": "state-one"}):
            with self.assertRaises(web.WebError):
                web.callback_transaction(self.session, params)
        with self.assertRaises(web.WebError):
            web.callback_transaction({**self.session, "phase": "binding"}, self.params)

    def test_callback_expiration_enforced_before_dynamodb_ttl_deletion(self):
        self.pending["expires_at"] = int(time.time()) - 1
        with self.assertRaises(web.WebError):
            web.callback_transaction(self.session, self.params)

    def test_csrf_requires_both_same_origin_and_session_token(self):
        origin = "https://test.execute-api.cn-north-1.amazonaws.com.cn"
        with patch.dict(os.environ, ENV):
            web.check_csrf({"headers": {"Origin": origin, "X-CSRF-Token": "csrf-one"}}, self.session)
            for headers in ({}, {"Origin": origin, "X-CSRF-Token": "other"},
                            {"Origin": "https://evil.test", "X-CSRF-Token": "csrf-one"}):
                with self.assertRaises(web.WebError):
                    web.check_csrf({"headers": headers}, self.session)

    def test_export_does_not_include_tokens_authorization_uri_or_profile(self):
        report = web.safe_report({"status": "passed", "access_token": "private-token",
            "authorization_url": "private-url", "session_uri": "private-session", "custom_state": "private-state",
            "graph": {"http_status": 200, "user_id": "private-user", "displayName": "private-name"}})
        self.assertEqual(report, {"status": "passed", "graph": {"http_status": 200}})

    def test_session_cookie_is_secure_httponly_host_scoped(self):
        cookie = web.cookie(web.SESSION_COOKIE, "opaque", 900)
        self.assertTrue(cookie.startswith("__Host-"))
        self.assertIn("Secure; HttpOnly; SameSite=Lax", cookie)
        self.assertIn("Path=/", cookie)
        self.assertNotIn("Domain=", cookie)

    def test_worker_binds_only_verified_current_browser_session_employee(self):
        current = {
            "token": "current-browser-token", "oid": "current-user", "phase": "binding",
            "pending": self.pending, "job_id": "job", "expires": int(time.time()) + 500, "_revision": 1,
        }
        store, identity = Mock(), Mock()
        store.get.return_value = copy.deepcopy(current)
        identity.complete_resource_token_auth.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        with patch.dict(os.environ, ENV), patch.object(web, "Store", return_value=store), \
                patch.object(web.entra, "verify", return_value={"oid": "current-user"}), \
                patch.object(web, "identity_client", return_value=identity):
            web.worker({"internal_job": "complete", "key": "cookie-selected-session", "job_id": "job"})
        identity.complete_resource_token_auth.assert_called_once_with(
            userIdentifier={"userToken": "current-browser-token"}, sessionUri="session-one",
        )
        self.assertEqual(store.replace.call_args.args[1]["phase"], "authorized")
        self.assertNotIn("pending", store.replace.call_args.args[1])

    def test_changed_user_stops_native_completion(self):
        current = {"token": "token", "oid": "first", "phase": "binding", "pending": self.pending,
                   "job_id": "job", "_revision": 1}
        store = Mock()
        store.get.return_value = current
        with patch.dict(os.environ, ENV), patch.object(web, "Store", return_value=store), \
                patch.object(web.entra, "verify", return_value={"oid": "second"}), \
                patch.object(web, "identity_client") as identity:
            web.worker({"internal_job": "complete", "key": "current", "job_id": "job"})
        identity.assert_not_called()
        self.assertEqual(current["report"]["error"], "current_employee_mismatch")

    def test_http_200_without_graph_same_user_is_not_success(self):
        current = {"token": "token", "oid": "employee", "phase": "working", "job_id": "job", "_revision": 1,
                   "login": {}, "binding": {"http_status": 200}}
        store = Mock()
        store.get.return_value = current
        result = {"status": "passed", "agentcore_runtime_used": True, "agentcore_identity_used": True,
                  "identity_access_token_received": True, "graph": {"http_status": 200,
                  "same_user_as_verified_token_a": False}}
        with patch.dict(os.environ, ENV), patch.object(web, "Store", return_value=store), \
                patch.object(web.entra, "verify", return_value={"oid": "employee"}), \
                patch.object(web, "call_runtime", return_value=(result, [{"http_status": 200}])):
            web.worker({"internal_job": "check", "key": "current", "job_id": "job"})
        self.assertEqual(current["report"]["status"], "failed")

    def test_duplicate_worker_does_not_repeat_exchange(self):
        store = Mock()
        store.get.return_value = {"job_id": "job", "phase": "binding", "worker_claimed": True}
        with patch.dict(os.environ, ENV), patch.object(web, "Store", return_value=store), \
                patch.object(web, "identity_client") as identity:
            self.assertEqual(web.worker({"internal_job": "complete", "key": "current", "job_id": "job"}), {"ignored": True})
        identity.assert_not_called()


if __name__ == "__main__":
    unittest.main()
