# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""HTTP failures must not create sessions, expose bodies, or complete identity checks."""
import json
import unittest
from unittest.mock import Mock, patch

import requests

from client import MCPClient, evidence
import obo


def response(status, payload, **headers):
    value = requests.Response()
    value.status_code = status
    value.url = "https://service.example.invalid/"
    value.headers.update(headers)
    value._content = json.dumps(payload).encode()
    value.json = Mock(wraps=value.json)
    return value


class HttpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = MCPClient("http://127.0.0.1:8000/mcp", bearer="test-bearer")
        self.client.session_id = "existing-session"

    def test_denied_calls_remain_observable_without_accepting_the_body_or_session(self):
        for status in (401, 403, 429, 500):
            with self.subTest(status=status):
                self.client.next_id = 0
                rejected = response(
                    status, {"id": 1, "result": {"credential": "must-not-escape"}},
                    **{"Mcp-Session-Id": "untrusted-session"},
                )
                with patch("client.requests.post", return_value=rejected) as post:
                    actual, value = self.client.rpc("tools/list")
                self.assertEqual(actual.status_code, status)
                self.assertIn("error", value)
                self.assertNotIn("must-not-escape", json.dumps(value))
                self.assertEqual(self.client.session_id, "existing-session")
                rejected.json.assert_not_called()
                self.assertFalse(post.call_args.kwargs["allow_redirects"])
                self.assertFalse(evidence("call", actual, value, expected_success=True)["passed"])
                self.assertEqual(evidence("denial", actual, value)["passed"], status in (401, 403))

    def test_redirect_does_not_forward_bearer_or_accept_a_session(self):
        redirected = response(
            302, {"id": 1, "result": {}},
            **{"Mcp-Session-Id": "untrusted-session", "Location": "https://unrelated.invalid/"},
        )
        with patch("client.requests.post", return_value=redirected) as post:
            _, value = self.client.rpc("tools/list")
        self.assertIn("error", value)
        self.assertEqual(self.client.session_id, "existing-session")
        redirected.json.assert_not_called()
        post.assert_called_once()
        self.assertFalse(post.call_args.kwargs["allow_redirects"])

    def test_success_accepts_session_only_after_matching_response_id(self):
        successful = response(200, {"id": 1, "result": {"tools": []}},
                              **{"Mcp-Session-Id": "verified-session"})
        with patch("client.requests.post", return_value=successful):
            _, value = self.client.rpc("tools/list")
        self.assertEqual(value["result"], {"tools": []})
        self.assertEqual(self.client.session_id, "verified-session")

    def test_mismatched_response_id_cannot_replace_session(self):
        mismatched = response(200, {"id": 999, "result": {}},
                              **{"Mcp-Session-Id": "untrusted-session"})
        with patch("client.requests.post", return_value=mismatched):
            with self.assertRaisesRegex(RuntimeError, "response ID mismatch"):
                self.client.rpc("tools/list")
        self.assertEqual(self.client.session_id, "existing-session")

    def test_empty_notification_response_is_accepted(self):
        accepted = response(204, None)
        accepted._content = b""
        with patch("client.requests.post", return_value=accepted):
            actual, value = self.client.rpc("notifications/initialized", notification=True)
        self.assertEqual(actual.status_code, 204)
        self.assertEqual(value, {})

    def test_graph_failures_and_redirects_never_parse_or_record_profile(self):
        user = "00000000-0000-0000-0000-000000000001"
        for status in (302, 401, 403, 429, 500):
            with self.subTest(status=status):
                rejected = response(status, {"id": user, "error": "must-not-escape"})
                with patch.object(obo.requests, "get", return_value=rejected):
                    report = obo.graph_me("test-graph-token", user)
                self.assertEqual(report["http_status"], status)
                self.assertFalse(report["passed"])
                self.assertFalse(report["same_user_as_verified_token_a"])
                rejected.json.assert_not_called()
                for sensitive in (user, "must-not-escape", "test-graph-token"):
                    self.assertNotIn(sensitive, json.dumps(report))

    def test_http_exception_without_response_fails_closed_without_raw_error_text(self):
        operations = (
            ("client.requests.post", lambda: self.client.rpc("tools/list")),
            ("obo.requests.get", lambda: obo.graph_me(
                "test-graph-token", "00000000-0000-0000-0000-000000000001",
            )),
        )
        for target, operation in operations:
            with self.subTest(target=target):
                with patch(target, side_effect=requests.HTTPError("must-not-escape")):
                    with self.assertRaises(RuntimeError) as raised:
                        operation()
                self.assertNotIn("must-not-escape", str(raised.exception))
                self.assertEqual(self.client.session_id, "existing-session")


if __name__ == "__main__":
    unittest.main()
