# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Check user binding and token boundaries without making network requests."""
import json
import unittest
from unittest.mock import Mock, patch

import obo

USER = "00000000-0000-0000-0000-000000000001"
OTHER_USER = "00000000-0000-0000-0000-000000000002"


class OboTests(unittest.TestCase):
    def response(self, status=200, user=USER):
        response = Mock(status_code=status, headers={"request-id": "graph-request"})
        response.json.return_value = {"id": user, "displayName": "Must not be recorded"}
        return response

    def test_opaque_graph_token_and_matching_user(self):
        with patch.object(obo.requests, "get", return_value=self.response()) as get:
            row = obo.graph_me("opaque-token-for-graph", USER)
        self.assertTrue(row["passed"])
        args, kwargs = get.call_args
        self.assertEqual(args, (obo.GRAPH_ME,))
        self.assertEqual(kwargs["params"], {"$select": "id"})
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer opaque-token-for-graph")
        serialized = json.dumps(row)
        for sensitive in (USER, "opaque-token-for-graph", "Must not be recorded"):
            self.assertNotIn(sensitive, serialized)

    def test_graph_200_with_different_user_does_not_complete(self):
        with patch.object(obo.requests, "get", return_value=self.response(user=OTHER_USER)):
            self.assertFalse(obo.graph_me("opaque", USER)["passed"])

    def test_graph_error_with_id_does_not_complete(self):
        with patch.object(obo.requests, "get", return_value=self.response(status=403)):
            self.assertFalse(obo.graph_me("opaque", USER)["passed"])

    def test_invalid_token_a_never_reaches_exchange(self):
        middle = Mock()
        with patch.object(obo.entra, "verify", side_effect=ValueError):
            with self.assertRaises(ValueError):
                obo.exchange_and_call({}, "token-a", middle)
        middle.acquire_token_on_behalf_of.assert_not_called()

    def test_exchange_error_skips_graph_and_does_not_record_assertion(self):
        middle = Mock()
        middle.acquire_token_on_behalf_of.return_value = {
            "error": "interaction_required", "error_codes": [65001],
            "claims": "sensitive-claims-challenge", "error_description": "token-a",
        }
        with patch.object(obo.entra, "verify", return_value={"oid": USER}), \
             patch.object(obo, "graph_me") as graph:
            report = obo.exchange_and_call({}, "token-a", middle)
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(report["claims_challenge_received"])
        self.assertNotIn("token-a", json.dumps(report))
        self.assertNotIn("sensitive-claims-challenge", json.dumps(report))
        graph.assert_not_called()

    def test_exchange_uses_graph_scope_and_original_assertion(self):
        middle = Mock()
        middle.acquire_token_on_behalf_of.return_value = {"access_token": "opaque-graph-token"}
        with patch.object(obo.entra, "verify", return_value={"oid": USER}), \
             patch.object(obo, "graph_me", return_value={"passed": True}) as graph:
            report = obo.exchange_and_call({}, "token-a", middle)
        middle.acquire_token_on_behalf_of.assert_called_once_with(
            user_assertion="token-a", scopes=[obo.GRAPH_SCOPE],
        )
        graph.assert_called_once_with("opaque-graph-token", USER)
        self.assertEqual(report["status"], "passed")


if __name__ == "__main__":
    unittest.main()
