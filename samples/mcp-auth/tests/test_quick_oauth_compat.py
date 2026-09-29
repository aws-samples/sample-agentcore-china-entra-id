"""OAuth binding, parameter conversion and credential logging boundaries."""
import base64
from contextlib import redirect_stdout
import io
import json
import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import quick_oauth_compat as compat


class QuickOAuthCompatTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {
            "tenant_id": "b2081eba-d051-4b2b-b897-6fb4674d562e",
            "client_id": "e9d35449-4d98-49a2-880f-224548b62f83",
            "api_app_id": "e9d35449-4d98-49a2-880f-224548b62f83",
            "authority_host": "https://login.partner.microsoftonline.cn",
            "scope": "agent.invoke",
            "resource_uri": "https://sample-jwt-0123456789.gateway.bedrock-agentcore.cn-north-1.amazonaws.com.cn/mcp",
            "redirect_uri": "https://us-east-1.quicksight.aws.amazon.com/sn/oauthcallback",
        }
        self.params = {
            "client_id": self.cfg["client_id"], "redirect_uri": self.cfg["redirect_uri"],
            "response_type": "code", "scope": "agent.invoke",
            "state": "PRIVATE-STATE-CANARY", "resource": self.cfg["resource_uri"],
            "code_challenge_method": "S256", "code_challenge": "X" * 43,
        }
        self.token = {
            "client_id": self.cfg["client_id"], "client_secret": "PRIVATE-SECRET-CANARY",
            "grant_type": "authorization_code", "code": "PRIVATE-CODE-CANARY",
            "code_verifier": "V" * 64, "redirect_uri": self.cfg["redirect_uri"],
            "resource": self.cfg["resource_uri"], "scope": "agent.invoke",
        }
        env = patch.dict(os.environ, {"QUICK_OAUTH_COMPAT_CONFIG": json.dumps(self.cfg)})
        env.start()
        self.addCleanup(env.stop)

    def authorize_event(self, params=None):
        return {
            "path": "/authorize", "httpMethod": "GET",
            "multiValueQueryStringParameters": {
                key: [value] for key, value in (params or self.params).items()
            },
        }

    def token_event(self, params=None, authorization=None):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if authorization:
            headers["Authorization"] = authorization
        return {"path": "/token", "httpMethod": "POST", "headers": headers,
                "body": urlencode(self.token if params is None else params)}

    def test_preserves_oauth_binding_and_maps_only_the_known_api_scope(self):
        response = compat.handler(self.authorize_event(), None)
        self.assertEqual(response["statusCode"], 302)
        location = urlsplit(response["headers"]["Location"])
        query = parse_qs(location.query)
        self.assertEqual(location.netloc, "login.partner.microsoftonline.cn")
        self.assertEqual(location.path, "/" + self.cfg["tenant_id"] + "/oauth2/v2.0/authorize")
        for key in ("client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method"):
            self.assertEqual(query[key], [self.params[key]])
        self.assertEqual(query["scope"], [self.cfg["api_app_id"] + "/agent.invoke"])
        self.assertNotIn("resource", query)
        self.assertNotIn("offline_access", query["scope"][0])
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")

    def test_wrong_client_resource_or_callback_never_redirects(self):
        for key, value in [
            ("client_id", "another-client"),
            ("resource", "https://unrelated.example/mcp"),
            ("redirect_uri", "https://unrelated.example/callback"),
        ]:
            with self.subTest(key=key):
                response = compat.handler(self.authorize_event({**self.params, key: value}), None)
                self.assertEqual(response["statusCode"], 400)
                self.assertNotIn("Location", response["headers"])
                self.assertNotIn(value, response["body"])

    def test_duplicate_resource_is_rejected_instead_of_choosing_one(self):
        event = self.authorize_event()
        event["multiValueQueryStringParameters"]["resource"].append(self.cfg["api_app_id"])
        response = compat.handler(event, None)
        self.assertEqual(response["statusCode"], 400)
        self.assertNotIn("Location", response["headers"])

    def test_missing_or_plain_pkce_does_not_reach_entra(self):
        for change in [{"code_challenge_method": "plain"}, {"code_challenge": ""}]:
            with self.subTest(change=change):
                response = compat.handler(self.authorize_event({**self.params, **change}), None)
                self.assertEqual(response["statusCode"], 400)
                self.assertNotIn("Location", response["headers"])

    def test_scope_cannot_expand_to_another_api_or_application_roles(self):
        for scope in ["User.Read", "https://graph.microsoft.com/.default",
                      self.cfg["api_app_id"] + "/.default", "agent.invoke User.Read.All"]:
            with self.subTest(scope=scope):
                response = compat.handler(self.authorize_event({**self.params, "scope": scope}), None)
                self.assertEqual(response["statusCode"], 400)

    def test_access_token_passes_through_without_credentials_in_logs(self):
        body = json.dumps({
            "access_token": "PRIVATE-ACCESS-TOKEN-CANARY",
            "refresh_token": "PRIVATE-REFRESH-TOKEN-CANARY", "token_type": "Bearer",
        })
        logs = io.StringIO()
        with patch.object(compat, "exchange", return_value=(200, body, None)) as exchange, \
             redirect_stdout(logs):
            auth_result = compat.handler(self.authorize_event(), None)
            response = compat.handler(self.token_event(), None)
        self.assertEqual(auth_result["statusCode"], 302)
        self.assertEqual(response["body"], body)
        forwarded = exchange.call_args.args[0]
        self.assertNotIn("resource", forwarded)
        self.assertEqual(forwarded["code"], self.token["code"])
        self.assertEqual(forwarded["code_verifier"], self.token["code_verifier"])
        self.assertEqual(forwarded["scope"], self.cfg["api_app_id"] + "/agent.invoke")
        for secret in [
            *[self.token[k] for k in ("client_secret", "code", "code_verifier")],
            self.params["state"], "PRIVATE-ACCESS-TOKEN-CANARY", "PRIVATE-REFRESH-TOKEN-CANARY",
        ]:
            self.assertNotIn(secret, logs.getvalue())
        self.assertEqual(response["headers"]["Cache-Control"], "no-store")

    def test_basic_client_authentication_is_accepted_without_logging_header(self):
        body = {k: v for k, v in self.token.items() if k not in ("client_id", "client_secret")}
        authorization = "Basic " + base64.b64encode(
            (self.cfg["client_id"] + ":" + self.token["client_secret"]).encode(),
        ).decode()
        logs = io.StringIO()
        with patch.object(compat, "exchange", return_value=(400, '{"error":"invalid_grant"}', "invalid_grant")) as exchange, \
             redirect_stdout(logs):
            response = compat.handler(self.token_event(body, authorization), None)
        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(exchange.call_args.args[0]["client_secret"], self.token["client_secret"])
        self.assertNotIn(authorization, logs.getvalue())
        self.assertNotIn(self.token["client_secret"], logs.getvalue())

    def test_invalid_token_binding_is_not_forwarded(self):
        for update in [
            {"client_id": "another-client"}, {"resource": "https://unrelated.example"},
            {"redirect_uri": "https://unrelated.example/callback"},
            {"grant_type": "client_credentials"}, {"code_verifier": ""},
            {"client_secret": ""}, {"scope": "User.Read.All"},
        ]:
            with self.subTest(update=update), patch.object(compat, "exchange") as exchange:
                response = compat.handler(self.token_event({**self.token, **update}), None)
                self.assertEqual(response["statusCode"], 400)
                exchange.assert_not_called()

    def test_refresh_stays_bound_to_the_existing_api(self):
        params = {
            "client_id": self.cfg["client_id"], "client_secret": self.token["client_secret"],
            "grant_type": "refresh_token", "refresh_token": "PRIVATE-REFRESH-TOKEN-CANARY",
            "resource": self.cfg["resource_uri"],
        }
        with patch.object(compat, "exchange", return_value=(200, '{"access_token":"next"}', None)) as exchange:
            response = compat.handler(self.token_event(params), None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(exchange.call_args.args[0]["scope"], self.cfg["api_app_id"] + "/agent.invoke")
        self.assertNotIn("resource", exchange.call_args.args[0])

    def test_duplicate_token_credentials_are_not_forwarded(self):
        event = self.token_event()
        event["body"] += "&client_secret=SECOND-SECRET-CANARY"
        with patch.object(compat, "exchange") as exchange:
            response = compat.handler(event, None)
        self.assertEqual(response["statusCode"], 400)
        exchange.assert_not_called()
        self.assertNotIn("SECOND-SECRET", response["body"])

    def test_unapproved_upstream_host_is_not_used(self):
        changed = {**self.cfg, "authority_host": "https://unrelated.example"}
        with patch.dict(os.environ, {"QUICK_OAUTH_COMPAT_CONFIG": json.dumps(changed)}), \
             patch.object(compat, "exchange") as exchange:
            response = compat.handler(self.token_event(), None)
        self.assertEqual(response["statusCode"], 400)
        exchange.assert_not_called()


if __name__ == "__main__":
    unittest.main()
