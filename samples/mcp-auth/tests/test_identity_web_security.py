# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Portal rendering/URL regressions; no MSAL, JWT, MCP or cloud access required."""
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import shutil
# Runs the fixed local Node test harness below, with no shell or remote input.
import subprocess  # nosec B404
import sys
import time
from types import ModuleType
from unittest.mock import Mock, patch
from urllib.parse import urljoin, urlsplit

import pytest


SAMPLE = Path(__file__).resolve().parents[1]
HOST = "https://example.execute-api.cn-north-1.amazonaws.com.cn"
DEPLOYMENTS = [
    (HOST, HOST),
    (HOST + "/", HOST),
    (HOST + "/test", HOST + "/test"),
    (HOST + "/test/", HOST + "/test"),
    ("https://portal.example.com/team/identity", "https://portal.example.com/team/identity"),
    ("https://portal.example.com/team/identity/", "https://portal.example.com/team/identity"),
    ("https://PORTAL.example.com:443/v1.2/lab_~demo-1", "https://portal.example.com/v1.2/lab_~demo-1"),
    ("https://portal.example.com:8443/team/test", "https://portal.example.com:8443/team/test"),
]
BAD_BASES = [
    "", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
    "http://portal.example.com/test", "//portal.example.com/test", "https:///test",
    'https://portal.example.com/"><script>alert(1)</script>',
    'https://portal.example.com/" onload="alert(1)',
    "https://portal.example.com/' onclick='alert(1)",
    "https://portal.example.com/</script><script>alert(1)</script>",
    "https://portal.example.com/?next=javascript:alert(1)",
    "https://portal.example.com/#javascript:alert(1)",
    "https://portal.example.com/test?", "https://portal.example.com/test#",
    "https://user:password@portal.example.com/test",
    "https://portal.example.com@evil.example/test",
    "https://portal.example.com\\@evil.example/test",
    "https://portal.example.com/test\r\nLocation: https://evil.example/",
    "\nhttps://portal.example.com/test", "https://portal.\nexample.com/test",
    "https://portal.example.com/te\tst", " https://portal.example.com/test",
    "https://portal.example.com/test ", "https://portal.example.com/\x7f",
    "https://portal.example.com/\u2028", "https://port\u0430l.example.com/test",
    "https://portal.example.com/%22%3e%3cscript%3e",
    "https://portal.example.com/%0d%0aLocation%3aevil",
    "https://portal.example.com/%2f%2fevil.example", "https://portal.example.com/%252e%252e",
    "https://portal.example.com/test/../other", "https://portal.example.com/test/./",
    "https://portal.example.com/test//", "https://portal.example.com//evil.example",
    "https://portal.example.com/test;other", "https://portal.example.com:0/test",
    "https://portal.example.com:65536/test", "https://portal.example.com:wrong/test",
    "https://portal.example.com:/test", "https://portal.example.com:443:80/test",
    "https://-portal.example.com/test", "https://portal..example.com/test",
]


@pytest.fixture
def web(monkeypatch):
    # Stub only import boundaries. Load the actual web module and leave its
    # validation, response, cookie and callback implementations intact.
    modules = {name: ModuleType(name) for name in ("msal", "client", "entra", "identity_user_core")}
    modules["client"].MCPClient = Mock(side_effect=AssertionError("unexpected MCP call"))
    modules["entra"].verify = Mock()
    modules["entra"].safe_error = Mock()
    core = modules["identity_user_core"]
    core.BEGIN_TOOL, core.CHECK_TOOL = "begin", "check"
    core.settings = Mock(return_value={"api_app_id": "application", "scope": "agent.invoke",
                                      "tenant_id": "tenant"})
    core.now = Mock(return_value="2026-01-01T00:00:00Z")
    core.identity_client = Mock(side_effect=AssertionError("unexpected Identity call"))
    core.validate_authorization_url = Mock(side_effect=AssertionError("unexpected authorization URL"))
    spec = importlib.util.spec_from_file_location("_identity_web_security", SAMPLE / "identity_user_web.py")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    monkeypatch.setenv("PORTAL_BASE_URL", HOST + "/test")
    monkeypatch.setattr(module, "Store", Mock())
    return module


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


@pytest.mark.parametrize("value", BAD_BASES)
@pytest.mark.parametrize("path", ["/", "/index.html", "/app.js", "/login"])
def test_invalid_configuration_fails_before_render_or_oauth(web, monkeypatch, value, path):
    monkeypatch.setenv("PORTAL_BASE_URL", value)
    oauth = Mock()
    monkeypatch.setattr(web, "msal_app", oauth)
    result = web.handler({"path": path, "httpMethod": "GET"}, None)
    assert result["statusCode"] == 500
    assert json.loads(result["body"]) == {
        "status": "failed", "error": "invalid_portal_base_url", "tokens_recorded": False,
    }
    assert "Location" not in result["headers"]
    web.Store.assert_not_called()
    oauth.assert_not_called()


def test_missing_configuration_fails_closed(web, monkeypatch):
    monkeypatch.delenv("PORTAL_BASE_URL")
    assert web.handler({"path": "/"}, None)["statusCode"] == 500


@pytest.mark.parametrize("path", [
    "//evil.example", "https://evil.example", "javascript:alert(1)", "/../login",
    "/test/./login", "/test//login", "/%2e%2e/login", "/%252e%252e/login",
    "/\\evil.example", "/login?next=//evil.example", "/login#evil",
    "/login\r\nLocation: https://evil.example", '/"><script>alert(1)</script>',
])
def test_application_route_cannot_escape_deployment(web, path):
    with pytest.raises(web.WebError) as error:
        web.app_url(path)
    assert error.value.code == "invalid_application_path"


@pytest.mark.parametrize("configured,canonical", DEPLOYMENTS)
def test_static_page_and_links_preserve_stage_and_base_path(web, monkeypatch, configured, canonical):
    monkeypatch.setenv("PORTAL_BASE_URL", configured)
    event = {
        "path": "/", "httpMethod": "GET",
        "headers": {"Host": "evil.example", "X-Forwarded-Host": "evil.example",
                    "X-Forwarded-Prefix": "//evil.example"},
        "requestContext": {"path": "/untrusted", "stage": "untrusted"},
        "queryStringParameters": {"BASE": '"><script>alert(1)</script>', "next": "//evil.example"},
    }
    root = web.handler(event, None)
    assert root["statusCode"] == 303
    document_url = root["headers"]["Location"]
    assert document_url == canonical + "/index.html"

    page = web.handler({**event, "path": "/index.html"}, None)
    assert page["statusCode"] == 200
    assert page["body"] == (SAMPLE / "identity_user_static/index.html").read_text(encoding="utf-8")
    assert "{{BASE}}" not in page["body"]
    assert configured not in page["body"]
    tags = Page(page["body"]).tags
    assert [attrs for tag, attrs in tags if tag == "script"] == [{"src": "./app.js", "defer": None}]
    assert not any(tag == "base" or any(name.startswith("on") for name in attrs) for tag, attrs in tags)
    references = [attrs[key] for _, attrs in tags for key in ("src", "href") if key in attrs]
    assert references == ["./app.css", "./app.js", "./", "./login", "./continue", "./result"]
    for reference in references:
        assert urljoin(document_url, reference) == canonical + "/" + reference[2:]
    for path, mime in (("/app.js", "text/javascript"), ("/app.css", "text/css")):
        asset = web.handler({**event, "path": path}, None)
        assert asset["statusCode"] == 200
        assert asset["headers"]["Content-Type"] == mime + "; charset=utf-8"
        assert asset["body"] == (SAMPLE / "identity_user_static" / path[1:]).read_text(encoding="utf-8")
    web.Store.assert_not_called()


@pytest.mark.parametrize("configured,canonical", DEPLOYMENTS)
def test_login_and_both_callbacks_keep_deployment_prefix(web, monkeypatch, configured, canonical):
    monkeypatch.setenv("PORTAL_BASE_URL", configured)
    oauth = Mock()
    oauth.initiate_auth_code_flow.return_value = {
        "auth_uri": "https://login.partner.microsoftonline.cn/tenant/authorize?code_challenge=test",
    }
    monkeypatch.setattr(web, "msal_app", Mock(return_value=oauth))
    login = web.handler({"path": "/login", "httpMethod": "GET"}, None)
    assert login["statusCode"] == 303
    assert login["headers"]["Location"] == oauth.initiate_auth_code_flow.return_value["auth_uri"]
    assert oauth.initiate_auth_code_flow.call_args.kwargs == {
        "scopes": ["application/agent.invoke"],
        "redirect_uri": canonical + "/login/callback", "response_mode": "query",
    }
    assert "__Host-ac-login=" in login["multiValueHeaders"]["Set-Cookie"][0]
    assert web.app_url("/identity/callback") == canonical + "/identity/callback"

    web.Store.return_value.consume.return_value = {"flow": {"state": "login-state"}}
    oauth.acquire_token_by_auth_code_flow.return_value = {
        "access_token": "private-token", "id_token_claims": {"oid": "employee", "tid": "tenant"},
    }
    web.entra.verify.return_value = {"oid": "employee", "exp": int(time.time()) + 900}
    callback = web.handler({
        "path": "/login/callback", "httpMethod": "GET",
        "headers": {"Cookie": web.LOGIN_COOKIE + "=" + "a" * 43},
        "queryStringParameters": {"state": "login-state", "code": "private-code"},
    }, None)
    assert callback["statusCode"] == 303
    assert callback["headers"]["Location"] == canonical + "/"
    assert "private-token" not in json.dumps(callback)
    assert any(item.startswith(web.SESSION_COOKIE + "=") for item in callback["multiValueHeaders"]["Set-Cookie"])

    session = {"phase": "authorization_ready", "pending": {
        "session_uri": "session-one", "custom_state": "state-one", "expires_at": int(time.time()) + 300,
    }}
    web.Store.return_value.get.return_value = session
    start = Mock()
    monkeypatch.setattr(web, "start_job", start)
    identity_event = {
        "path": "/identity/callback", "httpMethod": "GET",
        "headers": {"Cookie": web.SESSION_COOKIE + "=" + "b" * 43},
        "queryStringParameters": {"session_id": "session-one", "state": "state-one"},
    }
    callback = web.handler(identity_event, None)
    assert callback["statusCode"] == 303
    assert callback["headers"]["Location"] == canonical + "/"
    assert start.call_args.args[2:] == (session, "complete")
    start.reset_mock()
    identity_event["queryStringParameters"]["state"] = "wrong-state"
    assert web.handler(identity_event, None)["statusCode"] == 400
    start.assert_not_called()


@pytest.mark.parametrize("configured,canonical", DEPLOYMENTS)
def test_csrf_matches_browser_origin_without_deployment_path(web, monkeypatch, configured, canonical):
    monkeypatch.setenv("PORTAL_BASE_URL", configured)
    parsed = urlsplit(canonical)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    session = {"csrf": "csrf-value"}
    web.check_csrf({"headers": {"Origin": origin, "X-CSRF-Token": "csrf-value"}}, session)
    for bad_origin in ("https://evil.example", "null", origin + "/test", origin + ".evil.example"):
        with pytest.raises(web.WebError) as error:
            web.check_csrf({"headers": {"Origin": bad_origin, "X-CSRF-Token": "csrf-value"}}, session)
        assert error.value.code == "origin_mismatch"
    with pytest.raises(web.WebError) as error:
        web.check_csrf({"headers": {"Origin": origin, "X-CSRF-Token": "wrong"}}, session)
    assert error.value.code == "csrf_mismatch"


def test_csp_retains_separate_restrictive_directives(web):
    headers = web.response(200)["headers"]
    assert headers["Content-Security-Policy"].split("; ") == [
        "default-src 'self'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:",
        "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'",
    ]
    assert headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize("configured,canonical", DEPLOYMENTS)
def test_existing_javascript_initialization_and_actions_use_deployment_prefix(
    web, monkeypatch, configured, canonical,
):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is optional; needed to execute the unchanged browser script")
    monkeypatch.setenv("PORTAL_BASE_URL", configured)
    document_url = web.handler({"path": "/"}, None)["headers"]["Location"]
    page = Page(web.handler({"path": "/index.html"}, None)["body"])
    script_src = next(attrs["src"] for tag, attrs in page.tags if tag == "script")
    source = web.handler({"path": "/app.js"}, None)["body"]
    # Execute the real app.js with a minimal DOM and fake network; do not duplicate
    # its base-path derivation or its event handlers in the Python assertions.
    harness = r"""
const {readFileSync} = require("node:fs");
const {runInNewContext} = require("node:vm");
const input = JSON.parse(readFileSync(0, "utf8"));
const requests = [], elements = new Map(), listeners = new Map();
const document = {
  currentScript: {src: new URL(input.scriptSrc, input.documentURL).href},
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, {
      parentElement: {}, classList: {toggle() {}, add() {}, remove() {}},
      addEventListener(name, callback) { listeners.set(id, callback); },
    });
    return elements.get(id);
  },
};
const context = {
  URL, document, clearTimeout() {}, setTimeout() { return 1; },
  async fetch(url, options) {
    requests.push({url, options});
    return {ok: true, status: 200, async json() {
      return {phase: "logged_in", csrf: "csrf-value", expires_at: 2000000000};
    }};
  },
};
(async () => {
  runInNewContext(input.source, context);
  await new Promise(setImmediate);
  for (const id of ["authorize", "run", "logout"]) {
    await listeners.get(id)();
  }
  process.stdout.write(JSON.stringify(requests));
})().catch(() => { process.exitCode = 1; });
"""
    # Executable resolved from the test environment; fixed harness, no shell,
    # local source over stdin, fake network and a ten-second timeout.
    result = subprocess.run(  # nosec B603
        [node, "-e", harness], input=json.dumps({
            "source": source, "scriptSrc": script_src, "documentURL": document_url,
        }), text=True, capture_output=True, check=True, timeout=10,
    )
    requests = json.loads(result.stdout)
    prefix = urlsplit(canonical).path
    assert [item["url"] for item in requests] == [
        prefix + "/api/session", prefix + "/authorize", prefix + "/api/session",
        prefix + "/run", prefix + "/api/session", prefix + "/logout", prefix + "/api/session",
    ]
    for item in requests:
        if item["options"].get("method") == "POST":
            assert item["options"]["headers"]["X-CSRF-Token"] == "csrf-value"
