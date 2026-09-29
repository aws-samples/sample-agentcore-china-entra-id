"""Narrow OAuth parameter adapter for Quick and an existing Entra China app.

Quick's MCP resource URL maps to the existing API's GUID-qualified v2 scope.
Tokens are issued by Entra and passed through unchanged. Nothing is persisted.
This is a custom compatibility component, not native Quick/Entra interoperability.
"""
import base64
import binascii
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, unquote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID

MAX_BODY = 32768
STANDARD_SCOPES = {"openid", "profile", "email", "offline_access"}
AUTHORIZE_KEYS = {
    "client_id", "redirect_uri", "response_type", "scope", "state", "resource",
    "code_challenge", "code_challenge_method", "response_mode", "nonce",
    "prompt", "login_hint",
}
TOKEN_KEYS = {
    "client_id", "client_secret", "redirect_uri", "grant_type", "code",
    "code_verifier", "refresh_token", "scope", "resource",
}


class InvalidRequest(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a credential-bearing POST to a redirected host.
        return None


def configuration():
    cfg = json.loads(os.environ["QUICK_OAUTH_COMPAT_CONFIG"])
    for key in ("tenant_id", "client_id", "api_app_id"):
        if str(UUID(cfg[key])) != cfg[key]:
            raise InvalidRequest("Invalid configured application or tenant ID")
    if cfg["authority_host"] != "https://login.partner.microsoftonline.cn":
        raise InvalidRequest("Only the configured Entra China authority is supported")
    if cfg["redirect_uri"] != "https://us-east-1.quicksight.aws.amazon.com/sn/oauthcallback":
        raise InvalidRequest("Unexpected Quick callback configuration")
    if not re.fullmatch(
        r"https://[a-z0-9-]+\.gateway\.bedrock-agentcore\."
        r"(cn-north-1|cn-northwest-1)\.amazonaws\.com\.cn/mcp", cfg["resource_uri"],
    ):
        raise InvalidRequest("Invalid configured China Gateway resource")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", cfg["scope"]):
        raise InvalidRequest("Invalid configured API scope")
    return cfg


def unique(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise InvalidRequest("Duplicate OAuth request parameter")
        if not isinstance(value, str):
            raise InvalidRequest("OAuth parameters must be strings")
        values[key] = value
    return values


def normalize_scopes(value, cfg, required=True):
    full = cfg["api_app_id"] + "/" + cfg["scope"]
    api_forms = {cfg["scope"], full, "api://" + full}
    normalized = []
    for scope in value.split():
        if scope in api_forms:
            scope = full
        elif scope not in STANDARD_SCOPES:
            raise InvalidRequest("Scope is outside the configured sample API")
        if scope not in normalized:
            normalized.append(scope)
    if required and full not in normalized:
        raise InvalidRequest("The configured API scope is required")
    return " ".join(normalized)


def check_binding(params, cfg, require_resource):
    if params.get("client_id") != cfg["client_id"]:
        raise InvalidRequest("Client ID does not match this adapter")
    resource = params.get("resource")
    if resource is not None and resource != cfg["resource_uri"]:
        raise InvalidRequest("Resource does not match the configured Gateway")
    if require_resource and resource is None:
        raise InvalidRequest("MCP resource is required")
    if "redirect_uri" in params and params["redirect_uri"] != cfg["redirect_uri"]:
        raise InvalidRequest("Redirect URI does not match the configured Quick callback")


def authorize(params, cfg):
    if set(params) - AUTHORIZE_KEYS:
        raise InvalidRequest("Unsupported authorization parameter")
    check_binding(params, cfg, require_resource=True)
    if params.get("response_type") != "code":
        raise InvalidRequest("Only the authorization code response type is supported")
    if params.get("redirect_uri") != cfg["redirect_uri"]:
        raise InvalidRequest("Quick redirect URI is required")
    if params.get("response_mode", "query") != "query":
        raise InvalidRequest("Only query response mode is supported")
    if not params.get("state") or len(params["state"]) > 16384:
        raise InvalidRequest("OAuth state is required")
    if params.get("code_challenge_method") != "S256" or not re.fullmatch(
        r"[A-Za-z0-9_-]{43}", params.get("code_challenge", ""),
    ):
        raise InvalidRequest("S256 PKCE is required")
    if params.get("prompt") not in (None, "login", "consent", "select_account", "none"):
        raise InvalidRequest("Unsupported prompt")
    forwarded = {key: value for key, value in params.items() if key != "resource"}
    forwarded["scope"] = normalize_scopes(params.get("scope", ""), cfg)
    location = (
        cfg["authority_host"] + "/" + cfg["tenant_id"] + "/oauth2/v2.0/authorize?"
        + urlencode(forwarded)
    )
    return location, forwarded["scope"]


def token_parameters(params, headers, cfg):
    if set(params) - TOKEN_KEYS:
        raise InvalidRequest("Unsupported token parameter")
    params = dict(params)
    authorization = headers.get("authorization")
    if authorization:
        if params.get("client_secret"):
            raise InvalidRequest("Use one client authentication method")
        try:
            kind, value = authorization.split(" ", 1)
            if kind.lower() != "basic":
                raise ValueError()
            decoded = base64.b64decode(value, validate=True).decode("utf-8")
            client, secret = (unquote(part) for part in decoded.split(":", 1))
        except (ValueError, UnicodeError, binascii.Error):
            raise InvalidRequest("Invalid client authentication") from None
        if params.get("client_id") not in (None, client):
            raise InvalidRequest("Conflicting client authentication")
        params["client_id"], params["client_secret"] = client, secret
    check_binding(params, cfg, require_resource=False)
    if not params.get("client_secret"):
        raise InvalidRequest("The existing Web application requires client authentication")
    grant = params.get("grant_type")
    if grant == "authorization_code":
        if not params.get("code") or params.get("redirect_uri") != cfg["redirect_uri"]:
            raise InvalidRequest("Authorization code and registered callback are required")
        if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", params.get("code_verifier", "")):
            raise InvalidRequest("A PKCE verifier is required")
        if "refresh_token" in params:
            raise InvalidRequest("Unexpected refresh token")
    elif grant == "refresh_token":
        if not params.get("refresh_token") or "code" in params or "code_verifier" in params:
            raise InvalidRequest("Invalid refresh request")
    else:
        raise InvalidRequest("Only authorization_code and refresh_token grants are supported")
    forwarded = {key: value for key, value in params.items() if key != "resource"}
    if params.get("scope"):
        forwarded["scope"] = normalize_scopes(params["scope"], cfg)
    else:
        # Keep token exchange bound to the same API, even if the client omits scope.
        forwarded["scope"] = cfg["api_app_id"] + "/" + cfg["scope"]
    return forwarded


def exchange(params, cfg):
    endpoint = cfg["authority_host"] + "/" + cfg["tenant_id"] + "/oauth2/v2.0/token"
    request = Request(
        endpoint, data=urlencode(params).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    try:
        with build_opener(NoRedirect()).open(request, timeout=15) as response:
            status, raw = response.status, response.read(1024 * 1024)
    except HTTPError as error:
        status, raw = error.code, error.read(1024 * 1024)
    except (URLError, TimeoutError):
        raise InvalidRequest("Entra token endpoint is unavailable") from None
    if status not in (200, 400, 401, 403, 429):
        raise InvalidRequest("Unexpected Entra token endpoint response")
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeError):
        raise InvalidRequest("Unexpected Entra token response format") from None
    if not isinstance(body, dict):
        raise InvalidRequest("Unexpected Entra token response format")
    if status == 200 and not isinstance(body.get("access_token"), str):
        raise InvalidRequest("Entra did not return an access token")
    return status, raw.decode("utf-8"), body.get("error")


def reply(status, body, headers=None):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json", "Cache-Control": "no-store",
            "Pragma": "no-cache", "X-Content-Type-Options": "nosniff", **(headers or {}),
        },
        "body": body if isinstance(body, str) else json.dumps(body),
    }


def audit(event, **safe_fields):
    # Call sites supply fixed configuration, statuses and field names only.
    print(json.dumps({"component": "quick-oauth-compat", "event": event, **safe_fields}))


def handler(event, context):
    path, method = event.get("path", ""), event.get("httpMethod", "")
    if path == "/health" and method == "GET":
        return reply(200, {"status": "ready", "component": "oauth-parameter-compatibility"})
    try:
        cfg = configuration()
        headers = {key.lower(): value for key, value in (event.get("headers") or {}).items()}
        if path == "/authorize" and method == "GET":
            multi = event.get("multiValueQueryStringParameters")
            params = unique(
                [(key, value) for key, values in multi.items() for value in values]
                if multi is not None else list((event.get("queryStringParameters") or {}).items())
            )
            location, scope = authorize(params, cfg)
            audit("authorize_redirect", request_id=getattr(context, "aws_request_id", None),
                  parameter_names=sorted(params), resource_matched=True,
                  normalized_scope=scope, pkce_method="S256")
            return reply(302, "", {"Location": location})
        if path == "/token" and method == "POST":
            if headers.get("content-type", "").split(";", 1)[0].strip() != "application/x-www-form-urlencoded":
                raise InvalidRequest("Token endpoint requires a form-encoded request")
            raw = event.get("body") or ""
            if len(raw) > MAX_BODY * 2:
                raise InvalidRequest("Token request is too large")
            if event.get("isBase64Encoded"):
                try:
                    raw = base64.b64decode(raw, validate=True).decode("utf-8")
                except (ValueError, UnicodeError, binascii.Error):
                    raise InvalidRequest("Invalid token request encoding") from None
            if len(raw.encode("utf-8")) > MAX_BODY:
                raise InvalidRequest("Token request is too large")
            params = unique(parse_qsl(raw, keep_blank_values=True, strict_parsing=True))
            forwarded = token_parameters(params, headers, cfg)
            status, body, error = exchange(forwarded, cfg)
            audit("token_exchange", request_id=getattr(context, "aws_request_id", None),
                  grant_type=forwarded["grant_type"], status=status,
                  error=error if isinstance(error, str) and re.fullmatch(r"[a-z_]{1,64}", error) else None)
            return reply(status, body)
        return reply(404, {"error": "not_found"})
    except (InvalidRequest, ValueError, KeyError, TypeError):
        audit("invalid_request", request_id=getattr(context, "aws_request_id", None))
        # Do not echo request input, secret, code, verifier, token or exception details.
        return reply(400, {"error": "invalid_request",
                           "error_description": "Request does not match this adapter's configured OAuth contract."})
