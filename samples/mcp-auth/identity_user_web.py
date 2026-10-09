# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""HTTPS BFF: cookie-bound login, single-use Identity callback, asynchronous MCP."""
import hashlib
import hmac
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlsplit, urlunsplit

import boto3
from botocore.exceptions import ClientError
import msal

from client import MCPClient
import entra
from identity_user_core import BEGIN_TOOL, CHECK_TOOL, identity_client, now, settings, validate_authorization_url

SESSION_COOKIE = "__Host-ac-session"
LOGIN_COOKIE = "__Host-ac-login"
STATIC = Path(__file__).with_name("identity_user_static")
SAFE_FIELDS = {
    "status", "recorded_at_utc", "completed_at_utc", "flow", "region",
    "agentcore_runtime_used", "agentcore_identity_used", "client_authentication",
    "tokens_recorded", "profile_values_recorded", "token_a_validated",
    "workload_request_id", "identity_request_id", "identity_access_token_received",
    "stage", "error", "aws_request_id",
}
GRAPH_FIELDS = {
    "operation", "http_status", "request_id", "same_user_as_verified_token_a",
    "profile_fields_returned", "profile_values_recorded", "user_id_values_recorded", "passed",
}


class WebError(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status


class Store:
    def __init__(self):
        self.table = boto3.resource("dynamodb", region_name=settings()["region"]).Table(os.environ["SESSION_TABLE"])

    def get(self, key):
        row = self.table.get_item(Key={"pk": key}, ConsistentRead=True).get("Item")
        if not row or int(row["expires"]) <= int(time.time()):
            raise WebError("session_expired", 401)
        value = json.loads(row["payload"])
        value["_revision"] = int(row["revision"])
        return value

    def create(self, key, value):
        self.table.put_item(Item={"pk": key, "expires": value["expires"],
                                  "payload": json.dumps(value), "revision": 0},
                            ConditionExpression="attribute_not_exists(pk)")

    def replace(self, key, value):
        revision = value.pop("_revision")
        self.table.update_item(
            Key={"pk": key},
            UpdateExpression="SET payload=:payload, revision=:next",
            ConditionExpression="revision=:previous AND expires>:now",
            ExpressionAttributeValues={":payload": json.dumps(value), ":next": revision + 1,
                                       ":previous": revision, ":now": int(time.time())},
        )
        value["_revision"] = revision + 1

    def consume(self, key):
        row = self.table.delete_item(Key={"pk": key}, ReturnValues="ALL_OLD").get("Attributes")
        if not row or int(row["expires"]) <= int(time.time()):
            raise WebError("login_expired", 401)
        return json.loads(row["payload"])

    def delete(self, key):
        self.table.delete_item(Key={"pk": key})


def cookie(name, value, age):
    return f"{name}={value}; Path=/; Max-Age={age}; Secure; HttpOnly; SameSite=Lax"


def key_from_cookie(event, name):
    jar = SimpleCookie()
    jar.load(headers(event).get("cookie", ""))
    value = jar[name].value if name in jar else ""
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise WebError("login_required", 401)
    return name + ":" + hashlib.sha256(value.encode()).hexdigest()


def headers(event):
    return {key.lower(): value for key, value in (event.get("headers") or {}).items()}


def response(status, body="", content_type="application/json; charset=utf-8", **extra):
    result = {
        "statusCode": status,
        "headers": {
            "Content-Type": content_type, "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "; ".join((
                "default-src 'self'", "script-src 'self'", "style-src 'self'",
                "img-src 'self' data:", "connect-src 'self'", "frame-ancestors 'none'",
                "base-uri 'none'", "form-action 'self'",
            )),
            "Strict-Transport-Security": "max-age=31536000",
            **extra.pop("headers", {}),
        },
        "body": json.dumps(body, ensure_ascii=False) if not isinstance(body, str) else body,
        **extra,
    }
    return result


def redirect(url, cookies=None):
    return response(303, headers={"Location": url},
                    **({"multiValueHeaders": {"Set-Cookie": cookies}} if cookies else {}))


def safe_app_path(path):
    return (
        re.fullmatch(r"/[A-Za-z0-9._~/-]*", path) is not None
        and "//" not in path
        and not any(part in (".", "..") for part in path.split("/"))
    )


def portal_base_url():
    """Validate deployment configuration before it can become a redirect or origin."""
    value = os.environ.get("PORTAL_BASE_URL", "")
    # Restrict before parsing: URL parsers may discard control characters. Percent
    # escapes, userinfo, queries, fragments and backslashes have no role in this
    # sample's HTTPS DNS name and unreserved deployment path.
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9._~/-]*)?", value):
        raise WebError("invalid_portal_base_url", 500)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise WebError("invalid_portal_base_url", 500) from None
    hostname = parsed.hostname
    if (
        not hostname or len(hostname) > 253 or port == 0
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
               for label in hostname.split("."))
        or (parsed.path and not safe_app_path(parsed.path))
    ):
        raise WebError("invalid_portal_base_url", 500)
    authority = hostname if port in (None, 443) else f"{hostname}:{port}"
    return urlunsplit(("https", authority, parsed.path.rstrip("/"), "", ""))


def app_url(path="/"):
    if not safe_app_path(path):
        raise WebError("invalid_application_path", 500)
    # A leading route slash must not replace the API Gateway stage/base path.
    return f"{portal_base_url()}{path}"


def msal_app(cfg):
    secret_arn = os.environ["CLIENT_SECRET_ARN"]
    if not secret_arn.startswith(f'arn:aws-cn:secretsmanager:{cfg["region"]}:{cfg["account_id"]}:secret:'):
        raise WebError("credential_region_mismatch", 500)
    value = boto3.client("secretsmanager", region_name=cfg["region"]).get_secret_value(
        SecretId=secret_arn,
    )["SecretString"]
    return msal.ConfidentialClientApplication(
        cfg["api_app_id"], client_credential=json.loads(value)["client_secret"],
        authority=f'{cfg["authority_host"]}/{cfg["tenant_id"]}',
        instance_discovery=False, exclude_scopes=["offline_access"],
    )


def query_params(event):
    multiple = event.get("multiValueQueryStringParameters")
    if multiple and any(len(value) != 1 for value in multiple.values()):
        raise WebError("duplicate_query_parameter")
    return event.get("queryStringParameters") or {}


def check_csrf(event, session):
    origin = urlsplit(portal_base_url())
    if headers(event).get("origin") != f"{origin.scheme}://{origin.netloc}":
        raise WebError("origin_mismatch", 403)
    supplied = headers(event).get("x-csrf-token", "")
    if not supplied or not hmac.compare_digest(supplied, session["csrf"]):
        raise WebError("csrf_mismatch", 403)


def callback_transaction(session, params):
    pending = session.get("pending")
    if not pending or pending["expires_at"] <= int(time.time()):
        raise WebError("authorization_session_expired")
    if session.get("phase") != "authorization_ready":
        raise WebError("authorization_callback_already_consumed")
    # SDK documents customState round-tripping but not its query-key spelling.
    # Accept exactly one named field; never accept an absent or mismatching value.
    states = [params[key] for key in ("state", "custom_state", "customState") if key in params]
    if len(states) != 1 or not hmac.compare_digest(states[0], pending["custom_state"]):
        raise WebError("authorization_state_mismatch")
    if not hmac.compare_digest(params.get("session_id", ""), pending["session_uri"]):
        raise WebError("authorization_session_mismatch")
    return pending


def safe_report(value):
    result = {key: value[key] for key in SAFE_FIELDS if key in value}
    if isinstance(value.get("graph"), dict):
        result["graph"] = {key: value["graph"][key] for key in GRAPH_FIELDS if key in value["graph"]}
    return result


def call_runtime(cfg, token, tool):
    client = MCPClient(cfg["runtime_url"], region=cfg["region"], bearer=token)
    rows = []
    for method, params in (
        ("initialize", None), ("tools/list", {}),
        ("tools/call", {"name": tool, "arguments": {}}),
    ):
        r, v = client.initialize() if method == "initialize" else client.rpc(method, params)
        rows.append({"operation": method, "http_status": r.status_code,
                     "request_id": r.headers.get("x-amzn-requestid")})
        if r.status_code != 200 or v.get("error") or v.get("result", {}).get("isError"):
            return {"status": "failed", "stage": "runtime_" + method.replace("/", "_")}, rows
    result = v["result"]
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"], rows
    content = result.get("content", [])
    if len(content) == 1 and content[0].get("type") == "text":
        value = json.loads(content[0]["text"])
        if isinstance(value, dict):
            return value, rows
    raise WebError("unexpected_mcp_response", 502)


def start_job(store, key, session, action):
    if session["phase"] in ("working", "binding"):
        raise WebError("operation_in_progress", 409)
    session["job_id"] = secrets.token_urlsafe(24)
    session["phase"] = "binding" if action == "complete" else "working"
    session["action"] = action
    session["job_started_at"] = int(time.time())
    session.pop("worker_claimed", None)
    store.replace(key, session)
    try:
        boto3.client("lambda", region_name=settings()["region"]).invoke(
            FunctionName=os.environ["AWS_LAMBDA_FUNCTION_NAME"], InvocationType="Event",
            Payload=json.dumps({"internal_job": action, "key": key, "job_id": session["job_id"]}).encode(),
        )
    except Exception:
        session["phase"] = "failed"
        session["report"] = {"status": "failed", "stage": "queue_operation", "tokens_recorded": False}
        store.replace(key, session)
        raise


def worker(event):
    store, cfg = Store(), settings()
    key = event["key"]
    session = store.get(key)
    if (session.get("job_id") != event["job_id"] or session["phase"] not in ("working", "binding")
            or session.get("worker_claimed")):
        return {"ignored": True}
    session["worker_claimed"] = True
    try:
        store.replace(key, session)
    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return {"ignored": True}
        raise
    stage = "current_employee_token"
    try:
        claims = entra.verify(session["token"], cfg)
        if claims.get("oid") != session["oid"]:
            raise WebError("current_employee_mismatch", 403)
        action = event["internal_job"]
        if action == "complete":
            pending = session["pending"]
            if pending["expires_at"] <= int(time.time()):
                raise WebError("authorization_session_expired")
            stage = "complete_resource_token_auth"
            completed = identity_client(cfg).complete_resource_token_auth(
                userIdentifier={"userToken": session["token"]}, sessionUri=pending["session_uri"],
            )
            session["binding"] = {
                "operation": "CompleteResourceTokenAuth",
                "http_status": completed["ResponseMetadata"]["HTTPStatusCode"],
                "request_id": completed["ResponseMetadata"].get("RequestId"),
                "current_browser_session_checked": True, "custom_state_checked": True,
            }
            session["phase"] = "authorized"
            session.pop("pending", None)
        else:
            stage = "runtime_mcp"
            result, rows = call_runtime(cfg, session["token"], BEGIN_TOOL if action == "authorize" else CHECK_TOOL)
            if action == "authorize" and result.get("authorization_url"):
                validate_authorization_url(result["authorization_url"], cfg)
                session["pending"] = {key: result[key] for key in (
                    "authorization_url", "session_uri", "custom_state", "expires_at",
                )}
                session["phase"] = "authorization_ready"
                session["authorization_evidence"] = {**safe_report(result["evidence"]), "mcp": rows}
            else:
                report = safe_report(result)
                report.update(mcp=rows, browser_login=session["login"], session_binding=session.get("binding"),
                              tokens_recorded=False, profile_values_recorded=False)
                passed = (
                    report.get("status") == "passed" and report.get("agentcore_runtime_used") is True
                    and report.get("agentcore_identity_used") is True
                    and report.get("identity_access_token_received") is True
                    and report.get("graph", {}).get("http_status") == 200
                    and report.get("graph", {}).get("same_user_as_verified_token_a") is True
                    and session.get("binding", {}).get("http_status") == 200
                )
                report["status"] = "passed" if passed else "failed"
                session.update(report=report, phase="complete" if passed else "failed")
    except Exception as error:
        report = {"status": "failed", "stage": stage, "error": type(error).__name__,
                  "recorded_at_utc": now(), "tokens_recorded": False, "profile_values_recorded": False}
        if isinstance(error, WebError):
            report["error"] = error.code
        if isinstance(error, ClientError):
            report.update(error=error.response["Error"]["Code"],
                          aws_request_id=error.response.get("ResponseMetadata", {}).get("RequestId"))
        session.update(report=report, phase="failed")
    try:
        store.replace(key, session)
    except ClientError as error:
        if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
    return {"processed": True}


def web(event):
    portal_base_url()
    path, method = event.get("path", "/"), event.get("httpMethod", "GET")
    if method == "GET" and path == "/":
        # Gateway can map both /stage and /stage/ to "/". A fixed document path
        # makes relative links unambiguous without trusting Host/forwarded headers.
        return redirect(app_url("/index.html"))
    if method == "GET" and path in ("/index.html", "/app.js", "/app.css"):
        name = {"/index.html": "index.html", "/app.js": "app.js", "/app.css": "app.css"}[path]
        mime = {"/index.html": "text/html", "/app.js": "text/javascript", "/app.css": "text/css"}[path]
        text = (STATIC / name).read_text(encoding="utf-8")
        return response(200, text, mime + "; charset=utf-8")
    cfg, store = settings(), Store()
    if path == "/login" and method == "GET":
        flow = msal_app(cfg).initiate_auth_code_flow(
            scopes=[f'{cfg["api_app_id"]}/{cfg["scope"]}'], redirect_uri=app_url("/login/callback"),
            response_mode="query",
        )
        if "code_challenge=" not in flow.get("auth_uri", ""):
            raise WebError("pkce_unavailable", 503)
        nonce = secrets.token_urlsafe(32)
        store.create(LOGIN_COOKIE + ":" + hashlib.sha256(nonce.encode()).hexdigest(),
                     {"expires": int(time.time()) + 600, "flow": flow})
        return redirect(flow["auth_uri"], [cookie(LOGIN_COOKIE, nonce, 600)])
    if path == "/login/callback" and method == "GET":
        flow = store.consume(key_from_cookie(event, LOGIN_COOKIE))["flow"]
        params = query_params(event)
        result = msal_app(cfg).acquire_token_by_auth_code_flow(flow, params)
        if not result.get("access_token"):
            # Entra error descriptions may contain user details. Export codes only.
            diagnostic = entra.safe_error(result)
            return response(400, {"status": "login_failed", **diagnostic, "tokens_recorded": False})
        claims = entra.verify(result["access_token"], cfg)
        id_claims = result.get("id_token_claims", {})
        if not claims.get("oid") or claims["oid"] != id_claims.get("oid") or id_claims.get("tid") != cfg["tenant_id"]:
            raise WebError("login_identity_mismatch", 403)
        age = min(900, int(claims["exp"]) - int(time.time()) - 30)
        if age < 60:
            raise WebError("token_lifetime_too_short", 401)
        nonce = secrets.token_urlsafe(32)
        store.create(SESSION_COOKIE + ":" + hashlib.sha256(nonce.encode()).hexdigest(), {
            "expires": int(time.time()) + age, "token": result["access_token"], "oid": claims["oid"],
            "csrf": secrets.token_urlsafe(32), "phase": "logged_in",
            "login": {"completed_at_utc": now(), "flow": "authorization_code_with_pkce",
                      "client_authentication": "client_secret", "token_a_validated": True,
                      "id_token_user_matches_access_token": True},
        })
        return redirect(app_url(), [cookie(SESSION_COOKIE, nonce, age), cookie(LOGIN_COOKIE, "", 0)])
    key = key_from_cookie(event, SESSION_COOKIE)
    session = store.get(key)
    if path == "/api/session" and method == "GET":
        # A Lambda timeout leaves the job pending; expose it as retryable.
        if session["phase"] in ("working", "binding") and int(time.time()) - session.get("job_started_at", 0) > 270:
            session.update(phase="failed", report={"status": "failed", "stage": "operation_timeout",
                                                  "tokens_recorded": False})
            store.replace(key, session)
        return response(200, {"authenticated": True, "phase": session["phase"], "csrf": session["csrf"],
                              "expires_at": session["expires"], "report": session.get("report")})
    if path == "/identity/callback" and method == "GET":
        callback_transaction(session, query_params(event))
        # The cookie identifies the current browser session. Query parameters
        # never select a user or retrieve the originating user's identity.
        start_job(store, key, session, "complete")
        return redirect(app_url())
    if path == "/continue" and method == "GET":
        if session["phase"] != "authorization_ready" or session["pending"]["expires_at"] <= int(time.time()):
            raise WebError("authorization_not_ready")
        return redirect(validate_authorization_url(session["pending"]["authorization_url"], cfg))
    if path == "/result" and method == "GET":
        if not session.get("report"):
            raise WebError("result_not_ready", 409)
        return response(200, session["report"], headers={
            "Content-Disposition": 'attachment; filename="identity-user-oauth.json"',
        })
    if method == "POST":
        check_csrf(event, session)
        if path == "/logout":
            store.delete(key)
            return response(200, {"signed_out": True},
                            multiValueHeaders={"Set-Cookie": [cookie(SESSION_COOKIE, "", 0)]})
        if path == "/authorize":
            if session["phase"] not in ("logged_in", "failed", "complete", "authorized", "authorization_ready"):
                raise WebError("operation_in_progress", 409)
            session.pop("pending", None)
            session.pop("binding", None)
            session.pop("report", None)
            start_job(store, key, session, "authorize")
            return response(202, {"phase": "working"})
        if path == "/run":
            if session["phase"] not in ("authorized", "complete", "failed") or not session.get("binding"):
                raise WebError("authorization_required", 409)
            start_job(store, key, session, "check")
            return response(202, {"phase": "working"})
    raise WebError("not_found", 404)


def handler(event, context):
    try:
        # Only SigV4-authorized Lambda callers can submit an internal event.
        # API Gateway user JSON remains inside body and cannot select this branch.
        if event.get("internal_job") in ("authorize", "check", "complete") and "requestContext" not in event:
            return worker(event)
        return web(event)
    except WebError as error:
        return response(error.status, {"status": "failed", "error": error.code, "tokens_recorded": False})
    except Exception as error:
        # Never log the event, query parameters, Cookie, SDK request or exception text.
        diagnostic = {"status": "failed", "error": type(error).__name__, "tokens_recorded": False}
        if isinstance(error, ClientError):
            diagnostic.update(error=error.response["Error"]["Code"],
                              aws_request_id=error.response.get("ResponseMetadata", {}).get("RequestId"))
        return response(500, diagnostic)
