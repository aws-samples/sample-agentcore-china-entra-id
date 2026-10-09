"""Real Entra China login and app-only MCP calls; credentials stay in memory."""
import argparse
import base64
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import time
from urllib.parse import parse_qs

import jwt
import msal
import requests

from client import MCPClient, evidence, exercise, summarize
import local_config as local


def safe_error(result):
    return {"error": result.get("error", "token_not_returned"),
            "error_codes": result.get("error_codes", []), "correlation_id": result.get("correlation_id")}


def verify(token, cfg, *, application=False):
    authority = f'{cfg["authority_host"]}/{cfg["tenant_id"]}'
    response = requests.get(authority + "/v2.0/.well-known/openid-configuration", timeout=20)
    response.raise_for_status()
    discovery = response.json()
    if not discovery["jwks_uri"].startswith(authority + "/"):
        raise RuntimeError("Unexpected JWKS URI")
    signing_key = jwt.PyJWKClient(discovery["jwks_uri"]).get_signing_key_from_jwt(token).key
    claims = jwt.decode(
        token, signing_key, algorithms=["RS256"], audience=cfg["api_app_id"], issuer=discovery["issuer"],
        options={"require": ["exp", "iat", "iss", "aud", "tid"]},
    )
    expected_client = cfg["machine_client_app_id"] if application else cfg["client_app_id"]
    if claims.get("tid") != cfg["tenant_id"] or claims.get("azp") != expected_client:
        raise RuntimeError("Unexpected tenant or authorized client")
    if application:
        if claims.get("scp") or cfg["machine_role"] not in claims.get("roles", []):
            raise RuntimeError("Required app-only permission missing")
    elif cfg["scope"] not in claims.get("scp", "").split():
        raise RuntimeError("Required delegated permission missing")
    return claims


def public_client(cfg):
    return msal.PublicClientApplication(
        cfg["client_app_id"], authority=f'{cfg["authority_host"]}/{cfg["tenant_id"]}',
        instance_discovery=False, exclude_scopes=["offline_access"],
    )


def interactive(cfg, *, timeout=600, scopes=None):
    app = public_client(cfg)
    flow = app.initiate_auth_code_flow(
        scopes=scopes or [f'{cfg["api_app_id"]}/{cfg["scope"]}'],
        redirect_uri="http://localhost:8400", response_mode="form_post",
    )
    if "auth_uri" not in flow or "code_challenge=" not in flow["auth_uri"]:
        raise RuntimeError("PKCE flow unavailable")
    result = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def page(self, status, message):
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(("<!doctype html><meta charset=utf-8><h1>China MCP 登录测试</h1><p>" + message + "</p>").encode())

        def do_GET(self):
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", flow["auth_uri"])
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            else:
                self.page(200, "请访问 /start 开始。令牌不会显示在页面或测试报告中。")

        def do_POST(self):
            if self.path != "/":
                return self.page(404, "未知回调")
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length < 65536:
                    raise ValueError("Invalid callback size")
                params = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
                value = app.acquire_token_by_auth_code_flow(flow, params)
                result.update(value)
                if "access_token" in value:
                    self.page(200, "已取得 API 访问令牌，正在执行后续测试。请回到终端等待结果。")
                else:
                    self.page(400, "Entra 未返回 API 访问令牌。请查看终端和本地结果文件中的错误信息。")
            except Exception as error:
                result.update(error=type(error).__name__)
                self.page(400, "认证回调校验失败。")

    with HTTPServer(("127.0.0.1", 8400), Handler) as httpd:
        httpd.timeout = 1
        print("在运行本程序的同一台合规电脑打开 http://localhost:8400/start", flush=True)
        deadline = time.monotonic() + timeout
        while not result and time.monotonic() < deadline:
            httpd.handle_request()
    return result or {"error": "interactive_timeout"}


def read_client_secret():
    secret = os.environ.get("ENTRA_CLIENT_SECRET")
    secret_file = os.environ.get("ENTRA_CLIENT_SECRET_FILE")
    if secret and secret_file:
        raise RuntimeError("Select one client secret source")
    if secret_file:
        secret = Path(secret_file).read_text(encoding="utf-8-sig").strip()
    if not secret:
        raise RuntimeError("Provide ENTRA_CLIENT_SECRET or ENTRA_CLIENT_SECRET_FILE")
    return secret


def certificate_credential(private_key, certificate_pem):
    """Build an MSAL credential from validated PEM bytes without writing files."""
    from datetime import datetime, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    certificate = x509.load_pem_x509_certificate(certificate_pem)
    key = serialization.load_pem_private_key(private_key, password=None)
    now = datetime.now(timezone.utc)
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise RuntimeError("Client certificate is outside its validity period")
    if not isinstance(key, rsa.RSAPrivateKey):
        raise RuntimeError("This sample requires an RSA client certificate")
    if key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ) != certificate.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ):
        raise RuntimeError("Client certificate and private key do not match")
    # MSAL >= 1.35 selects SHA-256 for PEM certificates without a legacy thumbprint.
    return {"private_key": private_key.decode("ascii"),
            "public_certificate": certificate_pem.decode("ascii")}


def confidential_client(cfg, method, *, client_id=None):
    if method == "secret":
        credential = read_client_secret()
    elif method == "certificate":
        key_path = os.environ.get("ENTRA_PRIVATE_KEY_FILE")
        cert_path = os.environ.get("ENTRA_CERTIFICATE_FILE")
        if not key_path or not cert_path:
            raise RuntimeError("ENTRA_PRIVATE_KEY_FILE and ENTRA_CERTIFICATE_FILE required")
        credential = certificate_credential(Path(key_path).read_bytes(), Path(cert_path).read_bytes())
    else:
        raise ValueError("Unsupported client credential method")
    return msal.ConfidentialClientApplication(
        client_id or cfg["machine_client_app_id"], client_credential=credential,
        authority=f'{cfg["authority_host"]}/{cfg["tenant_id"]}', instance_discovery=False,
    )


def test_token(cfg, token, *, application=False, id_token=None):
    verify(token, cfg, application=application)
    state = local.read_state()
    mode = "app" if application else "jwt"
    if any(mode not in state.get(kind, {}) for kind in ("runtimes", "gateways")):
        raise RuntimeError("Deploy the corresponding Runtime and Gateway entry before testing")
    rows = []
    for kind in ("runtimes", "gateways"):
        endpoint = state[kind][mode]["url"]
        rows.extend(exercise(endpoint, prefix=f"{kind}_{mode}_", region=cfg["region"], bearer=token))
        pieces = token.split(".")
        signature = bytearray(base64.urlsafe_b64decode(pieces[2] + "=" * (-len(pieces[2]) % 4)))
        signature[0] ^= 1
        pieces[2] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        response, value = MCPClient(endpoint, region=cfg["region"], bearer=".".join(pieces)).rpc("tools/list")
        rows.append(evidence(kind + "_real_signature_tamper", response, value))
        if id_token:
            response, value = MCPClient(endpoint, region=cfg["region"], bearer=id_token).rpc("tools/list")
            rows.append(evidence(kind + "_id_token_misuse", response, value))
        if application:
            response, value = MCPClient(state[kind]["jwt"]["url"], region=cfg["region"], bearer=token).rpc("tools/list")
            rows.append(evidence(kind + "_app_cannot_enter_delegated_scope_entry", response, value))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("flow", choices=["login", "device", "client-secret", "client-certificate"])
    parser.add_argument("--config")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    cfg = local.config(args.config)
    application = args.flow.startswith("client-")
    if application:
        if not cfg.get("machine_client_app_id") or not cfg.get("machine_role"):
            raise RuntimeError("Configure the machine client ID and required application role first")
        method = "secret" if args.flow == "client-secret" else "certificate"
        result = confidential_client(cfg, method).acquire_token_for_client(scopes=[f'{cfg["api_app_id"]}/.default'])
    elif args.flow == "device":
        app = public_client(cfg)
        flow = app.initiate_device_flow(scopes=[f'{cfg["api_app_id"]}/{cfg["scope"]}'])
        if "user_code" not in flow:
            result = flow
        else:
            # The one-time device code is displayed only for the interactive user, never stored in reports.
            print(flow["message"], flush=True)
            result = app.acquire_token_by_device_flow(flow)
    else:
        result = interactive(cfg, timeout=args.timeout)
    report = {"recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "flow": args.flow, "region": cfg["region"], "tokens_recorded": False}
    if "access_token" not in result:
        report.update(status="blocked", **safe_error(result))
    else:
        try:
            rows = test_token(cfg, result["access_token"], application=application, id_token=result.get("id_token"))
            report.update(status="passed" if all(r["passed"] for r in rows) else "failed",
                          summary=summarize(rows), cases=rows)
        except Exception as error:
            report.update(status="failed", stage="token_verification_or_mcp",
                          error=type(error).__name__)
    local.save(local.ROOT / "results" / (args.flow + ".json"), report, private=False)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if "summary" in report:
        counts = report["summary"]
        statuses = Counter(row["http_status"] for row in report["cases"])
        print("；".join(f"HTTP {status}: {number} 次" for status, number in sorted(statuses.items()))
              + f'；未满足检查条件: {counts["unexpected_results"]} 项。')
    return report["status"] == "passed"


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
