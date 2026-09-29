"""Local Entra China OBO protocol check; Graph returns only the current user's ID.

This co-locates the public test client and confidential middle tier on one
authorized test computer. It does not deploy an OBO middle tier to AgentCore and
does not exercise AgentCore Identity token exchange. Raw tokens stay in memory.
"""
import argparse
import json
import time
import uuid

import requests

import entra
import local_config as local

GRAPH_BASE = "https://microsoftgraph.chinacloudapi.cn"
GRAPH_SCOPE = GRAPH_BASE + "/User.Read"
GRAPH_ME = GRAPH_BASE + "/v1.0/me"


def graph_me(token, user_oid):
    """Treat Graph tokens as opaque; let Graph validate its own access token."""
    expected_oid = uuid.UUID(user_oid)
    response = requests.get(
        GRAPH_ME,
        params={"$select": "id"},
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "client-request-id": str(uuid.uuid4()),
            "return-client-request-id": "true",
        },
        timeout=(15, 60),
        allow_redirects=False,
    )
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    same_user = False
    if response.status_code == 200 and isinstance(payload, dict):
        try:
            same_user = uuid.UUID(payload.get("id", "")) == expected_oid
        except (ValueError, TypeError, AttributeError):
            pass
    return {
        "operation": "GET China Graph /v1.0/me?$select=id",
        "http_status": response.status_code,
        "request_id": response.headers.get("request-id"),
        "same_user_as_verified_token_a": same_user,
        "profile_fields_requested": ["id"],
        "profile_values_recorded": False,
        "passed": response.status_code == 200 and same_user,
    }


def exchange_and_call(cfg, token_a, middle_tier):
    # The middle tier's own API access token must be validated before exchange.
    claims = entra.verify(token_a, cfg)
    user_oid = str(uuid.UUID(claims["oid"]))
    result = middle_tier.acquire_token_on_behalf_of(
        user_assertion=token_a, scopes=[GRAPH_SCOPE],
    )
    if not result.get("access_token"):
        return {
            "status": "blocked",
            "stage": "entra_obo_exchange",
            **entra.safe_error(result),
            "claims_challenge_received": bool(result.get("claims")),
            "cases": [],
        }
    row = graph_me(result["access_token"], user_oid)
    return {
        "status": "passed" if row["passed"] else "failed",
        "stage": "graph_me",
        "token_a_validated": True,
        "obo_access_token_received": True,
        "cases": [row],
    }


def preflight(cfg, method):
    if cfg.get("authority_host") != "https://login.partner.microsoftonline.cn":
        raise ValueError("This test requires the configured Entra China authority")
    for field in ("tenant_id", "api_app_id", "client_app_id"):
        uuid.UUID(cfg[field])
    # Do this before interactive login so missing credentials don't waste a login.
    return entra.confidential_client(cfg, method, client_id=cfg["api_app_id"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credential", choices=["secret", "certificate"], required=True)
    parser.add_argument("--config")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)
    report = {
        "recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "flow": "Entra China direct MSAL OBO -> China Graph /me",
        "client_authentication": args.credential,
        "execution_location": "local_test_computer",
        "agentcore_identity_used": False,
        "agentcore_runtime_used": False,
        "downstream_scope": GRAPH_SCOPE,
        "tokens_recorded": False,
        "profile_values_recorded": False,
    }
    stage = "local_credential_setup"
    try:
        cfg = local.config(args.config)
        report["region"] = cfg["region"]
        middle_tier = preflight(cfg, args.credential)
        stage = "interactive_login"
        login = entra.interactive(cfg, timeout=args.timeout)
        if not login.get("access_token"):
            report.update(status="blocked", stage=stage, **entra.safe_error(login))
        else:
            stage = "token_a_verification_or_obo_or_graph"
            report.update(exchange_and_call(cfg, login["access_token"], middle_tier))
    except Exception as error:
        report.update(status="failed", stage=stage, error=type(error).__name__)
    report["completed_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    output = local.ROOT / "results" / ("obo-" + args.credential + ".json")
    local.save(output, report, private=False)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("结果文件: " + str(output))
    return report["status"] == "passed"


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
