"""Run real machine authentication and shared MCP business scenarios.

Credentials and access tokens stay in memory. Reports contain verified
application identity metadata, HTTP/request IDs, and synthetic tool results.
"""
import argparse
from datetime import datetime, timezone
import json

import entra
import lab
from client import exercise


def business_result(result):
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured
    for item in result.get("content", []):
        if item.get("type") == "text":
            try:
                value = json.loads(item["text"])
            except (ValueError, KeyError):
                continue
            if isinstance(value, dict):
                return value
    raise RuntimeError("MCP tool did not return a JSON object")


def run_business(cfg, token):
    claims = entra.verify(token, cfg, application=True)
    state = lab.read_state()
    if (state["account_id"], state["region"]) != (cfg["account_id"], cfg["region"]):
        raise RuntimeError("MCP deployment account or region differs")
    rows = []
    for kind in ("runtimes", "gateways"):
        endpoint_rows = exercise(
            state[kind]["app"]["url"], prefix=kind + "_app_",
            region=cfg["region"], bearer=token,
        )
        for row in endpoint_rows:
            if "synthetic_result" not in row:
                continue
            value = business_result(row["synthetic_result"])
            if row["case"].endswith("maintenance_call"):
                row["business_result_verified"] = (
                    value.get("guide_id") == "DEMO-GUIDE-001"
                    and value.get("fault_code") == "P-DEMO-001"
                    and value.get("synthetic") is True
                )
            elif row["case"].endswith("parts_call"):
                row["business_result_verified"] = value == {
                    "part_number": "DEMO-PART-001", "warehouse": "DEMO-CN",
                    "quantity": 12, "synthetic": True,
                }
            row["passed"] = row["passed"] and row.get("business_result_verified", False)
        rows.extend(endpoint_rows)
    return {
        "token_validation": {
            "signature_issuer_audience_lifetime_verified": True,
            "tenant_verified": True,
            "client_id": claims["azp"],
            "audience": claims["aud"],
            "required_role": cfg["machine_role"],
            "required_role_present": cfg["machine_role"] in claims.get("roles", []),
            "delegated_scope_present": bool(claims.get("scp")),
        },
        "cases": rows,
        "successful_business_calls": sum(
            row.get("business_result_verified", False) and row["passed"]
            for row in rows
        ),
        "end_to_end_completed": len(rows) == 8 and all(row["passed"] for row in rows),
    }


def acquire_identity_token(cfg, sess):
    from identity import IDENTITY_STATE

    state = json.loads(IDENTITY_STATE.read_text())
    if (state["client_id"], state["tenant_id"], state["region"]) != (
        cfg["machine_client_app_id"], cfg["tenant_id"], cfg["region"],
    ):
        raise RuntimeError("Machine Identity provider configuration differs")
    data = sess.client("bedrock-agentcore")
    workload = data.get_workload_access_token(workloadName=state["workload_name"])
    result = data.get_resource_oauth2_token(
        workloadIdentityToken=workload["workloadAccessToken"],
        resourceCredentialProviderName=state["name"],
        scopes=[f'{cfg["api_app_id"]}/.default'], oauth2Flow="M2M",
    )
    if not result.get("accessToken"):
        raise RuntimeError("Identity did not return an access token")
    return result["accessToken"], {
        "workload_request_id": workload["ResponseMetadata"]["RequestId"],
        "identity_request_id": result["ResponseMetadata"]["RequestId"],
        "identity_http_status": result["ResponseMetadata"]["HTTPStatusCode"],
        "identity_provider_name": state["name"],
        "oauth2_flow": "M2M",
    }


def run(method, cfg, credentials_csv=None):
    report = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "scenario": method,
        "grant_type": "client_credentials",
        "account_id": cfg["account_id"], "region": cfg["region"],
        "client_id": cfg["machine_client_app_id"],
        "same_application_registration": cfg["machine_client_app_id"] == cfg["api_app_id"],
        "execution_location": "local SDK client invoking cloud MCP endpoints",
        "identity_used": method == "identity",
        "gateway_target_authentication": "GATEWAY_IAM_ROLE",
        "tokens_recorded": False, "credentials_recorded": False,
        "end_to_end_completed": False,
    }
    stage = "acquire_token"
    try:
        if method == "identity":
            token, metadata = acquire_identity_token(
                cfg, lab.session(cfg, credentials_csv),
            )
            report.update(metadata, client_authentication="client_secret_managed_by_Identity")
        else:
            client = entra.confidential_client(cfg, method)
            result = client.acquire_token_for_client(scopes=[f'{cfg["api_app_id"]}/.default'])
            if not result.get("access_token"):
                report.update(status="token_not_acquired", **entra.safe_error(result))
                return report
            token = result["access_token"]
            report["client_authentication"] = (
                "client_secret" if method == "secret" else "certificate_client_assertion"
            )
        report["access_token_acquired"] = True
        stage = "validate_token_and_invoke_mcp"
        report.update(run_business(cfg, token))
        report["status"] = "passed" if report["end_to_end_completed"] else "failed"
    except Exception as error:
        report.update(status="failed", stage=stage, error_type=type(error).__name__)
        response = getattr(error, "response", None)
        if isinstance(response, dict):
            report.update(
                aws_error_code=response.get("Error", {}).get("Code"),
                aws_request_id=response.get("ResponseMetadata", {}).get("RequestId"),
            )
    finally:
        report["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("method", choices=["secret", "certificate", "identity"])
    parser.add_argument("--credentials-csv")
    args = parser.parse_args()
    report = run(args.method, lab.config(), args.credentials_csv)
    names = {"secret": "client-secret", "certificate": "client-certificate", "identity": "identity-m2m"}
    stem = names[args.method]
    timestamp = report["recorded_at_utc"].replace("-", "").replace(":", "").split(".")[0] + "Z"
    for filename in (stem + ".json", stem + "-" + timestamp + ".json"):
        lab.save(lab.ROOT / "results" / filename, report, private=False)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report["end_to_end_completed"]


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
