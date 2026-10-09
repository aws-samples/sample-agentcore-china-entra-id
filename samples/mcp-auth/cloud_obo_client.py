# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Employee-only client for the Runtime-hosted OBO tool; no private key needed."""
import argparse
import json
import time

from client import MCPClient, evidence
import entra
import local_config as local

TOOL_NAME = "entra_check_my_graph_identity"
SAFE_RESULT_FIELDS = (
    "recorded_at_utc", "completed_at_utc", "flow", "execution_location",
    "agentcore_runtime_used", "agentcore_identity_used", "client_authentication",
    "credential_source", "tokens_recorded", "profile_values_recorded", "region",
    "status", "stage", "error", "error_codes", "correlation_id", "aws_request_id",
    "claims_challenge_received", "token_a_validated", "obo_access_token_received",
)
SAFE_CASE_FIELDS = (
    "operation", "http_status", "request_id", "same_user_as_verified_token_a",
    "profile_fields_requested", "profile_values_recorded", "passed",
)


def safe_cloud_result(result):
    value = result.get("structuredContent")
    if not isinstance(value, dict):
        value = {}
        for content in result.get("content", []):
            if content.get("type") == "text":
                try:
                    candidate = json.loads(content["text"])
                except (ValueError, TypeError):
                    continue
                if isinstance(candidate, dict):
                    value = candidate
                    break
    safe = {k: value[k] for k in SAFE_RESULT_FIELDS if k in value}
    safe["cases"] = [
        {k: row[k] for k in SAFE_CASE_FIELDS if k in row}
        for row in value.get("cases", []) if isinstance(row, dict)
    ]
    return safe


def test_cloud(cfg, token):
    entra.verify(token, cfg)
    state = json.loads((local.ROOT / ".state/cloud-obo-deployment.json").read_text(encoding="utf-8-sig"))
    client = MCPClient(state["runtime"]["url"], region=cfg["region"], bearer=token)
    rows = []
    response, value = client.initialize()
    rows.append(evidence("cloud_obo_initialize", response, value, expected_success=True))
    if not rows[-1]["passed"]:
        return rows
    response, value = client.rpc("tools/list")
    row = evidence("cloud_obo_tools_list", response, value, expected_success=True)
    tools = value.get("result", {}).get("tools", [])
    row["tools"] = [t["name"] for t in tools]
    selected = [t for t in tools if t["name"] == TOOL_NAME]
    row["passed"] = row["passed"] and len(selected) == 1 and not selected[0].get("inputSchema", {}).get("properties")
    rows.append(row)
    if not row["passed"]:
        return rows
    response, value = client.rpc("tools/call", {"name": TOOL_NAME, "arguments": {}})
    row = evidence("cloud_obo_graph_me", response, value, expected_success=True)
    cloud = safe_cloud_result(value.get("result", {}))
    graph = cloud.get("cases", [])
    row["passed"] = bool(
        row["passed"] and cloud.get("status") == "passed"
        and cloud.get("agentcore_runtime_used") is True
        and cloud.get("agentcore_identity_used") is False
        and cloud.get("execution_location") == "agentcore_runtime"
        and cloud.get("client_authentication") == "certificate"
        and cloud.get("token_a_validated") is True
        and cloud.get("obo_access_token_received") is True
        and len(graph) == 1 and graph[0].get("http_status") == 200
        and graph[0].get("same_user_as_verified_token_a") is True
    )
    row["cloud_result"] = cloud
    rows.append(row)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)
    cfg = local.config(args.config)
    report = {
        "recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "flow": "Employee PKCE -> China AgentCore Runtime MCP -> certificate OBO -> China Graph",
        "region": cfg["region"], "tokens_recorded": False,
        "client_credentials_required_on_employee_device": False,
    }
    try:
        login = entra.interactive(cfg, timeout=args.timeout)
        if not login.get("access_token"):
            report.update(status="blocked", stage="interactive_login", **entra.safe_error(login))
        else:
            rows = test_cloud(cfg, login["access_token"])
            report.update(
                status="passed" if len(rows) == 3 and all(r["passed"] for r in rows) else "failed",
                cases=rows,
            )
    except Exception as error:
        report.update(status="failed", stage="client_verification_or_runtime_mcp", error=type(error).__name__)
    report["completed_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    output = local.ROOT / "results/cloud-obo.json"
    local.save(output, report, private=False)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("结果文件: " + str(output))
    return report["status"] == "passed"


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
