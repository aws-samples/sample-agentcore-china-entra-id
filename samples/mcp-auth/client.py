# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Small MCP 2025-03-26 HTTP client with per-request IAM or bearer authentication."""
import json
from urllib.parse import urlparse

import requests

PROTOCOL = "2025-03-26"


class MCPClient:
    def __init__(self, endpoint, *, region="cn-north-1", credentials=None, bearer=None):
        parsed = urlparse(endpoint)
        host = parsed.hostname or ""
        local = parsed.scheme == "http" and host == "127.0.0.1" and parsed.port == 8000
        remote = parsed.scheme == "https" and (
            host == f"bedrock-agentcore.{region}.amazonaws.com.cn"
            or host.endswith(f".gateway.bedrock-agentcore.{region}.amazonaws.com.cn")
        )
        if not (local or remote) or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Only local sample or China AgentCore endpoints are accepted")
        if credentials and bearer:
            raise ValueError("Choose one authentication mode")
        self.endpoint, self.region = endpoint, region
        self.credentials, self.bearer = credentials, bearer
        self.session_id = None
        self.next_id = 0

    def rpc(self, method, params=None, *, notification=False, tamper=False):
        self.next_id += 1
        message = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notification:
            message["id"] = self.next_id
        body = json.dumps(message, separators=(",", ":")).encode()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.credentials:
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest

            request = AWSRequest(method="POST", url=self.endpoint, data=body, headers=headers)
            SigV4Auth(self.credentials, "bedrock-agentcore", self.region).add_auth(request)
            headers = dict(request.headers)
        if self.bearer:
            headers["Authorization"] = "Bearer " + self.bearer
        if tamper:
            if not self.credentials:
                raise ValueError("Signature tampering requires IAM signing")
            body += b" "
        try:
            response = requests.post(
                self.endpoint, data=body, headers=headers, timeout=(15, 120), allow_redirects=False,
            )
            response.raise_for_status()
        except requests.HTTPError as error:
            # Keep the status for the sample's access-denial checks, but never
            # accept an error body or session header as a successful MCP reply.
            if error.response is None:
                raise RuntimeError("MCP HTTP request failed without a response") from None
            return error.response, {"error": {"message": "MCP HTTP request failed"}}
        if not 200 <= response.status_code < 300:
            return response, {"error": {"message": "Unexpected MCP HTTP status"}}
        try:
            value = response.json()
        except ValueError:
            value = {}
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    candidate = json.loads(line[5:].strip())
                    if candidate.get("id") == message.get("id"):
                        value = candidate
                        break
        if not isinstance(value, dict):
            value = {}
        if not notification and value.get("id") != message["id"]:
            raise RuntimeError("MCP response ID mismatch")
        if response.headers.get("Mcp-Session-Id"):
            self.session_id = response.headers["Mcp-Session-Id"]
        return response, value

    def initialize(self):
        response, value = self.rpc("initialize", {
            "protocolVersion": PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "china-mcp-auth-reference", "version": "0.1.0"},
        })
        if response.status_code != 200 or "error" in value:
            return response, value
        if value.get("result", {}).get("protocolVersion") != PROTOCOL:
            raise RuntimeError("Unexpected negotiated MCP version")
        notified, _ = self.rpc("notifications/initialized", notification=True)
        if notified.status_code not in (200, 202, 204):
            raise RuntimeError("MCP initialization notification rejected")
        return response, value


def evidence(case, response, value, *, expected_success=False, marker=None):
    result = value.get("result", {})
    successful = response.status_code == 200 and "error" not in value and not result.get("isError", False)
    if marker:
        successful = successful and marker in json.dumps(result, ensure_ascii=False)
    return {
        "case": case,
        "http_status": response.status_code,
        "request_id": response.headers.get("x-amzn-requestid"),
        "rpc_error_code": value.get("error", {}).get("code"),
        "passed": successful if expected_success else response.status_code in (401, 403),
        "expected": "allowed" if expected_success else "denied",
    }


def summarize(rows):
    return {
        "successful_allowed_requests": sum(row["passed"] and row["expected"] == "allowed" for row in rows),
        "correctly_rejected_requests": sum(row["passed"] and row["expected"] == "denied" for row in rows),
        "unexpected_results": sum(not row["passed"] for row in rows),
        "total_checks": len(rows),
    }


def exercise(endpoint, *, prefix="", region="cn-north-1", credentials=None, bearer=None):
    client = MCPClient(endpoint, region=region, credentials=credentials, bearer=bearer)
    rows = []
    response, value = client.initialize()
    rows.append(evidence(prefix + "initialize", response, value, expected_success=True))
    if not rows[-1]["passed"]:
        return rows
    response, value = client.rpc("tools/list")
    row = evidence(prefix + "tools_list", response, value, expected_success=True)
    tools = value.get("result", {}).get("tools", [])
    row["tools"] = [t["name"] for t in tools]
    expected_names = {"get_maintenance_guide", "get_parts_stock", "describe_access_boundary"}
    row["passed"] = row["passed"] and expected_names.issubset({t["name"].split("___")[-1] for t in tools})
    rows.append(row)
    name = next((t["name"] for t in tools if t["name"].endswith("get_maintenance_guide")), None)
    if name:
        response, value = client.rpc("tools/call", {
            "name": name, "arguments": {"fault_code": "P-DEMO-001"},
        })
        row = evidence(prefix + "maintenance_call", response, value, expected_success=True, marker="DEMO-GUIDE-001")
        if row["passed"]:
            row["synthetic_result"] = value["result"]
        rows.append(row)
    name = next((t["name"] for t in tools if t["name"].endswith("get_parts_stock")), None)
    if name:
        response, value = client.rpc("tools/call", {"name": name, "arguments": {"part_number": "DEMO-PART-001"}})
        row = evidence(prefix + "parts_call", response, value, expected_success=True, marker="DEMO-PART-001")
        if row["passed"]:
            row["synthetic_result"] = value["result"]
        rows.append(row)
    return rows
