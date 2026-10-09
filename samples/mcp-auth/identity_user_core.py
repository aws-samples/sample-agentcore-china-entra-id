# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Native AgentCore Identity user authorization; no OBO exchange in this path."""
import json
import os
import secrets
import time
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

import entra
import obo

BEGIN_TOOL = "entra_identity_begin_authorization"
CHECK_TOOL = "entra_identity_check_my_graph_identity"
GRAPH_SCOPE = "https://microsoftgraph.chinacloudapi.cn/User.Read"


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def settings():
    cfg = json.loads(os.environ["IDENTITY_USER_CONFIG"])
    if cfg["region"] not in ("cn-north-1", "cn-northwest-1"):
        raise ValueError("China region required")
    if cfg["authority_host"] != "https://login.partner.microsoftonline.cn":
        raise ValueError("China authority required")
    return cfg


def identity_client(cfg):
    return boto3.client("bedrock-agentcore", region_name=cfg["region"], config=Config(
        connect_timeout=10, read_timeout=25, retries={"max_attempts": 1},
    ))


def validate_authorization_url(url, cfg):
    parsed = urlparse(url)
    hosts = {
        urlparse(cfg["authority_host"]).hostname,
        f'bedrock-agentcore.{cfg["region"]}.amazonaws.com.cn',
    }
    if (parsed.scheme != "https" or parsed.hostname not in hosts
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or parsed.fragment):
        raise ValueError("Unexpected Identity authorization endpoint")
    return url


def run(authorization, *, begin=False):
    """Only the trusted browser backend receives the transient authorization URL."""
    report = {
        "recorded_at_utc": now(), "flow": "USER_FEDERATION",
        "agentcore_runtime_used": os.environ.get("IDENTITY_USER_LOCATION") == "agentcore_runtime",
        "agentcore_identity_used": True, "client_authentication": "client_secret",
        "tokens_recorded": False, "profile_values_recorded": False,
    }
    stage = "inbound_token"
    try:
        cfg = settings()
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise ValueError("Bearer header required")
        claims = entra.verify(parts[1], cfg)
        if not claims.get("oid"):
            raise ValueError("Employee object identifier required")
        report.update(token_a_validated=True, region=cfg["region"])
        client = identity_client(cfg)
        stage = "get_workload_access_token_for_jwt"
        workload = client.get_workload_access_token_for_jwt(
            workloadName=cfg["workload_name"], userToken=parts[1],
        )
        report["workload_request_id"] = workload["ResponseMetadata"].get("RequestId")
        params = {
            "workloadIdentityToken": workload["workloadAccessToken"],
            "resourceCredentialProviderName": cfg["provider_name"],
            "scopes": [GRAPH_SCOPE], "oauth2Flow": "USER_FEDERATION",
            "resourceOauth2ReturnUrl": cfg["application_return_url"],
            "forceAuthentication": begin,
        }
        state = secrets.token_urlsafe(32)
        if begin:
            params["customState"] = state
        stage = "get_resource_oauth2_token"
        result = client.get_resource_oauth2_token(**params)
        report["identity_request_id"] = result["ResponseMetadata"].get("RequestId")
        if begin and result.get("authorizationUrl") and result.get("sessionUri"):
            # These fields are internal transport data, excluded from reports.
            return {
                "status": "authorization_required",
                "authorization_url": validate_authorization_url(result["authorizationUrl"], cfg),
                "session_uri": result["sessionUri"], "custom_state": state,
                "expires_at": int(time.time()) + 570, "evidence": report,
            }
        if not result.get("accessToken"):
            report.update(status="authorization_required", stage=stage)
            return report
        if begin:
            report.update(status="failed", stage="new_authorization_url_not_returned")
            return report
        report["identity_access_token_received"] = True
        stage = "graph_me"
        graph = obo.graph_me(result["accessToken"], claims["oid"])
        report["graph"] = graph
        report["status"] = "passed" if graph["passed"] else "failed"
    except ClientError as error:
        report.update(status="failed", stage=stage,
                      error=error.response["Error"]["Code"],
                      aws_request_id=error.response.get("ResponseMetadata", {}).get("RequestId"))
    except Exception as error:
        report.update(status="failed", stage=stage, error=type(error).__name__)
    report["completed_at_utc"] = now()
    return report
