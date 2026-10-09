# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Native Identity custom China OAuth provider and real M2M resource invocation.

Requires an authorized Entra confidential client, application permission and a
deployed app-only sample entry. No synthetic OAuth tokens are accepted as proof.
"""
import argparse
import json
import time

from botocore.exceptions import ClientError

import entra
import lab

IDENTITY_STATE = lab.ROOT / ".state/oauth-provider.json"


def configure(cfg, sess):
    client_id = cfg.get("machine_client_app_id")
    if not client_id:
        raise RuntimeError("Authorized machine client is required")
    control = sess.client("bedrock-agentcore-control")
    name = cfg["gateway_prefix"] + "-entra-oauth"
    discovery = f'{cfg["authority_host"]}/{cfg["tenant_id"]}/v2.0/.well-known/openid-configuration'
    if IDENTITY_STATE.exists():
        state = json.loads(IDENTITY_STATE.read_text())
        if (state["name"], state["client_id"], state["tenant_id"], state["region"]) != (
            name, client_id, cfg["tenant_id"], cfg["region"],
        ):
            raise RuntimeError("Existing provider state differs; review it before changing credentials")
        current = control.get_oauth2_credential_provider(name=name)
        output = current["oauth2ProviderConfigOutput"]["customOauth2ProviderConfig"]
        if (
            current["credentialProviderArn"] != state["arn"]
            or output["clientId"] != client_id
            or output["oauthDiscovery"]["discoveryUrl"] != discovery
            or state["arn"].split(":")[4] != cfg["account_id"]
        ):
            raise RuntimeError("Tracked machine provider differs from the deployed provider")
        state["client_secret_arn"] = current["clientSecretArn"]["secretArn"]
    else:
        try:
            control.get_oauth2_credential_provider(name=name)
        except control.exceptions.ResourceNotFoundException:
            pass
        else:
            raise RuntimeError("An untracked machine provider already exists")
        secret = entra.read_client_secret()
        result = control.create_oauth2_credential_provider(
            name=name, credentialProviderVendor="CustomOauth2",
            oauth2ProviderConfigInput={"customOauth2ProviderConfig": {
                "clientId": client_id, "clientSecret": secret,
                "oauthDiscovery": {
                    "discoveryUrl": discovery,
                },
            }},
            tags={"Project": cfg["project_tag"]},
        )
        state = {
            "name": name, "arn": result["credentialProviderArn"], "callback_url": result["callbackUrl"],
            "client_id": client_id, "tenant_id": cfg["tenant_id"], "region": cfg["region"],
            "account_id": cfg["account_id"],
            "client_secret_arn": result["clientSecretArn"]["secretArn"],
        }
        lab.save(IDENTITY_STATE, state)
    if "workload_name" not in state:
        workload = control.create_workload_identity(
            name=cfg["gateway_prefix"] + "-oauth-workload", tags={"Project": cfg["project_tag"]},
        )
        state.update(workload_name=workload["name"], workload_arn=workload["workloadIdentityArn"])
    lab.save(IDENTITY_STATE, state)
    print(json.dumps(state, indent=2))


def test_m2m(cfg, sess):
    state = json.loads(IDENTITY_STATE.read_text())
    if (state["client_id"], state["tenant_id"], state["region"]) != (
        cfg["machine_client_app_id"], cfg["tenant_id"], cfg["region"],
    ):
        raise RuntimeError("Identity provider configuration mismatch")
    data = sess.client("bedrock-agentcore")
    workload = data.get_workload_access_token(workloadName=state["workload_name"])
    result = data.get_resource_oauth2_token(
        workloadIdentityToken=workload["workloadAccessToken"],
        resourceCredentialProviderName=state["name"],
        scopes=[f'{cfg["api_app_id"]}/.default'], oauth2Flow="M2M",
    )
    token = result.get("accessToken")
    if not token:
        raise RuntimeError("Identity did not return an access token")
    rows = entra.test_token(cfg, token, application=True)
    report = {
        "recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "flow": "AgentCore Identity M2M -> Entra China -> app-only MCP entry",
        "identity_request_id": result["ResponseMetadata"]["RequestId"],
        "cases": rows, "all_passed": all(r["passed"] for r in rows), "tokens_recorded": False,
    }
    lab.save(lab.ROOT / "results/identity-m2m.json", report, private=False)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report["all_passed"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["configure", "test-m2m"])
    parser.add_argument("--config")
    parser.add_argument("--credentials-csv")
    args = parser.parse_args()
    cfg = lab.config(args.config)
    sess = lab.session(cfg, args.credentials_csv)
    try:
        if args.action == "configure":
            configure(cfg, sess)
        else:
            raise SystemExit(0 if test_m2m(cfg, sess) else 1)
    except ClientError as error:
        print(json.dumps({"error": error.response["Error"]["Code"],
                          "request_id": error.response["ResponseMetadata"]["RequestId"]}))
        raise SystemExit(1)
