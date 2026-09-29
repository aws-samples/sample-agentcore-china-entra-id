"""Deploy and invoke a China Gateway with native OAuth M2M to the JWT MCP Runtime."""
import argparse
from datetime import datetime, timezone
import json
import time

from botocore.credentials import Credentials

from client import exercise
from identity import IDENTITY_STATE
import lab
from machine_scenarios import business_result

STATE = lab.ROOT / ".state/gateway-oauth-deployment.json"


def provider_state(cfg):
    value = json.loads(IDENTITY_STATE.read_text())
    if any(value.get(key) != expected for key, expected in {
        "client_id": cfg["machine_client_app_id"],
        "account_id": cfg["account_id"], "region": cfg["region"],
        "tenant_id": cfg["tenant_id"],
    }.items()):
        raise RuntimeError("Machine OAuth provider state differs")
    return value


def service_policy(cfg, provider, workload_arn):
    base = f'arn:aws-cn:bedrock-agentcore:{cfg["region"]}:{cfg["account_id"]}'
    directory = base + ":workload-identity-directory/default"
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "GatewayWorkload", "Effect": "Allow",
         "Action": ["bedrock-agentcore:GetWorkloadAccessToken"],
         "Resource": [directory, workload_arn]},
        {"Sid": "MachineOAuthToken", "Effect": "Allow",
         "Action": ["bedrock-agentcore:GetResourceOauth2Token"],
         "Resource": [directory, workload_arn, base + ":token-vault/default", provider["arn"]]},
        {"Sid": "MachineClientCredential", "Effect": "Allow",
         "Action": ["secretsmanager:GetSecretValue"],
         "Resource": provider["client_secret_arn"]},
    ]}


def oauth_target(cfg, provider, endpoint):
    return {
        "name": "oauth-runtime",
        "description": "Native OAuth client credentials to the synthetic app JWT MCP Runtime",
        "targetConfiguration": {"mcp": {"mcpServer": {"endpoint": endpoint}}},
        "credentialProviderConfigurations": [{
            "credentialProviderType": "OAUTH",
            "credentialProvider": {"oauthCredentialProvider": {
                "providerArn": provider["arn"],
                "scopes": [f'{cfg["api_app_id"]}/.default'],
                "grantType": "CLIENT_CREDENTIALS",
            }},
        }],
    }


def wait_ready(get, label):
    previous = None
    for attempt in range(30):
        value = get()
        status = value["status"]
        if status != previous:
            print(json.dumps({"resource": label, "status": status}), flush=True)
            previous = status
        if status == "READY":
            return value
        if status in ("FAILED", "CREATE_FAILED", "UPDATE_UNSUCCESSFUL"):
            raise RuntimeError(label + " failed; inspect its recorded resource ID")
        time.sleep(5)
    raise RuntimeError(label + " is still provisioning; rerun to continue tracked resources")


def deploy(cfg, sess):
    provider = provider_state(cfg)
    control = sess.client("bedrock-agentcore-control")
    runtime = lab.read_state()["runtimes"]["app"]
    current_runtime = control.get_agent_runtime(agentRuntimeId=runtime["id"])
    if current_runtime["status"] != "READY":
        raise RuntimeError("Machine JWT Runtime is not ready")
    if current_runtime["authorizerConfiguration"] != lab.authorizer(cfg, "app"):
        raise RuntimeError("Machine JWT Runtime authorization differs")
    if (
        runtime["arn"] != current_runtime["agentRuntimeArn"]
        or runtime["url"] != lab.runtime_url(cfg, current_runtime["agentRuntimeArn"])
    ):
        raise RuntimeError("Machine Runtime endpoint differs from the AWS resource")
    current_provider = control.get_oauth2_credential_provider(name=provider["name"])
    if (
        current_provider["credentialProviderArn"] != provider["arn"]
        or current_provider["clientSecretArn"]["secretArn"] != provider["client_secret_arn"]
        or current_provider["oauth2ProviderConfigOutput"]["customOauth2ProviderConfig"]["clientId"]
        != cfg["machine_client_app_id"]
    ):
        raise RuntimeError("Machine OAuth provider identity differs")
    base = f'arn:aws-cn:bedrock-agentcore:{cfg["region"]}:{cfg["account_id"]}'
    name = cfg["gateway_prefix"] + "-oauth"
    role_name = cfg["runtime_prefix"] + "_gateway_oauth_role"
    trust = lab.service_trust(cfg, base + ":gateway/" + name + "-*")
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    if state and any(state.get(k) != v for k, v in {
        "account_id": cfg["account_id"], "region": cfg["region"],
        "name": name, "provider_arn": provider["arn"], "target_runtime_arn": runtime["arn"],
    }.items()):
        raise RuntimeError("Tracked OAuth Gateway belongs to another configuration")
    if not state:
        for page in control.get_paginator("list_gateways").paginate():
            if any(item["name"] == name for item in page["items"]):
                raise RuntimeError("An untracked OAuth Gateway already exists")
        workload = base + ":workload-identity-directory/default/workload-identity/" + name + "-*"
        role = lab.ensure_role(sess, cfg, role_name, trust, service_policy(cfg, provider, workload))
        created = lab.after_role_propagation(lambda: control.create_gateway(
            name=name, roleArn=role, protocolType="MCP",
            protocolConfiguration={"mcp": {"supportedVersions": ["2025-03-26"]}},
            authorizerType="AWS_IAM",
            description="IAM caller to native Entra China OAuth M2M JWT MCP target",
            tags={"Project": cfg["project_tag"]},
        ))
        state = {
            "account_id": cfg["account_id"], "region": cfg["region"], "name": name,
            "id": created["gatewayId"], "arn": created["gatewayArn"],
            "url": created["gatewayUrl"], "role_arn": role, "role_name": role_name,
            "provider_arn": provider["arn"], "target_runtime_arn": runtime["arn"],
            "target_runtime_url": runtime["url"],
        }
        workload_arn = created.get("workloadIdentityDetails", {}).get("workloadIdentityArn")
        if workload_arn:
            state["workload_arn"] = workload_arn
        lab.save(STATE, state)
    gateway = wait_ready(lambda: control.get_gateway(gatewayIdentifier=state["id"]), "OAuth Gateway")
    if gateway["authorizerType"] != "AWS_IAM" or gateway["roleArn"] != state["role_arn"]:
        raise RuntimeError("Tracked Gateway inbound authentication differs")
    workload_arn = gateway.get("workloadIdentityDetails", {}).get("workloadIdentityArn")
    if not workload_arn:
        raise RuntimeError("Gateway workload identity is not available yet; continue this tracked Gateway later")
    if state.get("workload_arn") and workload_arn != state["workload_arn"]:
        raise RuntimeError("Gateway workload identity differs")
    state["workload_arn"] = workload_arn
    lab.save(STATE, state)
    # Narrow the initial name prefix to the workload identity returned by AWS.
    lab.ensure_role(sess, cfg, role_name, trust, service_policy(cfg, provider, state["workload_arn"]))
    target_request = oauth_target(cfg, provider, runtime["url"])
    if "target_id" not in state:
        response = lab.after_role_propagation(lambda: control.create_gateway_target(
            gatewayIdentifier=state["id"], **target_request,
        ))
        state["target_id"] = response["targetId"]
        lab.save(STATE, state)
    target = wait_ready(lambda: control.get_gateway_target(
        gatewayIdentifier=state["id"], targetId=state["target_id"],
    ), "OAuth MCP target")
    for key in ("targetConfiguration", "credentialProviderConfigurations"):
        if target[key] != target_request[key]:
            raise RuntimeError("Gateway OAuth target differs from the planned configuration")
    state.update(status="READY", target_status="READY", native_oauth_target_verified=True)
    lab.save(STATE, state)
    lab.save(lab.ROOT / "results/gateway-oauth-deployment.json", {
        **state, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "gateway_inbound_authentication": "AWS_IAM",
        "gateway_outbound_authentication": "OAUTH / CLIENT_CREDENTIALS",
        "gateway_service_policy": service_policy(cfg, provider, state["workload_arn"]),
        "target_configuration": target_request,
        "end_to_end_test_executed": False,
    }, private=False)
    return state


def test(cfg, sess):
    state = json.loads(STATE.read_text())
    if (state["account_id"], state["region"]) != (cfg["account_id"], cfg["region"]):
        raise RuntimeError("Gateway deployment account differs")
    provider = provider_state(cfg)
    control = sess.client("bedrock-agentcore-control")
    target = control.get_gateway_target(gatewayIdentifier=state["id"], targetId=state["target_id"])
    expected = oauth_target(cfg, provider, state["target_runtime_url"])
    if target["credentialProviderConfigurations"] != expected["credentialProviderConfigurations"]:
        raise RuntimeError("Native OAuth target credential configuration differs")
    if target["targetConfiguration"] != expected["targetConfiguration"]:
        raise RuntimeError("Native OAuth target endpoint differs")
    principal = lab.caller_principal(sess, sess.client("sts").get_caller_identity()["Arn"])
    caller_role = lab.ensure_role(
        sess, cfg, cfg["runtime_prefix"] + "_oauth_caller",
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole",
        }]},
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": ["bedrock-agentcore:InvokeGateway"], "Resource": state["arn"],
        }]},
    )
    value = sess.client("sts").assume_role(
        RoleArn=caller_role, RoleSessionName="native-oauth-mcp-test", DurationSeconds=900,
    )["Credentials"]
    credentials = Credentials(value["AccessKeyId"], value["SecretAccessKey"], value["SessionToken"])
    rows = exercise(
        state["url"], prefix="native_oauth_gateway_", region=cfg["region"], credentials=credentials,
    )
    for row in rows:
        if "synthetic_result" in row:
            result = business_result(row["synthetic_result"])
            if row["case"].endswith("parts_call"):
                row["business_result_verified"] = result == {
                    "part_number": "DEMO-PART-001", "warehouse": "DEMO-CN",
                    "quantity": 12, "synthetic": True,
                }
            else:
                row["business_result_verified"] = result.get("guide_id") == "DEMO-GUIDE-001" and result.get("synthetic") is True
            row["passed"] = row["passed"] and row["business_result_verified"]
    report = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "scenario": "IAM caller -> Gateway native OAuth M2M -> Entra China -> app JWT Runtime MCP",
        "account_id": cfg["account_id"], "region": cfg["region"],
        "gateway_id": state["id"], "target_id": state["target_id"],
        "target_runtime_arn": state["target_runtime_arn"],
        "caller_authentication": "IAM SigV4 with STS role scoped to this Gateway",
        "caller_role_arn": caller_role, "caller_entra_token_used": False,
        "gateway_target_credential_type": "OAUTH", "gateway_oauth_grant_type": "CLIENT_CREDENTIALS",
        "native_oauth_target_configuration_verified": True,
        "identity_provider_name": provider["name"],
        "execution_location": "Gateway performs OAuth outbound authentication in AWS China",
        "cases": rows,
        "successful_business_calls": sum(row.get("business_result_verified", False) for row in rows),
        "end_to_end_completed": len(rows) == 4 and all(row["passed"] for row in rows),
        "tokens_recorded": False, "credentials_recorded": False,
    }
    report["status"] = "passed" if report["end_to_end_completed"] else "failed"
    timestamp = report["recorded_at_utc"].replace("-", "").replace(":", "").split(".")[0] + "Z"
    for filename in ("gateway-native-oauth.json", "gateway-native-oauth-" + timestamp + ".json"):
        lab.save(lab.ROOT / "results" / filename, report, private=False)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["deploy", "test"])
    parser.add_argument("--credentials-csv")
    args = parser.parse_args()
    cfg = lab.config()
    try:
        result = {"deploy": deploy, "test": test}[args.action](
            cfg, lab.session(cfg, args.credentials_csv),
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.action == "test" and not result["end_to_end_completed"]:
            raise SystemExit(1)
    except Exception as error:
        diagnostic = {"status": "failed", "error_type": type(error).__name__}
        if isinstance(error, RuntimeError):
            diagnostic["detail"] = str(error)
        response = getattr(error, "response", None)
        if isinstance(response, dict):
            diagnostic.update(error_code=response.get("Error", {}).get("Code"),
                              request_id=response.get("ResponseMetadata", {}).get("RequestId"),
                              operation=getattr(error, "operation_name", None))
        print(json.dumps(diagnostic))
        raise SystemExit(1)
