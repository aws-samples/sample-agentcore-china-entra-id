# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Parameterised deployment and evidence collection for the China MCP sample.

Standard SDK credentials are the default. --credentials-csv is a local lab
convenience; the file and its contents are never uploaded to AWS.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import time
from urllib.parse import quote
import zipfile

import boto3
from botocore.exceptions import ClientError

from client import MCPClient, evidence, exercise, summarize
from local_config import ROOT, STATE, config, read_state, save


def session(cfg, credentials_csv=None):
    kwargs = {"region_name": cfg["region"]}
    if credentials_csv:
        with Path(credentials_csv).open(encoding="utf-8-sig", newline="") as stream:
            row = next(csv.DictReader(stream))
        kwargs.update(aws_access_key_id=row["Access key ID"], aws_secret_access_key=row["Secret access key"])
    sess = boto3.Session(**kwargs)
    caller = sess.client("sts").get_caller_identity()
    if caller["Account"] != cfg["account_id"] or not caller["Arn"].startswith("arn:aws-cn:"):
        raise RuntimeError("Account or partition mismatch")
    return sess


def authorizer(cfg, mode="jwt"):
    def exact(name, value):
        return {"inboundTokenClaimName": name, "inboundTokenClaimValueType": "STRING",
                "authorizingClaimMatchValue": {"claimMatchOperator": "EQUALS",
                                              "claimMatchValue": {"matchValueString": value}}}
    value = {
        "discoveryUrl": f'{cfg["authority_host"]}/{cfg["tenant_id"]}/v2.0/.well-known/openid-configuration',
        "allowedAudience": [cfg["api_app_id"]], "allowedScopes": [cfg["scope"]],
        "customClaims": [exact("tid", cfg["tenant_id"]), exact("azp", cfg["client_app_id"])],
    }
    if mode == "app":
        value.pop("allowedScopes")
        value["customClaims"] = [
            exact("tid", cfg["tenant_id"]), exact("azp", cfg["machine_client_app_id"]),
            {"inboundTokenClaimName": "roles", "inboundTokenClaimValueType": "STRING_ARRAY",
             "authorizingClaimMatchValue": {"claimMatchOperator": "CONTAINS",
                                           "claimMatchValue": {"matchValueString": cfg["machine_role"]}}},
        ]
    return {"customJWTAuthorizer": value}


def modes(cfg):
    return ("iam", "jwt", "app") if cfg.get("machine_client_app_id") and cfg.get("machine_role") else ("iam", "jwt")


def selected_modes(cfg, mode=None):
    available = modes(cfg)
    if mode is None:
        return available
    if mode not in available:
        raise RuntimeError("Requested mode is not configured")
    return (mode,)


def runtime_url(cfg, arn):
    return f'https://bedrock-agentcore.{cfg["region"]}.amazonaws.com.cn/runtimes/{quote(arn, safe="")}/invocations?qualifier=DEFAULT'


def ensure_role(sess, cfg, name, trust, policy):
    iam = sess.client("iam")
    try:
        role = iam.get_role(RoleName=name)["Role"]
        if {t["Key"]: t["Value"] for t in role.get("Tags", [])}.get("Project") != cfg["project_tag"]:
            raise RuntimeError("Refusing to adopt an unrelated role")
    except iam.exceptions.NoSuchEntityException:
        role = iam.create_role(
            RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[{"Key": "Project", "Value": cfg["project_tag"]}],
        )["Role"]
    if role["AssumeRolePolicyDocument"] != trust:
        raise RuntimeError("Existing role trust differs; review before changing it")
    iam.put_role_policy(RoleName=name, PolicyName="SampleResourcesOnly", PolicyDocument=json.dumps(policy))
    return role["Arn"]


def service_trust(cfg, resource):
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": cfg["account_id"]},
                      "ArnLike": {"aws:SourceArn": resource}},
    }]}


def after_role_propagation(operation):
    for attempt in range(5):
        try:
            return operation()
        except ClientError as error:
            message = error.response["Error"].get("Message", "").lower()
            if attempt == 4 or not any(s in message for s in ("role validation failed", "cannot be assumed")):
                raise
            time.sleep(min(2 ** (attempt + 1), 10))


def package():
    directory = ROOT / "build/package"
    if not (directory / "mcp").is_dir():
        raise RuntimeError("Build Linux ARM64 runtime dependencies first; see README")
    archive = ROOT / "build/runtime.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(ROOT / "server.py", "server.py")
        for file in sorted(directory.rglob("*")):
            if file.is_file() and "__pycache__" not in file.parts and file.suffix != ".pyc":
                bundle.write(file, file.relative_to(directory))
    print(json.dumps({"archive_bytes": archive.stat().st_size,
                      "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}))


def deploy(cfg, sess, mode=None):
    requested_modes = selected_modes(cfg, mode)
    state = read_state()
    if state and (state["account_id"], state["region"], state["project_tag"]) != (
        cfg["account_id"], cfg["region"], cfg["project_tag"]
    ):
        raise RuntimeError("State belongs to another deployment")
    state.update(account_id=cfg["account_id"], region=cfg["region"], project_tag=cfg["project_tag"])
    state.setdefault("runtimes", {})
    state.setdefault("gateways", {})
    control, s3 = sess.client("bedrock-agentcore-control"), sess.client("s3")
    s3.head_bucket(Bucket=cfg["bucket"], ExpectedBucketOwner=cfg["account_id"])
    tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=cfg["bucket"])["TagSet"]}
    if tags.get("Project") != cfg["bucket_project_tag"]:
        raise RuntimeError("Deployment bucket tag mismatch")
    block = s3.get_public_access_block(Bucket=cfg["bucket"])["PublicAccessBlockConfiguration"]
    if not all(block.values()):
        raise RuntimeError("Deployment bucket must block all public access")
    code = (ROOT / "build/runtime.zip").read_bytes()
    key = "mcp-auth/" + hashlib.sha256(code).hexdigest()[:24] + ".zip"
    s3.put_object(Bucket=cfg["bucket"], Key=key, Body=code, ContentType="application/zip",
                  ExpectedBucketOwner=cfg["account_id"], ServerSideEncryption="AES256")
    state.update(bucket=cfg["bucket"], object_key=key)
    save(STATE, state)
    base = f'arn:aws-cn:bedrock-agentcore:{cfg["region"]}:{cfg["account_id"]}'
    known = {r["agentRuntimeName"] for page in control.get_paginator("list_agent_runtimes").paginate()
             for r in page["agentRuntimes"]}
    for mode in requested_modes:
        name = cfg["runtime_prefix"] + "_" + mode
        log = f'arn:aws-cn:logs:{cfg["region"]}:{cfg["account_id"]}:log-group:/aws/bedrock-agentcore/runtimes/{name}-*'
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
             "Resource": f'arn:aws-cn:s3:::{cfg["bucket"]}/mcp-auth/*'},
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:DescribeLogStreams",
                                           "logs:CreateLogStream", "logs:PutLogEvents"],
             "Resource": [log, log + ":*"]},
            {"Effect": "Allow", "Action": ["logs:DescribeLogGroups"],
             "Resource": f'arn:aws-cn:logs:{cfg["region"]}:{cfg["account_id"]}:log-group:*'},
        ]}
        role = ensure_role(sess, cfg, name + "_role", service_trust(cfg, base + f":runtime/{name}-*"), policy)
        state.setdefault("runtime_roles", {})[mode] = role
        save(STATE, state)
        if mode in state["runtimes"]:
            continue
        if name in known:
            raise RuntimeError("Untracked Runtime name already exists")
        request = {
            "agentRuntimeName": name,
            "agentRuntimeArtifact": {"codeConfiguration": {
                "code": {"s3": {"bucket": cfg["bucket"], "prefix": key}},
                "runtime": "PYTHON_3_12", "entryPoint": ["server.py"],
            }},
            "roleArn": role, "networkConfiguration": {"networkMode": "PUBLIC"},
            "protocolConfiguration": {"serverProtocol": "MCP"},
            "lifecycleConfiguration": {"idleRuntimeSessionTimeout": 300, "maxLifetime": 1800},
            "description": "China MCP authentication reference; read-only synthetic business tools",
            "tags": {"Project": cfg["project_tag"]},
        }
        if mode != "iam":
            request["authorizerConfiguration"] = authorizer(cfg, mode)
        result = after_role_propagation(lambda: control.create_agent_runtime(**request))
        state["runtimes"][mode] = {
            "id": result["agentRuntimeId"], "arn": result["agentRuntimeArn"],
            "url": runtime_url(cfg, result["agentRuntimeArn"]), "version": result["agentRuntimeVersion"],
        }
        save(STATE, state)
        print(json.dumps({"mode": mode, "runtime": result["agentRuntimeId"], "status": result["status"]}), flush=True)


def gateways(cfg, sess, mode=None):
    requested_modes = selected_modes(cfg, mode)
    state = read_state()
    control = sess.client("bedrock-agentcore-control")
    runtime = state["runtimes"]["iam"]
    if control.get_agent_runtime(agentRuntimeId=runtime["id"])["status"] != "READY":
        raise RuntimeError("IAM MCP Runtime is not READY")
    base = f'arn:aws-cn:bedrock-agentcore:{cfg["region"]}:{cfg["account_id"]}'
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["bedrock-agentcore:InvokeAgentRuntime"],
        "Resource": [runtime["arn"], runtime["arn"] + "/runtime-endpoint/DEFAULT"],
    }]}
    role = ensure_role(sess, cfg, cfg["runtime_prefix"] + "_gateway_role",
                       service_trust(cfg, base + ":gateway/*"), policy)
    state["gateway_role"] = role
    save(STATE, state)
    for mode in requested_modes:
        if mode not in state["gateways"]:
            name = cfg["gateway_prefix"] + "-" + mode
            existing = control.list_gateways(maxResults=100)["items"]
            if any(g["name"] == name for g in existing):
                raise RuntimeError("Untracked Gateway name exists")
            request = dict(
                name=name, roleArn=role, protocolType="MCP",
                protocolConfiguration={"mcp": {"supportedVersions": ["2025-03-26"]}},
                authorizerType="AWS_IAM" if mode == "iam" else "CUSTOM_JWT",
                description="Gateway to a Runtime-hosted synthetic MCP server",
                tags={"Project": cfg["project_tag"]},
            )
            if mode != "iam":
                request["authorizerConfiguration"] = authorizer(cfg, mode)
            result = after_role_propagation(lambda: control.create_gateway(**request))
            state["gateways"][mode] = {
                "id": result["gatewayId"], "arn": result["gatewayArn"], "url": result["gatewayUrl"],
            }
            save(STATE, state)
        gateway = state["gateways"][mode]
        if control.get_gateway(gatewayIdentifier=gateway["id"])["status"] != "READY":
            print(json.dumps({"mode": mode, "status": "GATEWAY_NOT_READY"}), flush=True)
            continue
        if "target_id" not in gateway:
            result = control.create_gateway_target(
                gatewayIdentifier=gateway["id"], name="runtime",
                description="IAM-authenticated Runtime MCP server with shared synthetic data",
                targetConfiguration={"mcp": {"mcpServer": {"endpoint": runtime["url"]}}},
                credentialProviderConfigurations=[{
                    "credentialProviderType": "GATEWAY_IAM_ROLE",
                    "credentialProvider": {"iamCredentialProvider": {"service": "bedrock-agentcore"}},
                }],
            )
            gateway["target_id"] = result["targetId"]
            save(STATE, state)
        target = control.get_gateway_target(gatewayIdentifier=gateway["id"], targetId=gateway["target_id"])
        print(json.dumps({"mode": mode, "target_status": target["status"],
                          "reasons": target.get("statusReasons", [])}), flush=True)


def status(cfg, sess):
    state = read_state()
    control = sess.client("bedrock-agentcore-control")
    rows = []
    for mode, runtime in state.get("runtimes", {}).items():
        result = control.get_agent_runtime(agentRuntimeId=runtime["id"])
        rows.append({"resource": "runtime", "mode": mode, "id": runtime["id"],
                     "status": result["status"], "failure_reason": result.get("failureReason")})
    for mode, gateway in state.get("gateways", {}).items():
        result = control.get_gateway(gatewayIdentifier=gateway["id"])
        row = {"resource": "gateway", "mode": mode, "id": gateway["id"], "status": result["status"]}
        if "target_id" in gateway:
            target = control.get_gateway_target(gatewayIdentifier=gateway["id"], targetId=gateway["target_id"])
            row.update(target_status=target["status"], reasons=target.get("statusReasons", []))
        rows.append(row)
    print(json.dumps(rows, indent=2))
    return rows


def caller_principal(sess, caller):
    """Use the persistent IAM principal, never an ephemeral STS session ARN."""
    if ":user/" in caller:
        return caller
    if ":assumed-role/" in caller:
        role_name = caller.split(":assumed-role/", 1)[1].split("/", 1)[0]
        arn = sess.client("iam").get_role(RoleName=role_name)["Role"]["Arn"]
        if arn.split(":")[:2] != ["arn", "aws-cn"] or arn.split(":")[4] != caller.split(":")[4]:
            raise RuntimeError("Caller role account or partition mismatch")
        return arn
    raise RuntimeError("Use an authorized deployment IAM user or assumed deployment role")


def test_aws(cfg, sess):
    state = read_state()
    # Test actual assumed-role credentials scoped to the sample's IAM resources.
    caller = sess.client("sts").get_caller_identity()["Arn"]
    principal = caller_principal(sess, caller)
    role = ensure_role(
        sess, cfg, cfg["runtime_prefix"] + "_caller",
        {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole",
        }]},
        {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["bedrock-agentcore:InvokeAgentRuntime"],
             "Resource": [state["runtimes"]["iam"]["arn"], state["runtimes"]["iam"]["arn"] + "/runtime-endpoint/DEFAULT"]},
            {"Effect": "Allow", "Action": ["bedrock-agentcore:InvokeGateway"],
             "Resource": state["gateways"]["iam"]["arn"]},
        ]},
    )
    state["caller_role"] = role
    save(STATE, state)
    def assumed(deny=False):
        request = {"RoleArn": role, "RoleSessionName": "mcp-auth-reference", "DurationSeconds": 900}
        if deny:
            request["Policy"] = json.dumps({"Version": "2012-10-17", "Statement": [{
                "Effect": "Deny", "Action": "bedrock-agentcore:*", "Resource": "*",
            }]})
        creds = sess.client("sts").assume_role(**request)["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"], region_name=cfg["region"],
        ).get_credentials().get_frozen_credentials()
    credentials = assumed()
    rows = []
    for resource in ("runtimes", "gateways"):
        endpoint = state[resource]["iam"]["url"]
        rows.extend(exercise(endpoint, prefix=resource + "_iam_", region=cfg["region"], credentials=credentials))
        client = MCPClient(endpoint, region=cfg["region"])
        response, value = client.rpc("tools/list")
        rows.append(evidence(resource + "_unsigned", response, value))
        client = MCPClient(endpoint, region=cfg["region"], credentials=credentials)
        response, value = client.rpc("tools/list", tamper=True)
        rows.append(evidence(resource + "_tampered_sigv4", response, value))
        client = MCPClient(endpoint, region=cfg["region"], credentials=assumed(deny=True))
        response, value = client.rpc("tools/list")
        rows.append(evidence(resource + "_denied_role_session", response, value))
        endpoint = state[resource]["jwt"]["url"]
        for label, bearer in [("missing_bearer", None), ("malformed_bearer", "not-a-jwt")]:
            response, value = MCPClient(endpoint, region=cfg["region"], bearer=bearer).rpc("tools/list")
            rows.append(evidence(resource + "_jwt_" + label, response, value))
    report = {"recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "region": cfg["region"], "caller_identity_kind": "STS assumed role",
              "cases": rows, "all_passed": all(r["passed"] for r in rows),
              "summary": summarize(rows),
              "does_not_prove": ["Entra user login", "Entra client credentials", "Identity OAuth", "OBO", "business ACL"]}
    save(ROOT / "results/aws-mcp.json", report, private=False)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return report["all_passed"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["package", "deploy", "gateways", "status", "test-aws", "test-local"])
    parser.add_argument("--config")
    parser.add_argument("--credentials-csv")
    parser.add_argument("--mode", choices=["iam", "jwt", "app"],
                        help="Deploy only this authentication entry (deploy/gateways only)")
    args = parser.parse_args()
    if args.mode and args.action not in ("deploy", "gateways"):
        parser.error("--mode applies only to deploy and gateways")
    if args.action == "package":
        package()
        return
    if args.action == "test-local":
        rows = exercise("http://127.0.0.1:8000/mcp", prefix="local_")
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        if not all(r["passed"] for r in rows):
            raise SystemExit(1)
        return
    cfg = config(args.config)
    sess = session(cfg, args.credentials_csv)
    action = {"deploy": deploy, "gateways": gateways, "status": status, "test-aws": test_aws}[args.action]
    result = action(cfg, sess, mode=args.mode) if args.action in ("deploy", "gateways") else action(cfg, sess)
    if result is False:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        # Do not log request parameters or arbitrary reflected response text.
        print(json.dumps({"error": error.response["Error"]["Code"],
                          "detail": error.response["Error"].get("Message", "")[:1000],
                          "request_id": error.response["ResponseMetadata"]["RequestId"]}))
        raise SystemExit(1)
