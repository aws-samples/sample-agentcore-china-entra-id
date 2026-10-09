# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Deploy the native Identity sample as a separate China Runtime and HTTPS BFF."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import zipfile

from botocore.exceptions import ClientError

import lab
from local_config import ROOT, config, save
from identity_user_setup import PROVIDER_STATE, configure_provider

STATE = ROOT / ".state/identity-user-deployment.json"
COMMON_SOURCES = ("entra.py", "obo.py", "client.py", "local_config.py", "identity_user_core.py")


def read_state():
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def packages(kinds=("runtime", "web")):
    # Reuse the pinned, Linux ARM64 Python 3.12 dependency bundle; never copy .venv.
    dependencies = ROOT / "build/cloud-obo-package"
    for name in ("boto3", "msal", "requests", "cryptography", "mcp"):
        if not (dependencies / name).is_dir():
            raise RuntimeError("Build requirements-cloud-obo.lock for Linux ARM64 Python 3.12 first")
    artifacts = {}
    for kind in kinds:
        path = ROOT / f"build/identity-user-{kind}.zip"
        sources = COMMON_SOURCES + (("identity_user_server.py",) if kind == "runtime" else ("identity_user_web.py",))
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name in sources:
                archive.write(ROOT / name, name)
            if kind == "web":
                for file in sorted((ROOT / "identity_user_static").iterdir()):
                    if file.suffix in (".html", ".js", ".css"):
                        archive.write(file, "identity_user_static/" + file.name)
            for file in sorted(dependencies.rglob("*")):
                if file.is_file() and "__pycache__" not in file.parts and file.suffix != ".pyc":
                    archive.write(file, file.relative_to(dependencies))
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if any(".state/" in name or name.endswith("accessKeys.csv") or name.endswith((".pem", ".cer")) for name in names):
                # The pinned SDK's public CA root bundles are required for TLS.
                unexpected = [name for name in names if
                              (".state/" in name or name.endswith("accessKeys.csv") or name.endswith((".pem", ".cer")))
                              and name not in ("certifi/cacert.pem", "botocore/cacert.pem")]
                if unexpected:
                    raise RuntimeError("Unexpected credential material in artifact")
        artifacts[kind] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                           "bytes": path.stat().st_size, "source_files": list(sources)}
    return artifacts


def allow(actions, resources):
    return {"Effect": "Allow", "Action": actions, "Resource": resources}


def checkpoint(state, **values):
    state.update(values)
    save(STATE, state)


def deploy(cfg, sess):
    state = read_state()
    if state and any(state[key] != cfg[key] for key in ("account_id", "region", "project_tag")):
        raise RuntimeError("Deployment account, region or ownership differs")
    checkpoint(state, **{key: cfg[key] for key in ("account_id", "region", "project_tag")})
    tags = {"Project": cfg["project_tag"], "Purpose": "identity-user-oauth"}
    provider = configure_provider(cfg, sess)
    artifacts = packages()
    region, account = cfg["region"], cfg["account_id"]
    base = f"arn:aws-cn:bedrock-agentcore:{region}:{account}"
    name = cfg["runtime_prefix"] + "_identity_user"
    function_name = cfg["gateway_prefix"] + "-identity-web"
    table_name = function_name + "-sessions"
    control, api, ddb, functions = [sess.client(service) for service in
                                  ("bedrock-agentcore-control", "apigateway", "dynamodb", "lambda")]
    s3 = sess.client("s3")
    s3.head_bucket(Bucket=cfg["bucket"], ExpectedBucketOwner=account)
    if {row["Key"]: row["Value"] for row in s3.get_bucket_tagging(Bucket=cfg["bucket"])["TagSet"]}.get("Project") != cfg["bucket_project_tag"]:
        raise RuntimeError("Bucket ownership tag differs")
    if not all(s3.get_public_access_block(Bucket=cfg["bucket"])["PublicAccessBlockConfiguration"].values()):
        raise RuntimeError("Bucket public access block required")
    for artifact in artifacts.values():
        artifact["key"] = f'mcp-auth/identity-user/{artifact["sha256"][:24]}.zip'
        s3.put_object(Bucket=cfg["bucket"], Key=artifact["key"], Body=Path(artifact["path"]).read_bytes(),
                      ContentType="application/zip", ExpectedBucketOwner=account, ServerSideEncryption="AES256")
    checkpoint(state, artifacts=artifacts, provider=provider)

    if "api_id" not in state:
        existing = [item for page in api.get_paginator("get_rest_apis").paginate() for item in page["items"]]
        if any(item["name"] == function_name for item in existing):
            raise RuntimeError("Untracked API already exists")
        result = api.create_rest_api(name=function_name, endpointConfiguration={"types": ["REGIONAL"]},
                                     description="Entra China native Identity user OAuth sample", tags=tags)
        checkpoint(state, api_id=result["id"])
    if api.get_rest_api(restApiId=state["api_id"]).get("tags", {}).get("Project") != cfg["project_tag"]:
        raise RuntimeError("API ownership differs")
    portal = f'https://{state["api_id"]}.execute-api.{region}.amazonaws.com.cn/test'
    checkpoint(state, portal_base_url=portal, login_callback_url=portal + "/login/callback",
               application_return_url=portal + "/identity/callback")

    try:
        table = ddb.describe_table(TableName=table_name)["Table"]
        if "table_arn" not in state or state["table_arn"] != table["TableArn"]:
            raise RuntimeError("Untracked session table")
    except ddb.exceptions.ResourceNotFoundException:
        table = ddb.create_table(
            TableName=table_name, AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}], BillingMode="PAY_PER_REQUEST",
            SSESpecification={"Enabled": True},
            Tags=[{"Key": key, "Value": value} for key, value in tags.items()],
        )["TableDescription"]
        checkpoint(state, table_arn=table["TableArn"], table_name=table_name)
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25})
    ttl = ddb.describe_time_to_live(TableName=table_name)["TimeToLiveDescription"]
    if ttl["TimeToLiveStatus"] == "DISABLED":
        ddb.update_time_to_live(TableName=table_name, TimeToLiveSpecification={"Enabled": True, "AttributeName": "expires"})

    workload_name = cfg["gateway_prefix"] + "-identity-user-workload"
    if "workload_arn" not in state:
        try:
            control.get_workload_identity(name=workload_name)
        except control.exceptions.ResourceNotFoundException:
            workload = control.create_workload_identity(
                name=workload_name, allowedResourceOauth2ReturnUrls=[state["application_return_url"]], tags=tags,
            )
            checkpoint(state, workload_arn=workload["workloadIdentityArn"], workload_name=workload_name)
        else:
            raise RuntimeError("Untracked workload identity")
    workload = control.get_workload_identity(name=workload_name)
    if workload["workloadIdentityArn"] != state["workload_arn"] or workload.get("allowedResourceOauth2ReturnUrls") != [state["application_return_url"]]:
        raise RuntimeError("Workload identity or return URL differs")
    resources = [base + ":workload-identity-directory/default", state["workload_arn"],
                 base + ":token-vault/default", provider["arn"]]
    log = f"arn:aws-cn:logs:{region}:{account}:log-group:/aws/bedrock-agentcore/runtimes/{name}-*"
    runtime_policy = {"Version": "2012-10-17", "Statement": [
        allow(["s3:GetObject", "s3:GetObjectVersion"], f'arn:aws-cn:s3:::{cfg["bucket"]}/mcp-auth/identity-user/*'),
        allow(["logs:CreateLogGroup", "logs:DescribeLogStreams", "logs:CreateLogStream", "logs:PutLogEvents"], [log, log + ":*"]),
        allow(["logs:DescribeLogGroups"], f"arn:aws-cn:logs:{region}:{account}:log-group:*"),
        allow(["bedrock-agentcore:GetWorkloadAccessTokenForJWT"], resources[:2]),
        allow(["bedrock-agentcore:GetResourceOauth2Token"], resources),
        {"Effect": "Deny", "Action": ["bedrock-agentcore:GetWorkloadAccessTokenForUserId"], "Resource": "*"},
    ]}
    runtime_role = lab.ensure_role(sess, cfg, name + "_role",
                                   lab.service_trust(cfg, base + f":runtime/{name}-*"), runtime_policy)
    runtime_cfg = {field: cfg[field] for field in (
        "account_id", "region", "tenant_id", "api_app_id", "client_app_id", "authority_host", "scope",
    )}
    runtime_cfg.update(workload_name=workload_name, provider_name=provider["name"],
                       application_return_url=state["application_return_url"])
    request = {
        "agentRuntimeArtifact": {"codeConfiguration": {
            "code": {"s3": {"bucket": cfg["bucket"], "prefix": artifacts["runtime"]["key"]}},
            "runtime": "PYTHON_3_12", "entryPoint": ["identity_user_server.py"],
        }},
        "roleArn": runtime_role, "networkConfiguration": {"networkMode": "PUBLIC"},
        "protocolConfiguration": {"serverProtocol": "MCP"},
        "lifecycleConfiguration": {"idleRuntimeSessionTimeout": 300, "maxLifetime": 1800},
        "authorizerConfiguration": lab.authorizer(cfg, "jwt"),
        "requestHeaderConfiguration": {"requestHeaderAllowlist": ["Authorization"]},
        "environmentVariables": {"IDENTITY_USER_CONFIG": json.dumps(runtime_cfg, separators=(",", ":")),
                                 "IDENTITY_USER_LOCATION": "agentcore_runtime"},
        "description": "Entra China native Identity USER_FEDERATION to China Graph via MCP",
    }
    if "runtime" not in state:
        existing = {row["agentRuntimeName"] for page in control.get_paginator("list_agent_runtimes").paginate()
                    for row in page["agentRuntimes"]}
        if name in existing:
            raise RuntimeError("Untracked Identity Runtime exists")
        result = lab.after_role_propagation(lambda: control.create_agent_runtime(
            agentRuntimeName=name, tags=tags, **request,
        ))
        checkpoint(state, runtime={"id": result["agentRuntimeId"], "arn": result["agentRuntimeArn"],
                                  "url": lab.runtime_url(cfg, result["agentRuntimeArn"])})
    else:
        current = control.get_agent_runtime(agentRuntimeId=state["runtime"]["id"])
        if current["agentRuntimeName"] != name or current["roleArn"] != runtime_role:
            raise RuntimeError("Tracked Runtime ownership differs")
        if any(current.get(key) != value for key, value in request.items()):
            control.update_agent_runtime(agentRuntimeId=state["runtime"]["id"], **request)
    checkpoint(state, runtime_role=runtime_role)

    function_arn = f"arn:aws-cn:lambda:{region}:{account}:function:{function_name}"
    lambda_log = f"arn:aws-cn:logs:{region}:{account}:log-group:/aws/lambda/{function_name}"
    web_policy = {"Version": "2012-10-17", "Statement": [
        allow(["logs:CreateLogStream", "logs:PutLogEvents"], lambda_log + ":*"),
        allow(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"], state["table_arn"]),
        allow(["secretsmanager:GetSecretValue"], provider["client_secret_arn"]),
        allow(["bedrock-agentcore:CompleteResourceTokenAuth"], resources),
        allow(["lambda:InvokeFunction"], function_arn),
    ]}
    web_trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole",
    }]}
    web_role = lab.ensure_role(sess, cfg, function_name + "-role", web_trust, web_policy)
    logs = sess.client("logs")
    try:
        logs.create_log_group(logGroupName="/aws/lambda/" + function_name, tags=tags)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    logs.put_retention_policy(logGroupName="/aws/lambda/" + function_name, retentionInDays=7)
    web_cfg = dict(runtime_cfg, runtime_url=state["runtime"]["url"])
    environment = {
        "IDENTITY_USER_CONFIG": json.dumps(web_cfg, separators=(",", ":")), "PORTAL_BASE_URL": portal,
        "SESSION_TABLE": table_name, "CLIENT_SECRET_ARN": provider["client_secret_arn"],
    }
    lambda_config = dict(Role=web_role, Handler="identity_user_web.handler", Runtime="python3.12",
                         Timeout=240, MemorySize=512, Environment={"Variables": environment})
    try:
        current = functions.get_function(FunctionName=function_name)
        if current.get("Tags", {}).get("Project") != cfg["project_tag"] or "function_arn" not in state:
            raise RuntimeError("Untracked Lambda function")
        functions.update_function_code(FunctionName=function_name, S3Bucket=cfg["bucket"],
                                       S3Key=artifacts["web"]["key"], Architectures=["arm64"])
        functions.get_waiter("function_updated_v2").wait(
            FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25})
        functions.update_function_configuration(FunctionName=function_name, **lambda_config)
    except functions.exceptions.ResourceNotFoundException:
        lab.after_role_propagation(lambda: functions.create_function(
            FunctionName=function_name, **lambda_config, Architectures=["arm64"],
            Code={"S3Bucket": cfg["bucket"], "S3Key": artifacts["web"]["key"]},
            Description="Cookie-bound Entra China login and native AgentCore Identity user OAuth", Tags=tags,
        ))
        checkpoint(state, function_arn=function_arn, function_name=function_name, web_role=web_role)
    functions.get_waiter("function_active_v2").wait(
        FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25})
    functions.put_function_event_invoke_config(FunctionName=function_name, MaximumRetryAttempts=0, MaximumEventAgeInSeconds=120)
    # Function invocations include both web requests and asynchronous MCP jobs.
    # API throttling bounds this small test's anonymous login traffic.
    resources_api = api.get_resources(restApiId=state["api_id"])["items"]
    root = next(row for row in resources_api if row["path"] == "/")
    proxy = next((row for row in resources_api if row["path"] == "/{proxy+}"), None)
    if proxy is None:
        proxy = api.create_resource(restApiId=state["api_id"], parentId=root["id"], pathPart="{proxy+}")
    uri = f"arn:aws-cn:apigateway:{region}:lambda:path/2015-03-31/functions/{function_arn}/invocations"
    for resource in (root, proxy):
        if "ANY" not in resource.get("resourceMethods", {}):
            api.put_method(restApiId=state["api_id"], resourceId=resource["id"], httpMethod="ANY",
                           authorizationType="NONE", apiKeyRequired=False)
        api.put_integration(restApiId=state["api_id"], resourceId=resource["id"], httpMethod="ANY",
                            type="AWS_PROXY", integrationHttpMethod="POST", uri=uri, timeoutInMillis=29000)
    try:
        functions.add_permission(
            FunctionName=function_name, StatementId="SampleApiGateway", Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com", SourceAccount=account,
            SourceArn=f'arn:aws-cn:execute-api:{region}:{account}:{state["api_id"]}/test/*/*',
        )
    except functions.exceptions.ResourceConflictException:
        permission = json.loads(functions.get_policy(FunctionName=function_name)["Policy"])
        if not any(row.get("Sid") == "SampleApiGateway" and row.get("Condition", {}).get("ArnLike", {}).get("AWS:SourceArn")
                   == f'arn:aws-cn:execute-api:{region}:{account}:{state["api_id"]}/test/*/*'
                   for row in permission["Statement"]):
            raise RuntimeError("Lambda API permission differs")
    api.create_deployment(restApiId=state["api_id"], stageName="test",
                          description="Native Identity sample: no OAuth query/body logging")
    api.update_stage(restApiId=state["api_id"], stageName="test", patchOperations=[
        {"op": "replace", "path": "/*/*/logging/loglevel", "value": "OFF"},
        {"op": "replace", "path": "/*/*/logging/dataTrace", "value": "false"},
        {"op": "replace", "path": "/*/*/throttling/rateLimit", "value": "5"},
        {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "10"},
        {"op": "replace", "path": "/*/*/caching/enabled", "value": "false"},
    ])
    checkpoint(state, deployed_at_utc=datetime.now(timezone.utc).isoformat())
    return status(cfg, sess)


def status(cfg, sess):
    state = read_state()
    current_path = ROOT / "results/identity-user-current-status.json"
    current = json.loads(current_path.read_text()) if current_path.exists() else {}
    completed = current.get("native_identity_user_oauth_completed") is True and current.get("status") == "passed"
    provider = json.loads(PROVIDER_STATE.read_text())
    runtime = sess.client("bedrock-agentcore-control").get_agent_runtime(agentRuntimeId=state["runtime"]["id"])
    function = sess.client("lambda").get_function_configuration(FunctionName=state["function_name"])
    report = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "region": cfg["region"],
        "runtime_status": runtime["status"], "lambda_status": function["State"],
        "runtime_id": state["runtime"]["id"], "portal_url": state["portal_base_url"] + "/",
        "entra_web_redirects": [state["login_callback_url"], state["provider"]["callback_url"]],
        "entra_web_redirects_registered": provider.get("callback_registered_in_entra", False),
        "workload_application_return_url": state["application_return_url"],
        "provider_created": True, "public_https_application_implemented": True,
        "native_identity_user_oauth_tested": completed,
        "status": "real_user_federation_and_graph_completed" if completed
            else "deployed_awaiting_entra_redirect_registration_and_real_login",
        "user_flow_evidence_file": current.get("evidence_file") if completed else None,
        "deployment_ready": runtime["status"] == "READY" and function["State"] == "Active",
        "artifact_sha256": {kind: artifact["sha256"] for kind, artifact in state["artifacts"].items()},
        "tokens_recorded": False,
    }
    save(ROOT / "results/identity-user-deployment.json", report, private=False)
    return report


def update_web(cfg, sess):
    """Refresh only the owned web Lambda; preserve Runtime and active DDB sessions."""
    state = read_state()
    if any(state[key] != cfg[key] for key in ("account_id", "region", "project_tag")):
        raise RuntimeError("Deployment ownership differs")
    functions, s3 = sess.client("lambda"), sess.client("s3")
    live = functions.get_function(FunctionName=state["function_name"])
    if (live["Configuration"]["FunctionArn"] != state["function_arn"]
            or live.get("Tags", {}).get("Project") != cfg["project_tag"]):
        raise RuntimeError("Web function ownership differs")
    s3.head_bucket(Bucket=cfg["bucket"], ExpectedBucketOwner=cfg["account_id"])
    if {row["Key"]: row["Value"] for row in s3.get_bucket_tagging(Bucket=cfg["bucket"])["TagSet"]}.get("Project") != cfg["bucket_project_tag"]:
        raise RuntimeError("Bucket ownership differs")
    artifact = packages(("web",))["web"]
    artifact["key"] = f'mcp-auth/identity-user/{artifact["sha256"][:24]}.zip'
    s3.put_object(Bucket=cfg["bucket"], Key=artifact["key"], Body=Path(artifact["path"]).read_bytes(),
                  ContentType="application/zip", ExpectedBucketOwner=cfg["account_id"], ServerSideEncryption="AES256")
    functions.update_function_code(FunctionName=state["function_name"], S3Bucket=cfg["bucket"],
                                   S3Key=artifact["key"], RevisionId=live["Configuration"]["RevisionId"])
    functions.get_waiter("function_updated_v2").wait(
        FunctionName=state["function_name"], WaiterConfig={"Delay": 2, "MaxAttempts": 25})
    state["artifacts"]["web"] = artifact
    checkpoint(state, web_updated_at_utc=datetime.now(timezone.utc).isoformat())
    return status(cfg, sess)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("package", "deploy", "status", "update-web"))
    parser.add_argument("--config")
    parser.add_argument("--credentials-csv")
    args = parser.parse_args()
    if args.action == "package":
        value = packages()
    else:
        cfg = config(args.config)
        value = {"deploy": deploy, "status": status, "update-web": update_web}[args.action](
            cfg, lab.session(cfg, args.credentials_csv))
    print(json.dumps(value, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        diagnostic = {"status": "failed", "error": type(error).__name__}
        if isinstance(error, ClientError):
            diagnostic.update(error=error.response["Error"]["Code"],
                              detail=error.response["Error"].get("Message", "")[:600],
                              request_id=error.response.get("ResponseMetadata", {}).get("RequestId"))
        elif isinstance(error, RuntimeError):
            diagnostic["detail"] = str(error)
        print(json.dumps(diagnostic, ensure_ascii=False))
        raise SystemExit(1)
