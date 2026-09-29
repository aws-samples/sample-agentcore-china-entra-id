"""Deploy a narrow OAuth parameter adapter without creating another Entra app."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import zipfile

from botocore.exceptions import ClientError

import lab

STATE = lab.ROOT / ".state/quick-oauth-compat-deployment.json"
REPORT = lab.ROOT / "results/quick-oauth-compat-deployment.json"


def adapter_config(cfg, deployment):
    if cfg["api_app_id"] != cfg["client_app_id"]:
        raise ValueError("This scenario intentionally uses the existing app for client and API")
    return {
        "tenant_id": cfg["tenant_id"], "client_id": cfg["client_app_id"],
        "api_app_id": cfg["api_app_id"], "scope": cfg["scope"],
        "authority_host": cfg["authority_host"],
        "resource_uri": deployment["gateways"]["jwt"]["url"],
        "redirect_uri": "https://us-east-1.quicksight.aws.amazon.com/sn/oauthcallback",
    }


def artifact():
    stream = io.BytesIO()
    source = lab.ROOT / "quick_oauth_compat.py"
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("quick_oauth_compat.py", source.read_bytes())
    return stream.getvalue(), hashlib.sha256(source.read_bytes()).hexdigest()


def deploy(cfg, deployment, sess):
    adapter = adapter_config(cfg, deployment)
    name = cfg["gateway_prefix"] + "-quick-oauth-compat"
    binding = {"account_id": cfg["account_id"], "region": cfg["region"],
               "project_tag": cfg["project_tag"], "name": name, "adapter_config": adapter}
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    if state and any(state.get(key) != value for key, value in binding.items()):
        raise RuntimeError("Tracked OAuth compatibility deployment belongs to another configuration")

    def checkpoint(**values):
        state.update(values)
        lab.save(STATE, state)

    checkpoint(**binding)
    control = sess.client("bedrock-agentcore-control")
    gateway = control.get_gateway(gatewayIdentifier=deployment["gateways"]["jwt"]["id"])
    if (
        gateway["gatewayUrl"] != adapter["resource_uri"]
        or gateway["authorizerType"] != "CUSTOM_JWT"
        or gateway["authorizerConfiguration"] != lab.authorizer(cfg)
    ):
        raise RuntimeError("Existing Gateway no longer matches the configured Entra app")
    api, functions, iam, logs = [sess.client(s) for s in ("apigateway", "lambda", "iam", "logs")]
    tags = {"Project": cfg["project_tag"], "Purpose": "quick-existing-app-oauth-compat"}
    region, account = cfg["region"], cfg["account_id"]
    if "api_id" not in state:
        for page in api.get_paginator("get_rest_apis").paginate():
            if any(item["name"] == name for item in page["items"]):
                raise RuntimeError("An untracked compatibility API already exists")
        created = api.create_rest_api(
            name=name, endpointConfiguration={"types": ["REGIONAL"]}, tags=tags,
            description="Existing-app Entra China OAuth parameter compatibility for Quick",
        )
        checkpoint(api_id=created["id"])
    actual_api = api.get_rest_api(restApiId=state["api_id"])
    if actual_api.get("tags") != tags or actual_api["name"] != name:
        raise RuntimeError("Tracked API ownership differs")
    endpoint = f'https://{state["api_id"]}.execute-api.{region}.amazonaws.com.cn/test'
    checkpoint(base_url=endpoint)
    log_group = "/aws/lambda/" + name
    log_arn = f"arn:aws-cn:logs:{region}:{account}:log-group:{log_group}"
    try:
        logs.create_log_group(logGroupName=log_group, tags=tags)
    except logs.exceptions.ResourceAlreadyExistsException:
        if logs.list_tags_log_group(logGroupName=log_group).get("tags") != tags:
            raise RuntimeError("Log group ownership differs") from None
    logs.put_retention_policy(logGroupName=log_group, retentionInDays=7)
    role_name = name + "-role"
    try:
        current_role = iam.get_role(RoleName=role_name)["Role"]
        if current_role["Arn"] != state.get("role_arn"):
            raise RuntimeError("An untracked adapter role already exists")
    except iam.exceptions.NoSuchEntityException:
        pass
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": log_arn + ":*",
    }]}
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }]}
    role = lab.ensure_role(sess, cfg, role_name, trust, policy)
    checkpoint(role_arn=role, log_group=log_group)
    payload, source_hash = artifact()
    function_arn = f"arn:aws-cn:lambda:{region}:{account}:function:{name}"
    settings = {
        "Role": role, "Handler": "quick_oauth_compat.handler", "Runtime": "python3.12",
        "Timeout": 20, "MemorySize": 128,
        "Environment": {"Variables": {"QUICK_OAUTH_COMPAT_CONFIG": json.dumps(adapter)}},
    }
    try:
        current = functions.get_function(FunctionName=name)
        if current.get("Tags") != tags or state.get("function_arn") != function_arn:
            raise RuntimeError("An untracked adapter Lambda already exists")
        functions.update_function_code(FunctionName=name, ZipFile=payload, Architectures=["arm64"])
        functions.get_waiter("function_updated_v2").wait(
            FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 25},
        )
        functions.update_function_configuration(FunctionName=name, **settings)
        functions.get_waiter("function_updated_v2").wait(
            FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 25},
        )
    except functions.exceptions.ResourceNotFoundException:
        lab.after_role_propagation(lambda: functions.create_function(
            FunctionName=name, **settings, Code={"ZipFile": payload},
            Architectures=["arm64"], Tags=tags,
            Description="Fixed resource-to-scope mapping; Entra issues all tokens; no secret storage",
        ))
        checkpoint(function_arn=function_arn)
    functions.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 25},
    )
    resources = api.get_resources(restApiId=state["api_id"])["items"]
    root = next(row for row in resources if row["path"] == "/")
    uri = f"arn:aws-cn:apigateway:{region}:lambda:path/2015-03-31/functions/{function_arn}/invocations"
    for path, method in (("authorize", "GET"), ("token", "POST"), ("health", "GET")):
        resource = next((row for row in resources if row["path"] == "/" + path), None)
        if resource is None:
            resource = api.create_resource(
                restApiId=state["api_id"], parentId=root["id"], pathPart=path,
            )
        if method not in resource.get("resourceMethods", {}):
            api.put_method(
                restApiId=state["api_id"], resourceId=resource["id"], httpMethod=method,
                authorizationType="NONE", apiKeyRequired=False,
            )
        api.put_integration(
            restApiId=state["api_id"], resourceId=resource["id"], httpMethod=method,
            type="AWS_PROXY", integrationHttpMethod="POST", uri=uri, timeoutInMillis=25000,
        )
        statement_id = "QuickCompat" + path.title()
        source_arn = f'arn:aws-cn:execute-api:{region}:{account}:{state["api_id"]}/test/{method}/{path}'
        try:
            functions.add_permission(
                FunctionName=name, StatementId=statement_id, Action="lambda:InvokeFunction",
                Principal="apigateway.amazonaws.com", SourceAccount=account, SourceArn=source_arn,
            )
        except functions.exceptions.ResourceConflictException:
            statements = json.loads(functions.get_policy(FunctionName=name)["Policy"])["Statement"]
            if not any(
                row.get("Sid") == statement_id
                and row.get("Condition", {}).get("ArnLike", {}).get("AWS:SourceArn") == source_arn
                and row.get("Condition", {}).get("StringEquals", {}).get("AWS:SourceAccount") == account
                for row in statements
            ):
                raise RuntimeError("Lambda API invocation permission differs") from None
    api.create_deployment(
        restApiId=state["api_id"], stageName="test",
        description="Quick OAuth compatibility: no OAuth query, request body or response body logging",
    )
    api.update_stage(restApiId=state["api_id"], stageName="test", patchOperations=[
        {"op": "replace", "path": "/*/*/logging/loglevel", "value": "OFF"},
        {"op": "replace", "path": "/*/*/logging/dataTrace", "value": "false"},
        {"op": "replace", "path": "/*/*/throttling/rateLimit", "value": "5"},
        {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "10"},
        {"op": "replace", "path": "/*/*/caching/enabled", "value": "false"},
    ])
    stage = api.get_stage(restApiId=state["api_id"], stageName="test")
    method = stage["methodSettings"]["*/*"]
    if method.get("dataTraceEnabled") or method.get("loggingLevel", "OFF") != "OFF":
        raise RuntimeError("OAuth request or response tracing is enabled")
    checkpoint(source_sha256=source_hash, deployed_at_utc=datetime.now(timezone.utc).isoformat())
    report = {
        **state, "authorization_url": endpoint + "/authorize", "token_url": endpoint + "/token",
        "health_url": endpoint + "/health",
        "component_type": "custom OAuth parameter compatibility adapter",
        "client_secret_stored_in_function": False,
        "token_response_passed_through": True,
        "api_execution_logging": "OFF", "api_data_trace_enabled": False,
        "existing_entra_app_modified": False, "existing_gateway_modified": False,
        "existing_runtime_modified": False, "new_entra_app_created": False,
        "quick_login_completed": False, "end_to_end_completed": False,
    }
    lab.save(REPORT, report, private=False)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials-csv")
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    cfg, deployment = lab.config(), lab.read_state()
    if args.plan:
        report = {
            "adapter_config": adapter_config(cfg, deployment),
            "new_resources": ["regional REST API", "Lambda function", "log group", "log-only IAM role"],
            "existing_resources_modified": False, "new_entra_app_created": False, "applied": False,
        }
    else:
        report = deploy(cfg, deployment, lab.session(cfg, args.credentials_csv))
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        print(json.dumps({"error": error.response["Error"]["Code"],
                          "request_id": error.response.get("ResponseMetadata", {}).get("RequestId")}))
        raise SystemExit(1) from None
    except (ValueError, RuntimeError) as error:
        print(json.dumps({"error": str(error)}))
        raise SystemExit(1) from None
