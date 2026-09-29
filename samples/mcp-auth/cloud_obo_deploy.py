"""Deploy a separate, certificate-authenticated OBO MCP middle tier in China."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import zipfile

from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import entra
import lab
from local_config import ROOT, config, save

STATE = ROOT / ".state/cloud-obo-deployment.json"
CERT_DIR = ROOT / ".state/cloud-obo-certificate"
ARCHIVE = ROOT / "build/cloud-obo-runtime.zip"
SOURCES = (
    "cloud_obo_server.py", "cloud_obo_core.py", "entra.py", "obo.py",
    "client.py", "local_config.py",
)


def read_state():
    return json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}


def prepare_certificate():
    CERT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = CERT_DIR / "client-private.pem"
    if not key_path.exists():
        if any(CERT_DIR.iterdir()):
            raise RuntimeError("Certificate directory is incomplete; review before creating a key")
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AgentCore China Runtime Cloud OBO Test")])
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
            ))
        (CERT_DIR / "client-public.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (CERT_DIR / "client-public.cer").write_bytes(cert.public_bytes(serialization.Encoding.DER))
        save(CERT_DIR / "metadata.json", {
            "purpose": "Separate certificate credential for the Runtime-hosted Entra OBO middle tier",
            "created_at_utc": now.isoformat(),
            "expires_at_utc": cert.not_valid_after_utc.isoformat(),
            "sha1_thumbprint": cert.fingerprint(hashes.SHA1()).hex(),
            "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            "entra_public_certificate_registered": False,
            "cloud_obo_executed": False,
        })
    entra.certificate_credential(key_path.read_bytes(), (CERT_DIR / "client-public.pem").read_bytes())
    metadata = json.loads((CERT_DIR / "metadata.json").read_text(encoding="utf-8"))
    cert = x509.load_pem_x509_certificate((CERT_DIR / "client-public.pem").read_bytes())
    if metadata["sha256_fingerprint"] != cert.fingerprint(hashes.SHA256()).hex():
        raise RuntimeError("Certificate metadata mismatch")
    if (CERT_DIR / "client-public.cer").read_bytes() != cert.public_bytes(serialization.Encoding.DER):
        raise RuntimeError("DER and PEM public certificates differ")
    public = ROOT / "dist/cloud-obo-runtime-public.cer"
    public.parent.mkdir(exist_ok=True)
    public.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return metadata


def package():
    directory = ROOT / "build/cloud-obo-package"
    for required in ("mcp", "boto3", "msal", "requests", "cryptography"):
        if not (directory / required).is_dir():
            raise RuntimeError("Build cloud OBO Linux ARM64 dependencies before packaging")
    with zipfile.ZipFile(ARCHIVE, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name in SOURCES:
            bundle.write(ROOT / name, name)
        for path in sorted(directory.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                bundle.write(path, path.relative_to(directory))
    return {
        "archive_bytes": ARCHIVE.stat().st_size,
        "sha256": hashlib.sha256(ARCHIVE.read_bytes()).hexdigest(),
    }


def runtime_configuration(cfg):
    return {field: cfg[field] for field in (
        "account_id", "region", "tenant_id", "api_app_id", "client_app_id", "authority_host", "scope",
    )}


def ensure_secret(cfg, sess, metadata):
    client = sess.client("secretsmanager")
    name = cfg["runtime_prefix"] + "/cloud-obo-client-certificate"
    expected_tags = {
        "Project": cfg["project_tag"], "Purpose": "cloud-obo-middle-tier",
        "CertificateSHA256": metadata["sha256_fingerprint"],
    }
    try:
        result = client.describe_secret(SecretId=name)
        tags = {row["Key"]: row["Value"] for row in result.get("Tags", [])}
        if any(tags.get(key) != value for key, value in expected_tags.items()) or result.get("DeletedDate"):
            raise RuntimeError("Existing secret ownership or certificate differs; no credential overwritten")
        return result["ARN"]
    except client.exceptions.ResourceNotFoundException:
        result = client.create_secret(
            Name=name,
            Description="30-day sample certificate for the Entra China Runtime OBO middle tier",
            SecretString=json.dumps({
                "client_id": cfg["api_app_id"], "tenant_id": cfg["tenant_id"],
                "private_key_pem": (CERT_DIR / "client-private.pem").read_text(encoding="ascii"),
                "certificate_pem": (CERT_DIR / "client-public.pem").read_text(encoding="ascii"),
            }),
            Tags=[{"Key": key, "Value": value} for key, value in expected_tags.items()],
        )
        return result["ARN"]


def deploy(cfg, sess):
    state = read_state()
    identity = (cfg["account_id"], cfg["region"], cfg["project_tag"])
    if state and tuple(state[key] for key in ("account_id", "region", "project_tag")) != identity:
        raise RuntimeError("Cloud OBO state belongs to another deployment")
    metadata = prepare_certificate()
    artifact = package()
    control, s3 = sess.client("bedrock-agentcore-control"), sess.client("s3")
    name = cfg["runtime_prefix"] + "_cloud_obo"
    # Do not create credentials if an unrelated Runtime already has this name.
    known = {item["agentRuntimeName"] for page in control.get_paginator("list_agent_runtimes").paginate()
             for item in page["agentRuntimes"]}
    if name in known and "runtime" not in state:
        raise RuntimeError("An untracked cloud OBO Runtime already exists")
    s3.head_bucket(Bucket=cfg["bucket"], ExpectedBucketOwner=cfg["account_id"])
    tags = {row["Key"]: row["Value"] for row in s3.get_bucket_tagging(Bucket=cfg["bucket"])["TagSet"]}
    if tags.get("Project") != cfg["bucket_project_tag"]:
        raise RuntimeError("Deployment bucket tag mismatch")
    if not all(s3.get_public_access_block(Bucket=cfg["bucket"])["PublicAccessBlockConfiguration"].values()):
        raise RuntimeError("Deployment bucket must block public access")
    state.update(account_id=identity[0], region=identity[1], project_tag=identity[2], runtime_name=name)
    secret_arn = ensure_secret(cfg, sess, metadata)
    state.update(secret_arn=secret_arn, certificate=metadata)
    save(STATE, state)
    object_key = "mcp-auth/cloud-obo/" + artifact["sha256"][:24] + ".zip"
    s3.put_object(
        Bucket=cfg["bucket"], Key=object_key, Body=ARCHIVE.read_bytes(),
        ContentType="application/zip", ExpectedBucketOwner=cfg["account_id"], ServerSideEncryption="AES256",
    )
    base = f'arn:aws-cn:bedrock-agentcore:{cfg["region"]}:{cfg["account_id"]}'
    log = f'arn:aws-cn:logs:{cfg["region"]}:{cfg["account_id"]}:log-group:/aws/bedrock-agentcore/runtimes/{name}-*'
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
         "Resource": f'arn:aws-cn:s3:::{cfg["bucket"]}/mcp-auth/cloud-obo/*'},
        {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": secret_arn},
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:DescribeLogStreams",
                                      "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": [log, log + ":*"]},
        {"Effect": "Allow", "Action": ["logs:DescribeLogGroups"],
         "Resource": f'arn:aws-cn:logs:{cfg["region"]}:{cfg["account_id"]}:log-group:*'},
    ]}
    role = lab.ensure_role(sess, cfg, name + "_role", lab.service_trust(cfg, base + f":runtime/{name}-*"), policy)
    state.update(role_arn=role, bucket=cfg["bucket"], object_key=object_key, artifact=artifact)
    save(STATE, state)
    request = {
        "agentRuntimeArtifact": {"codeConfiguration": {
            "code": {"s3": {"bucket": cfg["bucket"], "prefix": object_key}},
            "runtime": "PYTHON_3_12", "entryPoint": ["cloud_obo_server.py"],
        }},
        "roleArn": role, "networkConfiguration": {"networkMode": "PUBLIC"},
        "protocolConfiguration": {"serverProtocol": "MCP"},
        "lifecycleConfiguration": {"idleRuntimeSessionTimeout": 300, "maxLifetime": 1800},
        "authorizerConfiguration": lab.authorizer(cfg, "jwt"),
        "requestHeaderConfiguration": {"requestHeaderAllowlist": ["Authorization"]},
        "environmentVariables": {
            "CLOUD_OBO_CONFIG": json.dumps(runtime_configuration(cfg), separators=(",", ":")),
            "CLOUD_OBO_SECRET_ARN": secret_arn,
            "CLOUD_OBO_EXECUTION_LOCATION": "agentcore_runtime",
        },
        "description": "Entra China employee MCP: Runtime certificate OBO to China Graph /me",
    }
    if "runtime" in state:
        current = control.get_agent_runtime(agentRuntimeId=state["runtime"]["id"])
        if current["roleArn"] != role or current["agentRuntimeName"] != name:
            raise RuntimeError("Tracked Runtime identity mismatch")
        if any(current.get(key) != value for key, value in request.items()):
            raise RuntimeError("Tracked Runtime configuration differs; no automatic update performed")
    else:
        result = lab.after_role_propagation(lambda: control.create_agent_runtime(
            agentRuntimeName=name, tags={"Project": cfg["project_tag"], "Purpose": "cloud-obo-middle-tier"},
            **request,
        ))
        state["runtime"] = {
            "id": result["agentRuntimeId"], "arn": result["agentRuntimeArn"],
            "version": result["agentRuntimeVersion"], "url": lab.runtime_url(cfg, result["agentRuntimeArn"]),
        }
        save(STATE, state)
    return status(cfg, sess)


def status(cfg, sess):
    state = read_state()
    if (state["account_id"], state["region"]) != (cfg["account_id"], cfg["region"]):
        raise RuntimeError("State account or region differs")
    result = sess.client("bedrock-agentcore-control").get_agent_runtime(agentRuntimeId=state["runtime"]["id"])
    authorizer_matches = result.get("authorizerConfiguration") == lab.authorizer(cfg, "jwt")
    header_forwarding = result.get("requestHeaderConfiguration", {}).get("requestHeaderAllowlist") == ["Authorization"]
    env = result.get("environmentVariables", {})
    config_matches = json.loads(env.get("CLOUD_OBO_CONFIG", "{}")) == runtime_configuration(cfg)
    secret_matches = env.get("CLOUD_OBO_SECRET_ARN") == state["secret_arn"]
    report = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "region": cfg["region"], "runtime_id": state["runtime"]["id"],
        "runtime_status": result["status"], "failure_reason": result.get("failureReason"),
        "jwt_authorizer_matches": authorizer_matches,
        "authorization_header_forwarding_configured": header_forwarding,
        "nonsecret_runtime_config_matches": config_matches,
        "runtime_secret_reference_matches": secret_matches,
        "credential_source": "AWS Secrets Manager",
        "certificate_sha1_thumbprint": state["certificate"]["sha1_thumbprint"],
        "certificate_expires_at_utc": state["certificate"]["expires_at_utc"],
        "entra_public_certificate_registration": "pending_user_confirmation",
        "employee_cloud_obo_test": "pending", "agentcore_identity_native_oauth_tested": False,
        "artifact_sha256": state["artifact"]["sha256"],
        "deployment_configuration_ready": result["status"] == "READY"
            and authorizer_matches and header_forwarding and config_matches and secret_matches,
    }
    save(ROOT / "results/cloud-obo-deployment.json", report, private=False)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare-certificate", "package", "deploy", "status"))
    parser.add_argument("--config")
    parser.add_argument("--credentials-csv")
    args = parser.parse_args()
    if args.action == "prepare-certificate":
        result = prepare_certificate()
    elif args.action == "package":
        result = package()
    else:
        cfg = config(args.config)
        sess = lab.session(cfg, args.credentials_csv)
        result = {"deploy": deploy, "status": status}[args.action](cfg, sess)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except ClientError as error:
        print(json.dumps({
            "error": error.response["Error"]["Code"],
            "detail": error.response["Error"].get("Message", "")[:1000],
            "request_id": error.response.get("ResponseMetadata", {}).get("RequestId"),
        }))
        raise SystemExit(1)
