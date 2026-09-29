"""OBO middle tier hosted by Runtime; private material is read only in memory."""
import json
import os
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import msal

import entra
import obo

TOOL_NAME = "entra_check_my_graph_identity"


def runtime_config():
    cfg = json.loads(os.environ["CLOUD_OBO_CONFIG"])
    if cfg["region"] not in ("cn-north-1", "cn-northwest-1"):
        raise ValueError("China region required")
    if cfg["authority_host"] != "https://login.partner.microsoftonline.cn":
        raise ValueError("Entra China authority required")
    for field in ("tenant_id", "api_app_id", "client_app_id"):
        uuid.UUID(cfg[field])
    return cfg


def load_secret(cfg):
    arn = os.environ["CLOUD_OBO_SECRET_ARN"]
    prefix = f'arn:aws-cn:secretsmanager:{cfg["region"]}:{cfg["account_id"]}:secret:'
    if not arn.startswith(prefix):
        raise ValueError("Credential secret must be in the configured China account and region")
    client = boto3.client(
        "secretsmanager", region_name=cfg["region"],
        config=Config(connect_timeout=10, read_timeout=20, retries={"max_attempts": 2}),
    )
    value = json.loads(client.get_secret_value(SecretId=arn)["SecretString"])
    if value.get("client_id") != cfg["api_app_id"] or value.get("tenant_id") != cfg["tenant_id"]:
        raise ValueError("Credential is bound to a different middle tier")
    return value


class CertificateMiddleTier:
    """Resolve the app credential only after obo.py validates the user token."""
    def __init__(self, cfg):
        self.cfg = cfg

    def acquire_token_on_behalf_of(self, *, user_assertion, scopes):
        secret = load_secret(self.cfg)
        credential = entra.certificate_credential(
            secret["private_key_pem"].encode("ascii"),
            secret["certificate_pem"].encode("ascii"),
        )
        # Each invocation gets a separate MSAL cache; user tokens aren't shared.
        middle = msal.ConfidentialClientApplication(
            self.cfg["api_app_id"], client_credential=credential,
            authority=f'{self.cfg["authority_host"]}/{self.cfg["tenant_id"]}',
            instance_discovery=False,
        )
        return middle.acquire_token_on_behalf_of(user_assertion=user_assertion, scopes=scopes)


def run_identity_check(authorization):
    report = {
        "recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "flow": "AgentCore Runtime -> Entra China certificate OBO -> China Graph /me",
        "execution_location": os.environ.get("CLOUD_OBO_EXECUTION_LOCATION", "local_development"),
        "agentcore_runtime_used": os.environ.get("CLOUD_OBO_EXECUTION_LOCATION") == "agentcore_runtime",
        "agentcore_identity_used": False,
        "client_authentication": "certificate",
        "credential_source": "AWS Secrets Manager",
        "tokens_recorded": False,
        "profile_values_recorded": False,
    }
    stage = "request_authorization"
    try:
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise ValueError("Runtime Authorization header is required")
        cfg = runtime_config()
        report["region"] = cfg["region"]
        stage = "token_a_verification_or_credential_or_obo_or_graph"
        report.update(obo.exchange_and_call(cfg, parts[1], CertificateMiddleTier(cfg)))
    except ClientError as error:
        report.update(
            status="failed", stage="aws_credential_access",
            error=error.response["Error"]["Code"],
            aws_request_id=error.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    except Exception as error:
        report.update(status="failed", stage=stage, error=type(error).__name__)
    report["completed_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return report
