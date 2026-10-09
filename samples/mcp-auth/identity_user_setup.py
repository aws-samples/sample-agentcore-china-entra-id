# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Prepare the existing Entra app for native Identity user OAuth.

Secret entry happens interactively on the deployment computer. This module
does not implement the user-facing HTTPS application or execute a 3LO test.
"""
import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlparse

import local_config as local

SECRET_FILE = local.ROOT / ".state/identity-user-client-secret.txt"
PROVIDER_STATE = local.ROOT / ".state/identity-user-provider.json"
GRAPH_SCOPE = "https://microsoftgraph.chinacloudapi.cn/User.Read"


def stage_secret():
    if SECRET_FILE.exists():
        raise RuntimeError("Existing secret file preserved; do not overwrite credentials implicitly")
    if not sys.stdin.isatty():
        raise RuntimeError("Run stage-secret in an interactive terminal; redirected secret input is disabled")
    first = getpass.getpass("粘贴新建的 Entra client secret Value（不回显）: ").strip()
    second = getpass.getpass("再次粘贴以确认（不回显）: ").strip()
    if first != second:
        raise RuntimeError("Secret confirmation does not match")
    if not 16 <= len(first) <= 2048 or any(character.isspace() for character in first):
        raise RuntimeError("Unexpected client secret format")
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(first + "\n")
    return {"secret_staged": True, "file": str(SECRET_FILE), "secret_value_recorded_in_output": False}


def provider_name(cfg):
    return cfg["gateway_prefix"] + "-entra-user-oauth"


def plan(cfg):
    evidence = local.ROOT / "results/cloud-obo.json"
    previous = json.loads(evidence.read_text(encoding="utf-8-sig")) if evidence.exists() else {}
    provider = json.loads(PROVIDER_STATE.read_text()) if PROVIDER_STATE.exists() else {}
    deployment_path = local.ROOT / "results/identity-user-deployment.json"
    deployed = json.loads(deployment_path.read_text()) if deployment_path.exists() else {}
    value = {
        "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": deployed.get("status", "provider_created" if provider else "prepared_not_deployed"),
        "scenario": "Employee web login -> Runtime -> Identity USER_FEDERATION -> Entra China -> Graph /me",
        "account_id": cfg["account_id"], "region": cfg["region"], "tenant_id": cfg["tenant_id"],
        "entra_application": cfg.get("application_display_name", "configured-entra-application"), "client_id": cfg["api_app_id"],
        "provider_name": provider_name(cfg), "provider_vendor": "CustomOauth2",
        "discovery_url": f'{cfg["authority_host"]}/{cfg["tenant_id"]}/v2.0/.well-known/openid-configuration',
        "downstream_scope": GRAPH_SCOPE, "client_authentication_for_this_path": "client_secret",
        "existing_cloud_obo_passed": previous.get("status") == "passed",
        "identity_user_secret_staged": SECRET_FILE.exists(),
        "identity_user_provider_state_present": PROVIDER_STATE.exists(),
        "provider_callback_url": provider.get("callback_url"),
        "web_app_login_callback_url": next(iter(deployed.get("entra_web_redirects",
            deployed.get("entra_web_redirects_to_register", []))), None),
        "application_return_url": deployed.get("workload_application_return_url"),
        "portal_url": deployed.get("portal_url"),
        "deployment_ready": deployed.get("deployment_ready", False),
        "callback_urls_assigned_after_deployment": bool(deployed),
        "public_https_application_implemented": deployed.get("public_https_application_implemented", False),
        "native_identity_user_oauth_tested": deployed.get("native_identity_user_oauth_tested", False),
        "offline_access_requested": False,
        "next_actions": [
            "User creates a short-lived client secret on the existing app and stages its Value locally.",
            "Create the China CustomOauth2 provider and capture its actual callbackUrl.",
            "Deploy the included HTTPS application and Identity Runtime tool.",
            "Register the actual provider callback and sample app login callback as Web redirects in Entra.",
            "Register the app return URL on the workload identity; verify browser session and customState before CompleteResourceTokenAuth.",
            "Run employee login, native Identity user authorization and Graph /me; record HTTP status and same-user result.",
        ],
    }
    if deployed:
        value["next_actions"] = [
            "Register the two actual Entra Web redirects listed in identity-user-deployment.json.",
            "In the employee browser, complete enterprise login and native Identity authorization in the HTTPS portal.",
            "Run the MCP Graph tool and download identity-user-oauth.json; require Graph HTTP 200 and the same-user result.",
        ]
    if value["native_identity_user_oauth_tested"]:
        value["next_actions"] = [
            "Retain the local identity-user-oauth.json result.",
            "Validate machine client credentials and native Identity M2M with the required application permission.",
            "Validate Gateway native OAuth target credentials and separately test user isolation and revocation.",
        ]
    local.save(local.ROOT / "results/identity-user-next-plan.json", value, private=False)
    return value


def configure_provider(cfg, sess):
    if cfg["authority_host"] != "https://login.partner.microsoftonline.cn":
        raise RuntimeError("Expected the configured Entra China authority")
    control = sess.client("bedrock-agentcore-control")
    name = provider_name(cfg)
    discovery = f'{cfg["authority_host"]}/{cfg["tenant_id"]}/v2.0/.well-known/openid-configuration'
    if PROVIDER_STATE.exists():
        state = json.loads(PROVIDER_STATE.read_text(encoding="utf-8-sig"))
        if any(state.get(k) != value for k, value in {
            "name": name, "client_id": cfg["api_app_id"], "tenant_id": cfg["tenant_id"],
            "account_id": cfg["account_id"], "region": cfg["region"],
        }.items()):
            raise RuntimeError("Existing user OAuth provider state differs")
        current = control.get_oauth2_credential_provider(name=name)
        if current["credentialProviderArn"] != state["arn"]:
            raise RuntimeError("Tracked provider identity differs")
        output = current.get("oauth2ProviderConfigOutput", {}).get("customOauth2ProviderConfig", {})
        if output.get("clientId") != cfg["api_app_id"] or output.get("oauthDiscovery", {}).get("discoveryUrl") != discovery:
            raise RuntimeError("Provider configuration differs; credentials were not updated")
        return state
    try:
        control.get_oauth2_credential_provider(name=name)
    except control.exceptions.ResourceNotFoundException:
        pass
    else:
        raise RuntimeError("An untracked user OAuth provider already exists")
    if not SECRET_FILE.exists() or SECRET_FILE.is_symlink():
        raise RuntimeError("Stage the dedicated user OAuth secret in the regular local file first")
    if SECRET_FILE.stat().st_mode & 0o077:
        raise RuntimeError("The local client secret file must have owner-only permissions")
    secret = SECRET_FILE.read_text(encoding="utf-8-sig").strip()
    if not secret:
        raise RuntimeError("Client secret file is empty")
    result = control.create_oauth2_credential_provider(
        name=name, credentialProviderVendor="CustomOauth2",
        oauth2ProviderConfigInput={"customOauth2ProviderConfig": {
            "clientId": cfg["api_app_id"], "clientSecret": secret,
            "oauthDiscovery": {"discoveryUrl": discovery},
        }},
        tags={"Project": cfg["project_tag"], "Purpose": "entra-user-oauth"},
    )
    state = {
        "name": name, "arn": result["credentialProviderArn"],
        "client_id": cfg["api_app_id"], "tenant_id": cfg["tenant_id"],
        "account_id": cfg["account_id"], "region": cfg["region"],
        "callback_url": result.get("callbackUrl"),
        "client_secret_arn": result["clientSecretArn"]["secretArn"],
        "provider_created_at_utc": datetime.now(timezone.utc).isoformat(),
        "callback_registered_in_entra": False, "native_user_oauth_executed": False,
    }
    # Save returned identity before validating the URL, so a partial result can
    # be reviewed without creating duplicate resources.
    local.save(PROVIDER_STATE, state)
    callback = urlparse(state["callback_url"] or "")
    if callback.scheme != "https" or not (callback.hostname or "").endswith(".amazonaws.com.cn"):
        raise RuntimeError("Review the returned OAuth callback before registering it in Entra")
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "stage-secret", "configure-provider"))
    parser.add_argument("--config")
    parser.add_argument("--credentials-csv")
    args = parser.parse_args()
    if args.action == "stage-secret":
        result = stage_secret()
    else:
        cfg = local.config(args.config)
        if args.action == "plan":
            result = plan(cfg)
        else:
            import lab
            result = configure_provider(cfg, lab.session(cfg, args.credentials_csv))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Secret values and provider request parameters never enter diagnostics.
        diagnostic = {"status": "failed", "error_type": type(error).__name__}
        if isinstance(error, RuntimeError):
            diagnostic["detail"] = str(error)
        print(json.dumps(diagnostic, ensure_ascii=False))
        raise SystemExit(1)
