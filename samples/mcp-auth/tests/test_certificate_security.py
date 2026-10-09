"""Exercise certificate assertions with real MSAL and an offline HTTP transport."""
import base64
import hashlib
import json
import logging
import socket
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import jwt
import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

import cloud_obo_core
import cloud_obo_deploy
import entra
import prepare_certificate


CFG = {
    "account_id": "123456789012",
    "region": "cn-north-1",
    "tenant_id": "00000000-0000-0000-0000-000000000001",
    "api_app_id": "00000000-0000-0000-0000-000000000002",
    "client_app_id": "00000000-0000-0000-0000-000000000002",
    "machine_client_app_id": "00000000-0000-0000-0000-000000000002",
    "authority_host": "https://login.partner.microsoftonline.cn",
    "scope": "agent.invoke",
}
AUTHORITY = f'{CFG["authority_host"]}/{CFG["tenant_id"]}'
TOKEN_ENDPOINT = AUTHORITY + "/oauth2/v2.0/token"
TEST_ACCESS_TOKEN = "offline-test-access-token"
TEST_USER_ASSERTION = "offline-test-user-assertion"


def make_certificate(*, validity="valid", matching=True, elliptic=False):
    key = (
        ec.generate_private_key(ec.SECP256R1()) if elliptic
        else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    signer = key if matching else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    before, after = now - timedelta(minutes=5), now + timedelta(days=1)
    if validity == "expired":
        before, after = now - timedelta(days=2), now - timedelta(days=1)
    elif validity == "future":
        before, after = now + timedelta(days=1), now + timedelta(days=2)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline certificate test")])
    certificate = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(signer.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(before).not_valid_after(after)
        .sign(signer, hashes.SHA256())
    )
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    )
    return private_pem, certificate.public_bytes(serialization.Encoding.PEM), certificate


def assert_not_exposed(materials, text):
    """Keep generated credentials out of failure messages as well as normal output."""
    for material in materials:
        if material and material in text:
            pytest.fail("Credential material escaped its intended boundary", pytrace=False)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("Unexpected network access in an offline certificate test", pytrace=False)

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(requests.Session, "request", blocked)


@pytest.fixture
def offline_http(monkeypatch):
    calls = {"get": [], "post": []}

    def response(url, body):
        result = requests.Response()
        result.status_code = 200
        result.url = url
        result.headers["Content-Type"] = "application/json"
        result._content = json.dumps(body).encode("utf-8")
        return result

    def get(session, url, **kwargs):
        if url != AUTHORITY + "/v2.0/.well-known/openid-configuration":
            pytest.fail("Unexpected discovery endpoint", pytrace=False)
        calls["get"].append((url, kwargs))
        return response(url, {
            "authorization_endpoint": AUTHORITY + "/oauth2/v2.0/authorize",
            "token_endpoint": TOKEN_ENDPOINT,
            "issuer": AUTHORITY + "/v2.0",
            "jwks_uri": AUTHORITY + "/discovery/v2.0/keys",
        })

    def post(session, url, **kwargs):
        if url != TOKEN_ENDPOINT:
            pytest.fail("Unexpected token endpoint", pytrace=False)
        calls["post"].append((url, kwargs))
        return response(url, {
            "access_token": TEST_ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3600,
        })

    monkeypatch.setattr(requests.Session, "get", get)
    monkeypatch.setattr(requests.Session, "post", post)
    return calls


@pytest.mark.parametrize("flow", ["client_credentials", "obo"])
def test_real_msal_uses_signed_sha256_assertion_without_leaking_credentials(
    flow, tmp_path, monkeypatch, offline_http, caplog, capsys,
):
    private_pem, certificate_pem, certificate = make_certificate()
    credential = entra.certificate_credential(private_pem, certificate_pem)
    assert set(credential) == {"private_key", "public_certificate"}
    caplog.set_level(logging.DEBUG, logger="msal")

    if flow == "client_credentials":
        key_path, cert_path = tmp_path / "private.pem", tmp_path / "public.pem"
        key_path.write_bytes(private_pem)
        cert_path.write_bytes(certificate_pem)
        monkeypatch.setenv("ENTRA_PRIVATE_KEY_FILE", str(key_path))
        monkeypatch.setenv("ENTRA_CERTIFICATE_FILE", str(cert_path))
        client = entra.confidential_client(CFG, "certificate")
        result = client.acquire_token_for_client(scopes=[CFG["api_app_id"] + "/.default"])
    else:
        monkeypatch.setattr(cloud_obo_core, "load_secret", lambda cfg: {
            "private_key_pem": private_pem.decode("ascii"),
            "certificate_pem": certificate_pem.decode("ascii"),
        })
        client = cloud_obo_core.CertificateMiddleTier(CFG)
        result = client.acquire_token_on_behalf_of(
            user_assertion=TEST_USER_ASSERTION,
            scopes=["https://microsoftgraph.chinacloudapi.cn/User.Read"],
        )

    assert result["access_token"] == TEST_ACCESS_TOKEN
    assert len(offline_http["get"]) == len(offline_http["post"]) == 1
    _, request = offline_http["post"][0]
    body = request["data"]
    assertion = body["client_assertion"]
    if isinstance(assertion, bytes):
        assertion = assertion.decode("ascii")
    header = jwt.get_unverified_header(assertion)
    assert header["alg"] == "PS256"
    fingerprint = header["x5t#S256"]
    assert base64.urlsafe_b64decode(
        fingerprint + "=" * (-len(fingerprint) % 4),
    ) == certificate.fingerprint(hashes.SHA256())
    assert "x5t" not in header
    assert base64.b64decode(header["x5c"][0]) == certificate.public_bytes(serialization.Encoding.DER)
    claims = jwt.decode(
        assertion, certificate.public_key(), algorithms=["PS256"],
        audience=TOKEN_ENDPOINT, issuer=CFG["api_app_id"],
        options={"require": ["aud", "iss", "sub", "iat", "exp", "jti"]},
    )
    assert claims["sub"] == CFG["api_app_id"]
    assert 0 < claims["exp"] - claims["iat"] <= 600
    parts = assertion.split(".")
    signature = bytearray(base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4)))
    signature[0] ^= 1
    parts[2] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(".".join(parts), certificate.public_key(), algorithms=["PS256"], audience=TOKEN_ENDPOINT)

    assert body["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    assert not {"client_secret", "private_key", "public_certificate", "thumbprint"} & body.keys()
    if flow == "obo":
        assert body["requested_token_use"] == "on_behalf_of"
        assert body["assertion"] == TEST_USER_ASSERTION
    else:
        assert body["grant_type"] == "client_credentials"
    private_material = [private_pem.decode("ascii"), private_pem.decode("ascii").splitlines()[1]]
    assert_not_exposed(private_material, json.dumps(offline_http, default=str))
    outside_body = json.dumps({
        "get": offline_http["get"],
        "post_headers": request.get("headers", {}),
        "post_params": request.get("params", {}),
    }, default=str)
    assert_not_exposed([assertion, TEST_ACCESS_TOKEN, TEST_USER_ASSERTION], outside_body)
    captured = capsys.readouterr()
    assert_not_exposed(
        private_material + [assertion, TEST_ACCESS_TOKEN, TEST_USER_ASSERTION],
        captured.out + captured.err + caplog.text,
    )


@pytest.mark.parametrize("kwargs,message", [
    ({"matching": False}, "do not match"),
    ({"validity": "expired"}, "validity period"),
    ({"validity": "future"}, "validity period"),
    ({"elliptic": True}, "RSA client certificate"),
])
def test_invalid_certificate_is_rejected_before_http(kwargs, message, tmp_path, monkeypatch, offline_http):
    private_pem, certificate_pem, _ = make_certificate(**kwargs)
    key_path, cert_path = tmp_path / "private.pem", tmp_path / "public.pem"
    key_path.write_bytes(private_pem)
    cert_path.write_bytes(certificate_pem)
    monkeypatch.setenv("ENTRA_PRIVATE_KEY_FILE", str(key_path))
    monkeypatch.setenv("ENTRA_CERTIFICATE_FILE", str(cert_path))
    with pytest.raises(RuntimeError, match=message):
        entra.confidential_client(CFG, "certificate")
    assert offline_http == {"get": [], "post": []}


def forbid_sha1(*args, **kwargs):
    pytest.fail("Sample certificate handling attempted SHA-1", pytrace=False)


@pytest.mark.parametrize("kind", ["application", "cloud_obo"])
def test_generated_certificate_metadata_uses_only_sha256(kind, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(hashes, "SHA1", forbid_sha1)
    if kind == "application":
        monkeypatch.setattr(prepare_certificate, "ROOT", tmp_path)
        prepare_certificate.main()
        directory = tmp_path / ".state/client-certificate"
    else:
        directory = tmp_path / ".state/cloud-obo-certificate"
        monkeypatch.setattr(cloud_obo_deploy, "ROOT", tmp_path)
        monkeypatch.setattr(cloud_obo_deploy, "CERT_DIR", directory)
        cloud_obo_deploy.prepare_certificate()
    metadata = json.loads((directory / "metadata.json").read_text())
    certificate = x509.load_pem_x509_certificate((directory / "client-public.pem").read_bytes())
    assert "sha1_thumbprint" not in metadata
    assert metadata["sha256_fingerprint"] == certificate.fingerprint(hashes.SHA256()).hex()
    assert certificate.signature_hash_algorithm.name == "sha256"
    key_path = directory / "client-private.pem"
    assert key_path.stat().st_mode & 0o777 == 0o600
    private_pem = key_path.read_text()
    captured = capsys.readouterr()
    assert_not_exposed(
        [private_pem, private_pem.splitlines()[1]],
        json.dumps(metadata) + captured.out + captured.err,
    )


def test_cloud_certificate_reuses_legacy_metadata_without_sha1_or_key_rotation(tmp_path, monkeypatch):
    directory = tmp_path / "certificate"
    monkeypatch.setattr(cloud_obo_deploy, "ROOT", tmp_path)
    monkeypatch.setattr(cloud_obo_deploy, "CERT_DIR", directory)
    metadata = cloud_obo_deploy.prepare_certificate()
    metadata["sha1_thumbprint"] = "unused-legacy-fingerprint"
    metadata_path = directory / "metadata.json"
    metadata_path.write_text(json.dumps(metadata))
    before = {path.name: hashlib.sha256(path.read_bytes()).digest() for path in directory.iterdir()}
    monkeypatch.setattr(hashes, "SHA1", forbid_sha1)
    generate = Mock(side_effect=AssertionError("Existing certificate must not be rotated"))
    monkeypatch.setattr(rsa, "generate_private_key", generate)
    result = cloud_obo_deploy.prepare_certificate()
    assert "sha1_thumbprint" not in result
    assert result["sha256_fingerprint"] == metadata["sha256_fingerprint"]
    assert before == {path.name: hashlib.sha256(path.read_bytes()).digest() for path in directory.iterdir()}
    generate.assert_not_called()


@pytest.mark.parametrize("legacy", [False, True])
def test_cloud_status_reports_sha256_for_new_and_legacy_state(legacy, tmp_path, monkeypatch, capsys):
    metadata = {"sha256_fingerprint": "ab" * 32, "expires_at_utc": "2030-01-01T00:00:00+00:00"}
    if legacy:
        metadata["sha1_thumbprint"] = "unused-legacy-fingerprint"
    secret_arn = "arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:offline-test"
    state = {
        "account_id": CFG["account_id"], "region": CFG["region"],
        "runtime": {"id": "offline-runtime"}, "certificate": metadata,
        "artifact": {"sha256": "cd" * 32}, "secret_arn": secret_arn,
    }
    monkeypatch.setattr(cloud_obo_deploy, "ROOT", tmp_path)
    monkeypatch.setattr(cloud_obo_deploy, "read_state", lambda: state)
    monkeypatch.setattr(hashes, "SHA1", forbid_sha1)
    session = Mock()
    session.client.return_value.get_agent_runtime.return_value = {
        "status": "READY", "authorizerConfiguration": cloud_obo_deploy.lab.authorizer(CFG, "jwt"),
        "requestHeaderConfiguration": {"requestHeaderAllowlist": ["Authorization"]},
        "environmentVariables": {
            "CLOUD_OBO_CONFIG": json.dumps(cloud_obo_deploy.runtime_configuration(CFG)),
            "CLOUD_OBO_SECRET_ARN": secret_arn,
        },
    }
    report = cloud_obo_deploy.status(CFG, session)
    session.client.assert_called_once_with("bedrock-agentcore-control")
    assert report["deployment_configuration_ready"] is True
    assert report["certificate_sha256_fingerprint"] == metadata["sha256_fingerprint"]
    assert "certificate_sha1_thumbprint" not in report
    assert json.loads((tmp_path / "results/cloud-obo-deployment.json").read_text()) == report
    captured = capsys.readouterr()
    assert_not_exposed(
        [secret_arn, "unused-legacy-fingerprint"], json.dumps(report) + captured.out + captured.err,
    )
