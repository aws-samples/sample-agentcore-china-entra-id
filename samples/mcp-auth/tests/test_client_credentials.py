# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Validate local credential selection before any identity-provider request."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import entra


class ClientCredentialTests(unittest.TestCase):
    def test_secret_file_accepts_utf8_bom_without_logging_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret.txt"
            path.write_text("local-test-secret\n", encoding="utf-8-sig")
            with patch.dict(os.environ, {"ENTRA_CLIENT_SECRET_FILE": str(path)}, clear=True):
                self.assertEqual(entra.read_client_secret(), "local-test-secret")

    def test_two_secret_sources_require_explicit_selection(self):
        with patch.dict(os.environ, {
            "ENTRA_CLIENT_SECRET": "test-one", "ENTRA_CLIENT_SECRET_FILE": "unused",
        }, clear=True):
            with self.assertRaises(RuntimeError):
                entra.read_client_secret()

    def certificate_case(self, directory, *, matching=True, expired=False):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert_key = key if matching else rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local unit test")])
        cert = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(cert_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now + timedelta(days=-1 if expired else 1))
            .sign(cert_key, hashes.SHA256())
        )
        key_path, cert_path = Path(directory) / "key.pem", Path(directory) / "cert.pem"
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return {"ENTRA_PRIVATE_KEY_FILE": str(key_path), "ENTRA_CERTIFICATE_FILE": str(cert_path)}

    def test_certificate_uses_api_client_for_obo(self):
        cfg = {"authority_host": "https://login.partner.microsoftonline.cn", "tenant_id": "test-tenant"}
        with tempfile.TemporaryDirectory() as directory:
            env = self.certificate_case(directory)
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(entra.msal, "ConfidentialClientApplication") as client:
                entra.confidential_client(cfg, "certificate", client_id="middle-tier-api")
        self.assertEqual(client.call_args.args, ("middle-tier-api",))
        self.assertFalse(client.call_args.kwargs["instance_discovery"])

    def test_mismatched_certificate_stops_before_network_client(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.certificate_case(directory, matching=False)
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(entra.msal, "ConfidentialClientApplication") as client:
                with self.assertRaises(RuntimeError):
                    entra.confidential_client({}, "certificate", client_id="middle-tier-api")
                client.assert_not_called()

    def test_expired_certificate_stops_before_network_client(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.certificate_case(directory, expired=True)
            with patch.dict(os.environ, env, clear=True), \
                 patch.object(entra.msal, "ConfidentialClientApplication") as client:
                with self.assertRaises(RuntimeError):
                    entra.confidential_client({}, "certificate", client_id="middle-tier-api")
                client.assert_not_called()


if __name__ == "__main__":
    unittest.main()
