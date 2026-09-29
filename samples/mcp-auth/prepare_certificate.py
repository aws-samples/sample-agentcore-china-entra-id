"""Prepare local test credentials; upload only client-public.cer to Entra."""
from datetime import datetime, timedelta, timezone
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from local_config import ROOT, save


def main():
    directory = ROOT / ".state/client-certificate"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_path = directory / "client-private.pem"
    if private_path.exists():
        raise RuntimeError("Existing private key preserved; do not overwrite a registered credential")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AgentCore China MCP Integration Test")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
    (directory / "client-public.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "client-public.cer").write_bytes(cert.public_bytes(serialization.Encoding.DER))
    metadata = {
        "purpose": "Test OAuth client authentication only; not a TLS server certificate",
        "created_at_utc": now.isoformat(), "expires_at_utc": cert.not_valid_after_utc.isoformat(),
        "sha1_thumbprint": cert.fingerprint(hashes.SHA1()).hex(),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "entra_public_certificate_registered": False,
        "certificate_flow_executed": False,
    }
    save(directory / "metadata.json", metadata)
    print(json.dumps({"public_certificate_for_entra": str(directory / "client-public.cer"),
                      "expires_at_utc": metadata["expires_at_utc"],
                      "entra_registration_complete": False}, indent=2))


if __name__ == "__main__":
    main()
