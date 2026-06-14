import subprocess
import tempfile
from pathlib import Path

from django.conf import settings


def openssl_bin() -> str:
    return str(getattr(settings, "PKI_OPENSSL_BIN", "openssl"))


def mldsa_sign_bytes(private_key_path: str, data: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        data_path = tmpdir / "data.bin"
        sig_path = tmpdir / "signature.sig"

        data_path.write_bytes(data)

        cmd = [
            openssl_bin(),
            "pkeyutl",
            "-sign",
            "-inkey",
            str(private_key_path),
            "-rawin",
            "-in",
            str(data_path),
            "-out",
            str(sig_path),
        ]

        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return sig_path.read_bytes()


def mldsa_verify_with_cert_pem(cert_pem: str, data: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        cert_path = tmpdir / "signer.crt"
        pub_path = tmpdir / "signer.pub"
        data_path = tmpdir / "data.bin"
        sig_path = tmpdir / "signature.sig"

        cert_path.write_text(cert_pem, encoding="utf-8")
        data_path.write_bytes(data)
        sig_path.write_bytes(signature)

        subprocess.run([
            openssl_bin(),
            "x509",
            "-in",
            str(cert_path),
            "-pubkey",
            "-noout",
            "-out",
            str(pub_path),
        ], check=True, capture_output=True, text=True)

        proc = subprocess.run([
            openssl_bin(),
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(pub_path),
            "-rawin",
            "-in",
            str(data_path),
            "-sigfile",
            str(sig_path),
        ], capture_output=True, text=True)

        return proc.returncode == 0