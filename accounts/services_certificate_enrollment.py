import tempfile
import subprocess
from pathlib import Path
from cryptography import x509
from django.conf import settings
from django.utils import timezone

from accounts.models import UserCertificate


def issue_certificate_from_csr(
    user,
    csr_pem: str,
    key_storage_type: str = "file",
    client_key_label: str = "",
):
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid CSR PEM: {str(e)}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        csr_path = tmpdir / "client.csr.pem"
        cert_path = tmpdir / "client.crt.pem"

        csr_path.write_text(csr_pem, encoding="utf-8")

        cmd = [
            str(settings.PKI_OPENSSL_BIN),
            "x509",
            "-req",
            "-in",
            str(csr_path),
            "-CA",
            str(settings.PKI_ROOT_CA_CERT),
            "-CAkey",
            str(settings.PKI_ROOT_CA_KEY),
            "-CAcreateserial",
            "-out",
            str(cert_path),
            "-days",
            "365",
            "-sha256",
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise ValueError(
                f"OpenSSL certificate issuance failed: {(proc.stdout or '')} {(proc.stderr or '')}".strip()
            )

        certificate_pem = cert_path.read_text(encoding="utf-8")
        cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))

    now = timezone.now()

    user_cert, _created = UserCertificate.objects.update_or_create(
        user=user,
        defaults={
            "certificate_pem": certificate_pem,
            "certificate_subject": cert.subject.rfc4514_string(),
            "certificate_serial": str(cert.serial_number),
            "key_storage_type": key_storage_type,
            "status": UserCertificate.Status.ACTIVE,
            "valid_from": cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else now,
            "valid_to": cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else now,
            # file-based phase: các field PKCS#11 có thể để trống
            "pkcs11_token_label": "",
            "pkcs11_key_label": client_key_label or "",
            "pkcs11_key_id": "",
            "pkcs11_slot": None,
        },
    )

    return {
        "user_certificate": user_cert,
        "certificate_pem": certificate_pem,
        "certificate_subject": cert.subject.rfc4514_string(),
        "certificate_serial": str(cert.serial_number),
    }