import subprocess
from pathlib import Path
from django.conf import settings
from accounts.models import UserCertificate

def run_cmd(cmd: list[str]) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

def revoke_user_certificate(user_cert: UserCertificate) -> None:
    if user_cert.status == UserCertificate.Status.REVOKED:
        return

    openssl_bin = str(settings.PKI_OPENSSL_BIN)
    openssl_ca_cnf = str(settings.PKI_OPENSSL_CA_CNF)

    cert_path = Path(settings.PKI_USER_CERT_DIR) / f"user_{user_cert.user.id}.crt"
    crl_path = Path(settings.PKI_CRL_DIR) / "lab_ca.crl.pem"

    if not cert_path.exists():
        raise RuntimeError(f"Certificate file not found: {cert_path}")

    run_cmd([
        openssl_bin,
        "ca",
        "-config", openssl_ca_cnf,
        "-revoke", str(cert_path),
        "-batch",
    ])

    run_cmd([
        openssl_bin,
        "ca",
        "-config", openssl_ca_cnf,
        "-gencrl",
        "-out", str(crl_path),
        "-batch",
    ])

    user_cert.status = UserCertificate.Status.REVOKED
    user_cert.save(update_fields=["status"])