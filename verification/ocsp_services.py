import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from django.conf import settings


def check_certificate_ocsp_status(cert_pem: str, issuer_pem: str) -> dict:
    """
    Returns one of:
    - good
    - revoked
    - unknown
    - unavailable
    - error
    """
    if not cert_pem or not issuer_pem:
        return {
            "status": "error",
            "message": "Missing certificate or issuer certificate for OCSP check.",
        }

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        serial = format(cert.serial_number, "X")
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to parse signer certificate for OCSP: {exc}",
        }

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cert_path = tmp / "cert.pem"
            issuer_path = tmp / "issuer.pem"
            cert_path.write_text(cert_pem, encoding="utf-8")
            issuer_path.write_text(issuer_pem, encoding="utf-8")

            cmd = [
                str(settings.OPENSSL_BIN),
                "ocsp",
                "-issuer",
                str(issuer_path),
                "-cert",
                str(cert_path),
                "-url",
                settings.OCSP_RESPONDER_URL,
                "-noverify",
            ]

            proc = subprocess.run(cmd, capture_output=True, text=True)
            output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            lower_output = output.lower()

            if proc.returncode != 0:
                network_hints = ("connection refused", "timed out", "unable to connect", "no response")
                if any(hint in lower_output for hint in network_hints):
                    return {
                        "status": "unavailable",
                        "serial": serial,
                        "message": output or "OCSP responder unavailable.",
                    }
                return {
                    "status": "error",
                    "serial": serial,
                    "message": output or "OpenSSL OCSP command failed.",
                }

            if "revoked" in lower_output:
                status = "revoked"
            elif "good" in lower_output:
                status = "good"
            elif "unknown" in lower_output:
                status = "unknown"
            else:
                status = "error"

            return {
                "status": status,
                "serial": serial,
                "message": output,
            }
    except FileNotFoundError as exc:
        return {
            "status": "error",
            "serial": serial,
            "message": f"OpenSSL binary not found: {exc}",
        }
    except Exception as exc:
        return {
            "status": "unavailable",
            "serial": serial,
            "message": f"OCSP check unavailable: {exc}",
        }
