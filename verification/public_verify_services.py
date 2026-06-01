import base64
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import re
from django.conf import settings
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from signing.cms_services import verify_cms_detached_signature
from verification.crl_utils import is_cert_revoked_in_crl
from verification.ocsp_services import check_certificate_ocsp_status
from signing.pades_services import verify_pades_signature

def _save_upload(uploaded_file, suffix=""):
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        for chunk in uploaded_file.chunks():
            tmp.write(chunk)
        return Path(tmp.name)


def _basic_certificate_checks(cert):
    result = {
        "certificate_subject": cert.subject.rfc4514_string(),
        "certificate_issuer": cert.issuer.rfc4514_string(),
        "certificate_serial": str(cert.serial_number),
        "certificate_time_valid": False,
        "certificate_trusted_by_lab_ca": False,
        "certificate_revoked_crl": False,
        "ocsp_status": "not_checked",
        "ocsp_message": "",
    }

    now = datetime.now(timezone.utc)

    if cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        result["certificate_time_valid"] = True

    with open(settings.PKI_ROOT_CA_CERT, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())

    if cert.issuer == root_cert.subject:
        result["certificate_trusted_by_lab_ca"] = True

    if is_cert_revoked_in_crl(cert.serial_number):
        result["certificate_revoked_crl"] = True

    if getattr(settings, "ENABLE_OCSP_CHECK", True):
        with open(settings.PKI_ROOT_CA_CERT, "rb") as f:
            issuer_pem = f.read().decode("utf-8")

        ocsp_result = check_certificate_ocsp_status(
            cert_pem=cert.public_bytes(
                encoding=__import__(
                    "cryptography.hazmat.primitives.serialization",
                    fromlist=["Encoding"],
                ).Encoding.PEM
            ).decode("utf-8"),
            issuer_pem=issuer_pem,
        )

        result["ocsp_status"] = ocsp_result.get("status", "error")
        result["ocsp_message"] = ocsp_result.get("message", "")

    return result


def verify_public_raw_signature(document_file, signature_file, certificate_file):
    """
    RAW mode:
    - document_file: original file
    - signature_file: base64 signature file, or raw binary signature
    - certificate_file: signer certificate PEM
    """

    try:
        document_bytes = document_file.read()
        signature_data = signature_file.read()
        certificate_pem = certificate_file.read()

        cert = x509.load_pem_x509_certificate(certificate_pem)
        public_key = cert.public_key()

        try:
            signature_bytes = base64.b64decode(signature_data.strip(), validate=True)
            signature_encoding = "base64"
        except Exception:
            signature_bytes = signature_data
            signature_encoding = "binary"

        try:
            public_key.verify(
                signature_bytes,
                document_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            signature_valid = True
            signature_error = ""
        except InvalidSignature:
            signature_valid = False
            signature_error = "Invalid signature. File may be modified or certificate does not match."
        except Exception as exc:
            signature_valid = False
            signature_error = str(exc)

        cert_checks = _basic_certificate_checks(cert)

        final_valid = (
            signature_valid
            and cert_checks["certificate_time_valid"]
            and cert_checks["certificate_trusted_by_lab_ca"]
            and not cert_checks["certificate_revoked_crl"]
            and cert_checks["ocsp_status"] not in {"revoked", "unknown"}
        )

        return {
            "mode": "RAW",
            "ok": final_valid,
            "status": "valid" if final_valid else "invalid",
            "signature_valid": signature_valid,
            "signature_encoding": signature_encoding,
            "signature_error": signature_error,
            **cert_checks,
        }

    except Exception as exc:
        return {
            "mode": "RAW",
            "ok": False,
            "status": "error",
            "message": str(exc),
        }


def verify_public_cms_detached(document_file, cms_signature_file):
    """
    CAdES/CMS detached mode:
    - document_file: original file
    - cms_signature_file: .p7s detached signature
    """

    document_path = None
    signature_path = None

    try:
        document_path = _save_upload(document_file, suffix=".document")
        signature_path = _save_upload(cms_signature_file, suffix=".p7s")

        result = verify_cms_detached_signature(
            input_file=str(document_path),
            cms_signature_path=str(signature_path),
            ca_cert_path=str(settings.PKI_ROOT_CA_CERT),
        )

        return {
            "mode": "CAdES/CMS detached",
            "ok": bool(result.get("ok")),
            "status": result.get("status", "invalid"),
            "verification_mode": result.get("verification_mode", ""),
            "message": result.get("message", ""),
            "warning": result.get("warning", ""),
        }

    except Exception as exc:
        return {
            "mode": "CAdES/CMS detached",
            "ok": False,
            "status": "error",
            "message": str(exc),
        }

    finally:
        for p in [document_path, signature_path]:
            try:
                if p and Path(p).exists():
                    Path(p).unlink()
            except Exception:
                pass

def _parse_pades_details(details):
    certificate_subject = "-"
    trust_anchor = "-"
    certificate_trusted = False

    subject_match = re.search(r'Certificate subject:\s+"([^"]+)"', details)
    if subject_match:
        certificate_subject = subject_match.group(1)

    trust_match = re.search(r'Trust anchor:\s+"([^"]+)"', details)
    if trust_match:
        trust_anchor = trust_match.group(1)

    if "The signer's certificate is trusted." in details:
        certificate_trusted = True

    return {
        "certificate_subject": certificate_subject,
        "certificate_issuer": trust_anchor,
        "certificate_serial": "-",
        "certificate_time_valid": None,
        "certificate_trusted_by_lab_ca": certificate_trusted,
        "certificate_revoked_crl": None,
        "ocsp_status": "-",
        "ocsp_message": "",
    }

def verify_public_pades(signed_pdf_file):
    """
    PAdES mode:
    - signed_pdf_file: signed PDF with embedded signature.
    """

    signed_pdf_path = None

    try:
        signed_pdf_path = _save_upload(signed_pdf_file, suffix=".pdf")

        result = verify_pades_signature(
            signed_pdf_path=str(signed_pdf_path),
            ca_cert_path=str(settings.PKI_ROOT_CA_CERT),
        )

        details = result.get("details", "")
        pades_cert_info = _parse_pades_details(details)

        return {
            "mode": "PAdES signed PDF",
            "ok": bool(result.get("ok")),
            "status": result.get("status", "invalid"),
            "signature_valid": bool(result.get("ok")),
            "message": result.get("message", ""),
            "warning": "",
            "pades_details": details,
            **pades_cert_info,
        }

    except Exception as exc:
        return {
            "mode": "PAdES signed PDF",
            "ok": False,
            "status": "error",
            "signature_valid": False,
            "message": str(exc),
        }

    finally:
        try:
            if signed_pdf_path and Path(signed_pdf_path).exists():
                Path(signed_pdf_path).unlink()
        except Exception:
            pass