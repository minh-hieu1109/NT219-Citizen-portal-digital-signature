import base64
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import re
from django.conf import settings
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

from signing.cms_services import verify_cms_detached_signature
from verification.crl_utils import is_cert_revoked_in_crl
from verification.ocsp_services import check_certificate_ocsp_status
from signing.pades_services import verify_pades_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from accounts.models import UserCertificate
def _save_upload(uploaded_file, suffix=""):
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        for chunk in uploaded_file.chunks():
            tmp.write(chunk)
        return Path(tmp.name)

def apply_public_certificate_policy(result: dict) -> dict:
    """
    Tách rõ:
    - signature_valid: chữ ký đúng về mặt mật mã
    - status/ok: kết quả tin cậy cuối cùng sau khi check cert/revoke
    """
    signature_ok = bool(result.get("signature_valid") or result.get("ok"))

    trusted = result.get("certificate_trusted_by_lab_ca")
    revoked = result.get("certificate_revoked_crl")
    ocsp_status = result.get("ocsp_status")

    trusted_ok = trusted is not False
    revoked_bad = revoked is True or ocsp_status == "revoked"

    final_ok = signature_ok and trusted_ok and not revoked_bad

    result["ok"] = final_ok
    result["status"] = "valid" if final_ok else "invalid"

    if revoked_bad:
        old = result.get("message", "")
        result["message"] = (
            old + " Certificate is revoked, so the overall result is INVALID."
        ).strip()

    return result


def _extract_certificates_from_cms(cms_signature_path, document_path=None):
    certs = []

    for inform in ["DER", "PEM", "SMIME"]:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp:
            certs_out = Path(tmp.name)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".out") as tmp:
            verified_out = Path(tmp.name)

        try:
            cmd = [
                str(settings.PKI_OPENSSL_BIN),
                "cms",
                "-verify",
                "-inform",
                inform,
                "-in",
                str(cms_signature_path),
                "-noverify",
                "-certsout",
                str(certs_out),
                "-out",
                str(verified_out),
            ]

            if document_path:
                cmd.extend([
                    "-content",
                    str(document_path),
                    "-binary",
                ])

            subprocess.run(cmd, capture_output=True, text=True)

            pem_data = certs_out.read_text(
                encoding="utf-8",
                errors="ignore",
            )

            if "BEGIN CERTIFICATE" in pem_data:
                blocks = pem_data.split("-----END CERTIFICATE-----")
                for block in blocks:
                    if "-----BEGIN CERTIFICATE-----" in block:
                        pem = block + "-----END CERTIFICATE-----\n"
                        certs.append(
                            x509.load_pem_x509_certificate(
                                pem.encode("utf-8")
                            )
                        )

                if certs:
                    return certs

        finally:
            certs_out.unlink(missing_ok=True)
            verified_out.unlink(missing_ok=True)

    return certs


def _pick_signer_certificate(certs):
    if not certs:
        return None

    for cert in certs:
        if cert.subject != cert.issuer:
            return cert

    return certs[0]


def _extract_pades_sha256_fingerprint(details: str):
    match = re.search(
        r"Certificate SHA256 fingerprint:\s*([0-9a-fA-F]+)",
        details or "",
    )

    if not match:
        return None

    return match.group(1).lower()


def _find_user_certificate_by_sha256_fingerprint(fingerprint: str):
    if not fingerprint:
        return None

    for user_cert in UserCertificate.objects.all():
        if not user_cert.certificate_pem:
            continue

        cert = x509.load_pem_x509_certificate(user_cert.certificate_pem.encode("utf-8"))
        current_fp = cert.fingerprint(hashes.SHA256()).hex().lower()

        if current_fp == fingerprint.lower():
            return user_cert

    return None


def _enrich_pades_result_with_revocation(result: dict) -> dict:
    details = result.get("pades_details", "")
    fingerprint = _extract_pades_sha256_fingerprint(details)
    user_cert = _find_user_certificate_by_sha256_fingerprint(fingerprint)

    if not user_cert:
        return result

    cert = x509.load_pem_x509_certificate(user_cert.certificate_pem.encode("utf-8"))
    cert_checks = _basic_certificate_checks(cert)

    result.update(cert_checks)

    revoked_by_db = user_cert.status == UserCertificate.Status.REVOKED
    revoked_by_crl = cert_checks.get("certificate_revoked_crl") is True

    result["certificate_revoked_crl"] = bool(revoked_by_db or revoked_by_crl)

    if revoked_by_db:
        result["warning"] = (
            result.get("warning", "")
            + " Certificate is marked revoked in local certificate database."
        ).strip()

    return result

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


def _pick_signer_certificate(certs):
    """
    Pick end-entity signer cert, not Root CA.
    """
    if not certs:
        return None

    # Ưu tiên cert không phải self-signed/root
    for cert in certs:
        if cert.subject != cert.issuer:
            return cert

    return certs[0]

def verify_public_cms_detached(document_file, cms_signature_file):
    document_path = None
    signature_path = None

    try:
        document_path = _save_upload(document_file, suffix=".document")
        signature_path = _save_upload(cms_signature_file, suffix=".p7s")

        cms_result = verify_cms_detached_signature(
            input_file=str(document_path),
            cms_signature_path=str(signature_path),
            ca_cert_path=str(settings.PKI_ROOT_CA_CERT),
        )

        cert_info = {
            "certificate_subject": "-",
            "certificate_issuer": "-",
            "certificate_serial": "-",
            "certificate_time_valid": None,
            "certificate_trusted_by_lab_ca": None,
            "certificate_revoked_crl": None,
            "ocsp_status": "-",
            "ocsp_message": "",
            "signer_email": "-",
            "signer_common_name": "-",
        }

        try:
            certs = _extract_certificates_from_cms(signature_path, document_path)
            signer_cert = _pick_signer_certificate(certs)

            if signer_cert:
                cert_info.update(_basic_certificate_checks(signer_cert))

                attrs = signer_cert.subject
                email_attrs = attrs.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)
                cn_attrs = attrs.get_attributes_for_oid(x509.NameOID.COMMON_NAME)

                cert_info["signer_email"] = email_attrs[0].value if email_attrs else "-"
                cert_info["signer_common_name"] = cn_attrs[0].value if cn_attrs else "-"

        except Exception as exc:
            cert_info["warning"] = f"Could not extract signer certificate: {exc}"

        public_result = {
            "mode": "CAdES/CMS detached",
            "ok": bool(cms_result.get("ok")),
            "status": "valid" if cms_result.get("ok") else "invalid",
            "signature_valid": bool(cms_result.get("ok")),
            "verification_mode": cms_result.get("verification_mode", ""),
            "message": cms_result.get("message", ""),
            "warning": cms_result.get("warning", ""),
            **cert_info,
        }

        return apply_public_certificate_policy(public_result)

    except Exception as exc:
        return {
            "mode": "CAdES/CMS detached",
            "ok": False,
            "status": "error",
            "signature_valid": False,
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
    signed_pdf_path = None

    try:
        signed_pdf_path = _save_upload(signed_pdf_file, suffix=".pdf")

        pades_result = verify_pades_signature(
            signed_pdf_path=str(signed_pdf_path),
            ca_cert_path=str(settings.PKI_ROOT_CA_CERT),
        )

        details = (
            pades_result.get("details")
            or pades_result.get("pades_details")
            or pades_result.get("stdout")
            or pades_result.get("output")
            or ""
        )

        pades_cert_info = _parse_pades_details(details)

        public_result = {
            "mode": "PAdES signed PDF",
            "ok": bool(pades_result.get("ok")),
            "status": "valid" if pades_result.get("ok") else "invalid",
            "signature_valid": bool(pades_result.get("ok")),
            "message": pades_result.get("message", ""),
            "warning": pades_result.get("warning", ""),
            "pades_details": details,
            **pades_cert_info,
        }

        public_result = _enrich_pades_result_with_revocation(public_result)

        return apply_public_certificate_policy(public_result)

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