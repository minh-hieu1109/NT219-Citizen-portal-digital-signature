import base64
import subprocess
import tempfile
from hashlib import sha256
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from accounts.models import UserCertificate
from signing.models import SignatureRecord
from .models import VerificationResult
from .crl_utils import is_cert_revoked_in_crl
from .ocsp_services import check_certificate_ocsp_status
from .ltv_services import verify_ltv
from signing.mldsa_openssl import mldsa_verify_with_cert_pem

def verify_timestamp_for_file(file_path: str, timestamp_token_b64: str) -> dict:
    if not timestamp_token_b64:
        return {
            "ok": False,
            "message": "No timestamp token stored.",
        }

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        tsr_path = tmpdir / "response.tsr"
        tsr_path.write_bytes(base64.b64decode(timestamp_token_b64))

        verify_cmd = [
            str(settings.PKI_OPENSSL_BIN),
            "ts",
            "-verify",
            "-data",
            file_path,
            "-in",
            str(tsr_path),
            "-CAfile",
            str(settings.PKI_ROOT_CA_CERT),
            "-untrusted",
            str(settings.PKI_TSA_CERT),
        ]
        proc = subprocess.run(
            verify_cmd,
            capture_output=True,
            text=True,
        )

        message = (proc.stdout or "") + (proc.stderr or "")
        message = message.strip()

        return {
            "ok": proc.returncode == 0,
            "message": message,
        }


def verify_signature_record(signature_record: SignatureRecord) -> VerificationResult:
    signing_request = signature_record.signing_request
    document = signing_request.document

    VerificationResult.objects.filter(signature_record=signature_record).delete()

    if not document.file:
        return VerificationResult.objects.create(
            signature_record=signature_record,
            status=VerificationResult.Status.INVALID,
            is_signature_valid=False,
            is_hash_match=False,
            signer_subject=signature_record.certificate_subject,
            signer_serial=signature_record.certificate_serial,
            detail={"message": "Document has no file attached."},
        )

    with open(document.file.path, "rb") as f:
        file_bytes = f.read()

    recomputed_hash = sha256(file_bytes).hexdigest()
    is_hash_match = recomputed_hash == signature_record.signed_hash

    if not is_hash_match:
        return VerificationResult.objects.create(
            signature_record=signature_record,
            status=VerificationResult.Status.INVALID,
            is_signature_valid=False,
            is_hash_match=False,
            signer_subject=signature_record.certificate_subject,
            signer_serial=signature_record.certificate_serial,
            detail={
                "message": "File hash mismatch. The document may have been modified after signing.",
                "expected_hash": signature_record.signed_hash,
                "recomputed_hash": recomputed_hash,
            },
        )

    try:
        cert = x509.load_pem_x509_certificate(
            signature_record.certificate_pem.encode("utf-8")
        )

        signature_bytes = base64.b64decode(signature_record.signature_value)
        algorithm = (signature_record.algorithm or "").strip().upper()

        if algorithm in ["ML-DSA-65", "MLDSA-65"]:
            is_signature_valid = mldsa_verify_with_cert_pem(
                cert_pem=signature_record.certificate_pem,
                data=file_bytes,
                signature=signature_bytes,
            )

            if not is_signature_valid:
                raise InvalidSignature("ML-DSA signature verification failed.")
        else:
            public_key = cert.public_key()
            public_key.verify(
                signature_bytes,
                file_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            is_signature_valid = True

        if signature_record.algorithm == "ML-DSA-65":
            is_signature_valid = mldsa_verify_with_cert_pem(
                cert_pem=signature_record.certificate_pem,
                data=file_bytes,
                signature=signature_bytes,
            )

            if not is_signature_valid:
                raise InvalidSignature("ML-DSA signature verification failed.")
        else:
            public_key.verify(
                signature_bytes,
                file_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            is_signature_valid = True



    except InvalidSignature:
        return VerificationResult.objects.create(
            signature_record=signature_record,
            status=VerificationResult.Status.INVALID,
            is_signature_valid=False,
            is_hash_match=True,
            signer_subject=signature_record.certificate_subject,
            signer_serial=signature_record.certificate_serial,
            detail={"message": "Signature verification failed."},
        )

    except Exception as e:
        return VerificationResult.objects.create(
            signature_record=signature_record,
            status=VerificationResult.Status.INVALID,
            is_signature_valid=False,
            is_hash_match=True,
            signer_subject=signature_record.certificate_subject,
            signer_serial=signature_record.certificate_serial,
            detail={
                "message": "Verification error.",
                "error": str(e),
            },
        )

    with open(settings.PKI_ROOT_CA_CERT, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())

    if cert.issuer != root_cert.subject:
        return VerificationResult.objects.create(
            signature_record=signature_record,
            status=VerificationResult.Status.INVALID,
            is_signature_valid=True,
            is_hash_match=True,
            signer_subject=cert.subject.rfc4514_string(),
            signer_serial=str(cert.serial_number),
            detail={
                "message": "Signer certificate is not issued by the trusted lab CA.",
                "cert_issuer": cert.issuer.rfc4514_string(),
                "trusted_ca_subject": root_cert.subject.rfc4514_string(),
            },
        )

    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        return VerificationResult.objects.create(
            signature_record=signature_record,
            status=VerificationResult.Status.INVALID,
            is_signature_valid=True,
            is_hash_match=True,
            signer_subject=cert.subject.rfc4514_string(),
            signer_serial=str(cert.serial_number),
            detail={
                "message": "Signer certificate is expired or not yet valid.",
                "not_valid_before": cert.not_valid_before_utc.isoformat(),
                "not_valid_after": cert.not_valid_after_utc.isoformat(),
            },
        )

    db_cert = UserCertificate.objects.filter(
        certificate_serial=str(cert.serial_number)
    ).first()

    if db_cert and db_cert.status != UserCertificate.Status.ACTIVE:
        return VerificationResult.objects.create(
            signature_record=signature_record,
            status=VerificationResult.Status.INVALID,
            is_signature_valid=True,
            is_hash_match=True,
            signer_subject=cert.subject.rfc4514_string(),
            signer_serial=str(cert.serial_number),
            detail={
                "message": "Signer certificate is not active in local PKI database.",
                "certificate_status": db_cert.status,
            },
        )

    if is_cert_revoked_in_crl(cert.serial_number):
        return VerificationResult.objects.create(
            signature_record=signature_record,
            status=VerificationResult.Status.INVALID,
            is_signature_valid=True,
            is_hash_match=True,
            signer_subject=cert.subject.rfc4514_string(),
            signer_serial=str(cert.serial_number),
            detail={
                "message": "Signer certificate is revoked according to CRL."
            },
        )

    ocsp_info = {}
    if getattr(settings, "ENABLE_OCSP_CHECK", True):
        with open(settings.PKI_ROOT_CA_CERT, "rb") as f:
            issuer_pem = f.read().decode("utf-8")

        ocsp_result = check_certificate_ocsp_status(
            cert_pem=signature_record.certificate_pem,
            issuer_pem=issuer_pem,
        )
        ocsp_status = ocsp_result.get("status", "error")
        ocsp_info = {
            "ocsp_enabled": True,
            "ocsp_status": ocsp_status,
            "ocsp_message": ocsp_result.get("message", ""),
            "ocsp_serial": ocsp_result.get("serial", str(cert.serial_number)),
            "ocsp_responder_url": settings.OCSP_RESPONDER_URL,
        }

        if ocsp_status == "revoked":
            return VerificationResult.objects.create(
                signature_record=signature_record,
                status=VerificationResult.Status.INVALID,
                is_signature_valid=True,
                is_hash_match=True,
                signer_subject=cert.subject.rfc4514_string(),
                signer_serial=str(cert.serial_number),
                detail={
                    "message": "Signer certificate is revoked according to OCSP.",
                    **ocsp_info,
                },
            )

        if ocsp_status == "unknown":
            return VerificationResult.objects.create(
                signature_record=signature_record,
                status=VerificationResult.Status.INVALID,
                is_signature_valid=True,
                is_hash_match=True,
                signer_subject=cert.subject.rfc4514_string(),
                signer_serial=str(cert.serial_number),
                detail={
                    "message": "OCSP responder returned unknown certificate status.",
                    **ocsp_info,
                },
            )
    else:
        ocsp_info = {
            "ocsp_enabled": False,
            "ocsp_status": "disabled",
            "ocsp_message": "OCSP check disabled by settings.",
        }

    timestamp_info = {}
    if signature_record.timestamp_token:
        ts_result = verify_timestamp_for_file(
            document.file.path,
            signature_record.timestamp_token,
        )
        timestamp_info = {
            "has_timestamp": True,
            "timestamp_status": "valid" if ts_result["ok"] else "invalid",
            "timestamp_message": ts_result["message"],
        }

        if not ts_result["ok"]:
            timestamp_info["timestamp_warning"] = (
                "Timestamp token is invalid in current ML-DSA lab setup. "
                "Signature and document hash are still cryptographically valid."
            )
    else:
        timestamp_info = {
            "has_timestamp": False,
            "timestamp_status": "missing",
            "timestamp_message": "No timestamp token stored.",
        }

    ltv_info = verify_ltv(signature_record)

    return VerificationResult.objects.create(
        signature_record=signature_record,
        status=VerificationResult.Status.VALID,
        is_signature_valid=True,
        is_hash_match=True,
        signer_subject=cert.subject.rfc4514_string(),
        signer_serial=str(cert.serial_number),
        detail={
            "message": "Signature is valid. File integrity OK. Certificate is trusted by lab CA and currently active.",
            **ocsp_info,
            **timestamp_info,
            "ltv": ltv_info,
        },
    )
