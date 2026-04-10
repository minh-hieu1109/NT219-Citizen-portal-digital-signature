import base64
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from accounts.models import UserCertificate
from .models import SignatureRecord, SigningRequest
from .signer_backends import get_signer_backend

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

def create_timestamp_token_for_file(file_path: str) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        tsq_path = tmpdir / "request.tsq"
        tsr_path = tmpdir / "response.tsr"

        query_cmd = [
            str(settings.PKI_OPENSSL_BIN),
            "ts",
            "-query",
            "-data",
            file_path,
            "-sha256",
            "-cert",
            "-out",
            str(tsq_path),
        ]
        subprocess.run(query_cmd, check=True, capture_output=True, text=True)

        reply_cmd = [
            str(settings.PKI_OPENSSL_BIN),
            "ts",
            "-reply",
            "-config",
            str(settings.PKI_TSA_CONF),
            "-section",
            settings.PKI_TSA_SECTION,
            "-queryfile",
            str(tsq_path),
            "-out",
            str(tsr_path),
        ]
        subprocess.run(reply_cmd, check=True, capture_output=True, text=True)

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
        verify_proc = subprocess.run(
            verify_cmd,
            capture_output=True,
            text=True,
        )

        token_b64 = base64.b64encode(tsr_path.read_bytes()).decode("utf-8")
        ok = verify_proc.returncode == 0

        message = (verify_proc.stdout or "") + (verify_proc.stderr or "")
        message = message.strip()

        return {
            "ok": ok,
            "timestamp_token_b64": token_b64,
            "message": message,
        }


def remote_sign_signing_request(signing_request: SigningRequest) -> SignatureRecord:
    signer = signing_request.signer
    if not signer:
        raise ValueError("Signing request does not have a signer assigned.")

    if signing_request.signing_type != SigningRequest.SigningType.REMOTE:
        raise ValueError("This signing request is not a remote signing request.")

    if signing_request.status != SigningRequest.Status.PENDING:
        raise ValueError("This signing request is not in pending status.")

    if hasattr(signing_request, "signature_record"):
        raise ValueError("This signing request has already been signed.")

    user_cert = UserCertificate.objects.filter(user=signer).first()
    if not user_cert:
        raise ValueError(
            "Signer does not have a certificate. Please issue a certificate first."
        )

    if user_cert.status == UserCertificate.Status.REVOKED:
        raise ValueError(
            "Signer certificate has been revoked. Remote signing is not allowed."
        )

    if user_cert.status != UserCertificate.Status.ACTIVE:
        raise ValueError(
            "Signer certificate is not active. Remote signing is not allowed."
        )

    now = timezone.now()
    if user_cert.valid_from and now < user_cert.valid_from:
        raise ValueError("Signer certificate is not valid yet.")

    if user_cert.valid_to and now > user_cert.valid_to:
        raise ValueError("Signer certificate has expired.")

    document = signing_request.document
    if not document.file:
        raise ValueError("Document has no file attached.")

    with open(document.file.path, "rb") as f:
        file_bytes = f.read()

    file_hash_hex = sha256(file_bytes).hexdigest()

    signer_backend = get_signer_backend(user_cert)
    signature_bytes = signer_backend.sign(user_cert, file_bytes)
    signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

    signature_record = SignatureRecord.objects.create(
        signing_request=signing_request,
        signature_value=signature_b64,
        certificate_pem=user_cert.certificate_pem,
        certificate_subject=user_cert.certificate_subject,
        certificate_serial=user_cert.certificate_serial,
        algorithm="RSA-SHA256",
        signed_hash=file_hash_hex,
    )

    try:
        tsa_result = create_timestamp_token_for_file(document.file.path)
        signature_record.timestamp_token = tsa_result["timestamp_token_b64"]
        signature_record.timestamp_status = "valid" if tsa_result["ok"] else "invalid"
        signature_record.timestamp_message = tsa_result["message"]
        signature_record.save(
            update_fields=["timestamp_token", "timestamp_status", "timestamp_message"]
        )
    except Exception as e:
        signature_record.timestamp_status = "error"
        signature_record.timestamp_message = f"Timestamping failed: {str(e)}"
        signature_record.save(
            update_fields=["timestamp_status", "timestamp_message"]
        )

    signing_request.status = SigningRequest.Status.SIGNED
    signing_request.completed_at = signature_record.signed_at
    signing_request.save(update_fields=["status", "completed_at"])

    return signature_record


def sign_hash_value(hash_value: str, private_key_path: str) -> str:
    raise NotImplementedError(
        "Deprecated. Use remote_sign_signing_request() with signer backend instead."
    )

def prepare_client_signing_request(signing_request: SigningRequest) -> dict:
    signer = signing_request.signer
    if not signer:
        raise ValueError("Signing request does not have a signer assigned.")

    if signing_request.signing_type != SigningRequest.SigningType.CLIENT:
        raise ValueError("This signing request is not a client signing request.")

    if signing_request.status != SigningRequest.Status.PENDING:
        raise ValueError("This signing request is not in pending status.")

    if hasattr(signing_request, "signature_record"):
        raise ValueError("This signing request has already been signed.")

    user_cert = get_active_user_certificate_for_signing(signer)

    document = signing_request.document
    if not document.file:
        raise ValueError("Document has no file attached.")

    with open(document.file.path, "rb") as f:
        file_bytes = f.read()

    file_hash_hex = sha256(file_bytes).hexdigest()

    return {
        "signing_request_id": signing_request.id,
        "document_id": document.id,
        "document_title": document.title,
        "digest_hex": file_hash_hex,
        "algorithm": "RSA-SHA256-PREHASHED",
        "certificate_serial": user_cert.certificate_serial,
    }


def complete_client_signing_request(
    signing_request: SigningRequest,
    signature_b64: str,
    algorithm: str = "RSA-SHA256-PREHASHED",
) -> SignatureRecord:
    signer = signing_request.signer
    if not signer:
        raise ValueError("Signing request does not have a signer assigned.")

    if signing_request.signing_type != SigningRequest.SigningType.CLIENT:
        raise ValueError("This signing request is not a client signing request.")

    if signing_request.status != SigningRequest.Status.PENDING:
        raise ValueError("This signing request is not in pending status.")

    if hasattr(signing_request, "signature_record"):
        raise ValueError("This signing request has already been signed.")

    user_cert = get_active_user_certificate_for_signing(signer)

    document = signing_request.document
    if not document.file:
        raise ValueError("Document has no file attached.")

    with open(document.file.path, "rb") as f:
        file_bytes = f.read()

    file_hash_hex = sha256(file_bytes).hexdigest()
    digest_bytes = bytes.fromhex(file_hash_hex)

    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception:
        raise ValueError("Invalid base64 signature_value.")

    cert = x509.load_pem_x509_certificate(user_cert.certificate_pem.encode("utf-8"))

    if str(cert.serial_number) != str(user_cert.certificate_serial):
        raise ValueError("Stored certificate does not match signer certificate serial.")

    public_key = cert.public_key()
    public_key.verify(
        signature_bytes,
        digest_bytes,
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256()),
    )

    signature_record = SignatureRecord.objects.create(
        signing_request=signing_request,
        signature_value=signature_b64,
        certificate_pem=user_cert.certificate_pem,
        certificate_subject=user_cert.certificate_subject or cert.subject.rfc4514_string(),
        certificate_serial=user_cert.certificate_serial or str(cert.serial_number),
        algorithm=algorithm,
        signed_hash=file_hash_hex,
    )

    try:
        tsa_result = create_timestamp_token_for_file(document.file.path)
        signature_record.timestamp_token = tsa_result["timestamp_token_b64"]
        signature_record.timestamp_status = "valid" if tsa_result["ok"] else "invalid"
        signature_record.timestamp_message = tsa_result["message"]
        signature_record.save(
            update_fields=["timestamp_token", "timestamp_status", "timestamp_message"]
        )
    except Exception as e:
        signature_record.timestamp_status = "error"
        signature_record.timestamp_message = f"Timestamping failed: {str(e)}"
        signature_record.save(
            update_fields=["timestamp_status", "timestamp_message"]
        )

    signing_request.status = SigningRequest.Status.SIGNED
    signing_request.completed_at = signature_record.signed_at
    signing_request.save(update_fields=["status", "completed_at"])

    return signature_record

def get_active_user_certificate_for_signing(user) -> UserCertificate:
    user_cert = UserCertificate.objects.filter(user=user).first()
    if not user_cert:
        raise ValueError(
            "Signer does not have a certificate. Please issue a certificate first."
        )

    if user_cert.status == UserCertificate.Status.REVOKED:
        raise ValueError("Signer certificate has been revoked.")

    if user_cert.status != UserCertificate.Status.ACTIVE:
        raise ValueError("Signer certificate is not active.")

    now = timezone.now()
    if user_cert.valid_from and now < user_cert.valid_from:
        raise ValueError("Signer certificate is not valid yet.")

    if user_cert.valid_to and now > user_cert.valid_to:
        raise ValueError("Signer certificate has expired.")

    if not user_cert.certificate_pem:
        raise ValueError("Signer certificate PEM is missing.")

    return user_cert