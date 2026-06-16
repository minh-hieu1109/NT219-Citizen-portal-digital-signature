import base64
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
import secrets
from accounts.models import UserCertificate, User
from documents.models import Document
from .models import SignatureRecord, SigningRequest
from .signer_backends import get_signer_backend
from verification.ltv_services import archive_validation_evidence
from signing.pades_sequential_services import create_sequential_pades_for_signature_record
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from signing.artifact_services import generate_signature_artifacts
from signing.mldsa_openssl import mldsa_verify_with_cert_pem
from signing.external_tsp_client import external_tsp_sign
from django.core.files.base import ContentFile
import re


def normalize_pairing_code(code: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


def hash_pairing_code(code: str) -> str:
    normalized = normalize_pairing_code(code)
    pepper = settings.SECRET_KEY
    return sha256(f"{normalized}:{pepper}".encode("utf-8")).hexdigest()


def format_pairing_code(raw: str) -> str:
    raw = normalize_pairing_code(raw)
    return f"{raw[:4]}-{raw[4:]}"


def generate_pairing_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(8))
    return format_pairing_code(raw)


def issue_client_pairing_session(signing_request: SigningRequest) -> str:
    if signing_request.signing_type != SigningRequest.SigningType.CLIENT:
        raise ValueError("Only client signing requests can have pairing code.")

    if signing_request.status != SigningRequest.Status.PENDING:
        raise ValueError("Only pending requests can have pairing code.")

    pairing_code = generate_pairing_code()

    signing_request.client_token = secrets.token_urlsafe(48)
    signing_request.client_token_expires_at = timezone.now() + timedelta(minutes=10)

    signing_request.pairing_code_hash = hash_pairing_code(pairing_code)
    signing_request.pairing_code_expires_at = timezone.now() + timedelta(minutes=10)
    signing_request.pairing_status = SigningRequest.PairingStatus.WAITING_DEVICE
    signing_request.pairing_attempts = 0

    signing_request.paired_at = None
    signing_request.pairing_confirmed_at = None
    signing_request.signer_device_name = ""
    signing_request.signer_device_public_key_pem = ""

    signing_request.save(update_fields=[
        "client_token",
        "client_token_expires_at",
        "pairing_code_hash",
        "pairing_code_expires_at",
        "pairing_status",
        "pairing_attempts",
        "paired_at",
        "pairing_confirmed_at",
        "signer_device_name",
        "signer_device_public_key_pem",
    ])

    return pairing_code

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

def create_officer_approval_request_after_citizen_sign(citizen_signing_request):
    """
    After citizen self-signs a document, automatically create
    a pending officer approval signing request.
    """
    document = citizen_signing_request.document
    citizen = citizen_signing_request.signer

    if document.owner_id != citizen.id:
        return None

    existing_officer_request = SigningRequest.objects.filter(
        document=document,
        signer__role__in=[User.Role.OFFICER, User.Role.ADMIN],
        status__in=[
            SigningRequest.Status.PENDING,
            SigningRequest.Status.SIGNED,
        ],
    ).first()

    if existing_officer_request:
        return existing_officer_request

    officer = User.objects.filter(
        role=User.Role.OFFICER,
        is_verified_identity=True,
        certificate_profile__status=UserCertificate.Status.ACTIVE,
    ).first()

    if not officer:
        return None

    officer_request = SigningRequest.objects.create(
        document=document,
        requested_by=citizen_signing_request.requested_by,
        signer=officer,
        signing_type=SigningRequest.SigningType.REMOTE,
        status=SigningRequest.Status.PENDING,
        purpose=SigningRequest.SigningPurpose.OFFICER_APPROVAL,
    )
    input_hash = (
        getattr(document, "current_signed_pdf_sha256", "")
        or document.sha256_hash
        or ""
    )

    consent_text = (
        f"Officer approval request created after citizen signature. "
        f"citizen_signing_request_id={citizen_signing_request.id}, "
        f"document_id={document.id}, "
        f"document_hash={input_hash}"
    )

    officer_request.request_document_hash = input_hash
    officer_request.request_nonce = secrets.token_urlsafe(32)
    officer_request.auth_method = "system_after_citizen_signature"
    officer_request.consent_text = consent_text
    officer_request.consent_hash = sha256(consent_text.encode("utf-8")).hexdigest()
    officer_request.save(update_fields=[
        "request_document_hash",
        "request_nonce",
        "auth_method",
        "consent_text",
        "consent_hash",
    ])
    return officer_request

def get_document_input_path_for_signing(document):
    if getattr(document, "current_signed_pdf", None) and document.current_signed_pdf:
        return document.current_signed_pdf.path

    if getattr(document, "final_signed_pdf", None) and document.final_signed_pdf:
        return document.final_signed_pdf.path

    return document.file.path

def remote_sign_signing_request(signing_request: SigningRequest) -> SignatureRecord:
    signer = signing_request.signer
    if not signer:
        raise ValueError("Signing request does not have a signer assigned.")

    if signing_request.signing_type != SigningRequest.SigningType.REMOTE:
        raise ValueError("This signing request is not a remote signing request.")

    now = timezone.now()

    if signing_request.expires_at and now > signing_request.expires_at:
        raise ValueError("Signing request has expired.")

    if signing_request.used_at is not None:
        raise ValueError("Signing request has already been used (replay detected).")

    if signing_request.status != SigningRequest.Status.PENDING:
        raise ValueError("This signing request is not in pending status.")

    if hasattr(signing_request, "signature_record"):
        raise ValueError("This signing request has already been signed.")

    if (
        settings.REQUIRE_STRONG_AUTH_FOR_REMOTE_SIGNING
        and not signing_request.strong_auth_verified
    ):
        raise ValueError("Strong authentication is required for remote signing.")

    if signer.role == signer.Role.CITIZEN and not signer.is_verified_identity:
        raise ValueError(
            "Citizen identity is not verified. Remote signing is not allowed."
        )

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

    if user_cert.valid_from and now < user_cert.valid_from:
        raise ValueError("Signer certificate is not valid yet.")

    if user_cert.valid_to and now > user_cert.valid_to:
        raise ValueError("Signer certificate has expired.")

    document = signing_request.document
    if not document.file:
        raise ValueError("Document has no file attached.")

    input_path = get_document_input_path_for_signing(document)

    with open(input_path, "rb") as f:
        file_bytes = f.read()

    file_hash_hex = sha256(file_bytes).hexdigest()

    allowed_remote_purposes = [
        SigningRequest.SigningPurpose.CITIZEN_REMOTE_SIGN,
        SigningRequest.SigningPurpose.OFFICER_APPROVAL,
    ]

    if signing_request.purpose not in allowed_remote_purposes:
        raise ValueError(
            f"Unsupported remote signing purpose: {signing_request.purpose}"
        )

    # Portal không tự giữ private key.
    # Hàm này mô phỏng việc Portal gọi external TSP/HSM để ký.
    signature_bytes = external_tsp_sign(
        signing_request=signing_request,
        user_cert=user_cert,
        data=file_bytes,
    )

    signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

    signature_record = SignatureRecord.objects.create(
        signing_request=signing_request,
        signature_value=signature_b64,
        certificate_pem=user_cert.certificate_pem,
        certificate_subject=user_cert.certificate_subject,
        certificate_serial=user_cert.certificate_serial,
        algorithm="ML-DSA-65",
        signed_hash=file_hash_hex,
    )

    try:
        tsa_result = create_timestamp_token_for_file(input_path)
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

    if signing_request.purpose == SigningRequest.SigningPurpose.OFFICER_APPROVAL:
        document.status = Document.Status.SIGNED
    else:
        document.status = Document.Status.PENDING_SIGN

    document.save(update_fields=["status"])

    signing_request.status = SigningRequest.Status.SIGNED
    signing_request.used_at = timezone.now()
    signing_request.completed_at = signature_record.signed_at
    signing_request.save(update_fields=["status", "used_at", "completed_at"])

    try:
        archive_validation_evidence(signature_record)
    except Exception:
        pass

    try:
        generate_signature_artifacts(signature_record)
    except Exception as e:
        signature_record.timestamp_message = (
            (signature_record.timestamp_message or "")
            + f"\nArtifact generation failed: {str(e)}"
        )
        signature_record.save(update_fields=["timestamp_message"])

    pades_ok = False

    try:
        pades_result = create_sequential_pades_for_signature_record(signature_record)
        pades_ok = bool(pades_result.get("ok"))

        if not pades_ok:
            signature_record.timestamp_message = (
                (signature_record.timestamp_message or "")
                + f"\nSequential PAdES status: {pades_result.get('message', '')}"
            )
            signature_record.save(update_fields=["timestamp_message"])

    except Exception as e:
        signature_record.timestamp_message = (
            (signature_record.timestamp_message or "")
            + f"\nSequential PAdES failed: {str(e)}"
        )
        signature_record.save(update_fields=["timestamp_message"])

    if (
        pades_ok
        and signing_request.purpose == SigningRequest.SigningPurpose.CITIZEN_REMOTE_SIGN
    ):
        create_officer_approval_request_after_citizen_sign(signing_request)

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

    from signing.pades_external_client_services import prepare_client_pades_session

    session = prepare_client_pades_session(signing_request)

    return {
        "signing_request_id": signing_request.id,
        "document_id": signing_request.document.id,
        "document_title": signing_request.document.title,
        "algorithm": "ML-DSA-65",
        "mode": "pades_external_signing",
        "digest_algorithm": session.digest_algorithm,
        "document_digest": session.document_digest,
        "field_name": session.field_name,
        "signed_attrs_b64": session.signed_attrs_b64,
        "certificate_serial": signing_request.signer.certificate_profile.certificate_serial,
    }

def complete_client_signing_request(
    signing_request: SigningRequest,
    signature_b64: str,
    algorithm: str = "ML-DSA-65",
) -> SignatureRecord:
    algorithm = (algorithm or "").strip().upper()

    if algorithm not in ["ML-DSA-65", "MLDSA-65"]:
        raise ValueError("Unsupported algorithm. This PoC allows ML-DSA-65 only.")

    from signing.pades_external_client_services import finish_client_pades_session

    signature_record = finish_client_pades_session(
        signing_request=signing_request,
        signature_b64=signature_b64,
    )

    try:
        archive_validation_evidence(signature_record)
    except Exception:
        pass

    try:
        generate_signature_artifacts(signature_record)
    except Exception as e:
        signature_record.timestamp_message = (
            (signature_record.timestamp_message or "")
            + f"\nArtifact generation failed: {str(e)}"
        )
        signature_record.save(update_fields=["timestamp_message"])

    officer_request = create_officer_approval_request_after_citizen_sign(signing_request)

    if officer_request is None:
        signature_record.timestamp_message = (
            (signature_record.timestamp_message or "")
            + "\nOfficer approval request was not created. "
            + "Check whether an active verified officer certificate exists."
        )
        signature_record.save(update_fields=["timestamp_message"])

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

def issue_client_signing_token(signing_request: SigningRequest) -> str:
    if signing_request.signing_type != SigningRequest.SigningType.CLIENT:
        raise ValueError("Only client signing requests can have client token.")

    if signing_request.status != SigningRequest.Status.PENDING:
        raise ValueError("Only pending requests can have client token.")

    token = secrets.token_urlsafe(48)
    signing_request.client_token = token
    signing_request.client_token_expires_at = timezone.now() + timedelta(minutes=10)
    signing_request.save(update_fields=["client_token", "client_token_expires_at"])

    return token