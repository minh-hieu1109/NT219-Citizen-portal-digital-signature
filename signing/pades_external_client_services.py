import asyncio
import base64
import pickle
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import tempfile
from asgiref.sync import sync_to_async
from asn1crypto import cms
from asn1crypto.algos import SignedDigestAlgorithm
from django.conf import settings
from django.core.files.base import ContentFile
from django.utils import timezone

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko_certvalidator.registry import SimpleCertificateStore

from accounts.models import UserCertificate
from documents.models import Document
from documents.services import calculate_sha256_path
from signing.models import ClientPadesSession, SignatureRecord, SigningRequest
from signing.mldsa_openssl import mldsa_verify_with_cert_pem


ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18"
ML_DSA_65_SIGNATURE_SIZE = 3309

# PyHanko API lưu CMS object trong PDF dưới dạng hex string,
# nên bytes_reserved nên lớn hơn DER CMS thực tế khá nhiều.
# 65536 đủ rộng cho ML-DSA-65 + cert + CMS attrs + timestamp token demo.
CLIENT_PADES_BYTES_RESERVED = 65536
CLIENT_PADES_DIGEST_ALGORITHM = "sha512"


def _load_cert_from_pem_text(certificate_pem: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "signer_cert.pem"
        cert_path.write_text(certificate_pem, encoding="utf-8")
        return load_cert_from_pemder(str(cert_path))


def _build_external_signer(user_cert: UserCertificate, signature_value: bytes):
    signing_cert = _load_cert_from_pem_text(user_cert.certificate_pem)

    cert_store = SimpleCertificateStore()
    cert_store.register(signing_cert)

    signature_mechanism = SignedDigestAlgorithm(
        {
            "algorithm": ML_DSA_65_OID,
        }
    )

    return signers.ExternalSigner(
        signing_cert=signing_cert,
        cert_registry=cert_store,
        signature_value=signature_value,
        signature_mechanism=signature_mechanism,
    )

def _signature_record_exists(signing_request_id):
    return SignatureRecord.objects.filter(
        signing_request_id=signing_request_id
    ).exists()


def _read_prepared_pdf_bytes(session_id):
    session = ClientPadesSession.objects.get(pk=session_id)
    with session.prepared_pdf.open("rb") as f:
        return f.read()

def _get_timestamper():
    """
    Muốn nhúng timestamp vào unsignedAttrs của CMS thì pyHanko cần TimeStamper.

    Cách dễ nhất: chạy TSA dạng HTTP và set:
    PYHANKO_TSA_URL = "http://tsa:8080/timestamp"

    Hiện tại nếu chưa có HTTP TSA thì return None.
    """
    tsa_url = getattr(settings, "PYHANKO_TSA_URL", "")
    if not tsa_url:
        return None

    return timestamps.HTTPTimeStamper(tsa_url)


def _get_active_cert(user) -> UserCertificate:
    user_cert = UserCertificate.objects.filter(
        user=user,
        status=UserCertificate.Status.ACTIVE,
    ).first()

    if not user_cert:
        raise ValueError("Active signer certificate not found.")

    if not user_cert.certificate_pem:
        raise ValueError("Signer certificate PEM is missing.")

    return user_cert

def _reload_signing_request(signing_request_id):
    return (
        SigningRequest.objects
        .select_related("document", "signer")
        .get(pk=signing_request_id)
    )


def _save_prepared_session(
    signing_request_id,
    field_name,
    prepared_pdf_hash,
    document_digest,
    signed_attrs_b64,
    prepared_digest_blob,
    bytes_reserved,
    digest_algorithm,
    prepared_pdf_bytes,
):
    signing_request = _reload_signing_request(signing_request_id)

    session, _ = ClientPadesSession.objects.update_or_create(
        signing_request=signing_request,
        defaults={
            "field_name": field_name,
            "prepared_pdf_sha256": prepared_pdf_hash,
            "document_digest": document_digest,
            "signed_attrs_b64": signed_attrs_b64,
            "prepared_digest_blob": prepared_digest_blob,
            "bytes_reserved": bytes_reserved,
            "digest_algorithm": digest_algorithm,
            "status": ClientPadesSession.Status.PREPARED,
            "error_message": "",
        },
    )

    document = signing_request.document

    session.prepared_pdf.save(
        f"document_{document.id}_request_{signing_request.id}_prepared.pdf",
        ContentFile(prepared_pdf_bytes),
        save=True,
    )

    return session


def _get_session_by_request_id(signing_request_id):
    return ClientPadesSession.objects.get(signing_request_id=signing_request_id)


def _save_finished_client_pades_result(
    signing_request_id,
    session_id,
    user_cert_id,
    signature_b64,
    signed_pdf_bytes,
    signed_pdf_hash,
):
    signing_request = _reload_signing_request(signing_request_id)
    session = ClientPadesSession.objects.get(pk=session_id)
    user_cert = UserCertificate.objects.get(pk=user_cert_id)
    document = signing_request.document

    document.current_signed_pdf.save(
        f"document_{document.id}_citizen_pades_request_{signing_request.id}.pdf",
        ContentFile(signed_pdf_bytes),
        save=False,
    )

    document.current_signed_pdf_sha256 = signed_pdf_hash
    document.status = Document.Status.PENDING_SIGN
    document.save(update_fields=[
        "current_signed_pdf",
        "current_signed_pdf_sha256",
        "status",
        "updated_at",
    ])

    signature_record = SignatureRecord.objects.create(
        signing_request=signing_request,
        signature_value=signature_b64,
        certificate_pem=user_cert.certificate_pem,
        certificate_subject=user_cert.certificate_subject,
        certificate_serial=user_cert.certificate_serial,
        algorithm="ML-DSA-65",
        signed_hash=session.document_digest,
        timestamp_status="embedded" if _get_timestamper() else "not_embedded",
        timestamp_message=(
            "Client PAdES created using server-prepared ByteRange and signedAttrs. "
            f"current_signed_pdf_sha256={signed_pdf_hash}"
        ),
    )

    signing_request.status = SigningRequest.Status.SIGNED
    signing_request.used_at = timezone.now()
    signing_request.completed_at = signature_record.signed_at
    signing_request.client_token = None
    signing_request.client_token_expires_at = None
    signing_request.save(update_fields=[
        "status",
        "used_at",
        "completed_at",
        "client_token",
        "client_token_expires_at",
    ])

    session.status = ClientPadesSession.Status.COMPLETED
    session.completed_at = timezone.now()
    session.save(update_fields=["status", "completed_at"])

    return signature_record

async def _async_prepare_client_pades_session(signing_request: SigningRequest) -> ClientPadesSession:
    if signing_request.signing_type != SigningRequest.SigningType.CLIENT:
        raise ValueError("This is not a client signing request.")

    if signing_request.status != SigningRequest.Status.PENDING:
        raise ValueError("Signing request is not pending.")

    document = signing_request.document

    if not document.file:
        raise ValueError("Document file not found.")

    input_pdf_path = Path(document.file.path)

    if input_pdf_path.suffix.lower() != ".pdf":
        raise ValueError("Client-side PAdES only supports PDF files.")

    user_cert = await sync_to_async(_get_active_cert, thread_sensitive=True)(
        signing_request.signer
    )

    field_name = f"Sig_citizen_{signing_request.id}"

    dummy_signature = bytes(ML_DSA_65_SIGNATURE_SIZE)
    ext_signer = _build_external_signer(
        user_cert=user_cert,
        signature_value=dummy_signature,
    )

    pdf_signature_metadata = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm=CLIENT_PADES_DIGEST_ALGORITHM,
        subfilter=fields.SigSeedSubFilter.PADES,

        # Không dùng certification signature cho citizen để tránh DocMDP phức tạp.
        # Officer sẽ ký approval signature ở incremental revision sau.
        certify=False,
    )

    pdf_signer = signers.PdfSigner(
        pdf_signature_metadata,
        signer=ext_signer,
        timestamper=_get_timestamper(),
    )

    output = BytesIO()

    with open(input_pdf_path, "rb") as inf:
        writer = IncrementalPdfFileWriter(inf)

        prep_digest, tbs_document, output_handle = await pdf_signer.async_digest_doc_for_signing(
            writer,
            bytes_reserved=CLIENT_PADES_BYTES_RESERVED,
            output=output,
        )

    signed_attrs = await ext_signer.signed_attrs(
        prep_digest.document_digest,
        CLIENT_PADES_DIGEST_ALGORITHM,
        use_pades=True,
    )

    prepared_pdf_bytes = output_handle.getvalue()
    prepared_pdf_hash = sha256(prepared_pdf_bytes).hexdigest()

    session = await sync_to_async(_save_prepared_session, thread_sensitive=True)(
        signing_request.id,
        field_name,
        prepared_pdf_hash,
        prep_digest.document_digest.hex(),
        base64.b64encode(signed_attrs.dump()).decode("utf-8"),
        pickle.dumps(prep_digest),
        CLIENT_PADES_BYTES_RESERVED,
        CLIENT_PADES_DIGEST_ALGORITHM,
        prepared_pdf_bytes,
    )
    return session


def prepare_client_pades_session(signing_request: SigningRequest) -> ClientPadesSession:
    signing_request = _reload_signing_request(signing_request.id)
    return asyncio.run(_async_prepare_client_pades_session(signing_request))


async def _async_finish_client_pades_session(
    signing_request: SigningRequest,
    signature_b64: str,
) -> SignatureRecord:
    if signing_request.signing_type != SigningRequest.SigningType.CLIENT:
        raise ValueError("This is not a client signing request.")

    if signing_request.status != SigningRequest.Status.PENDING:
        raise ValueError("Signing request is not pending.")

    signature_exists = await sync_to_async(
        _signature_record_exists,
        thread_sensitive=True,
    )(signing_request.id)

    if signature_exists:
        raise ValueError("This signing request already has a signature record.")

    session = await sync_to_async(_get_session_by_request_id, thread_sensitive=True)(
        signing_request.id
    )

    if session.status != ClientPadesSession.Status.PREPARED:
        raise ValueError("Client PAdES session is not prepared.")

    user_cert = await sync_to_async(_get_active_cert, thread_sensitive=True)(
        signing_request.signer
    )

    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception:
        raise ValueError("Invalid base64 signature.")

    signed_attrs_der = base64.b64decode(session.signed_attrs_b64)

    # BẮT BUỘC: server verify chữ ký trước khi nhúng vào PDF.
    ok = mldsa_verify_with_cert_pem(
        cert_pem=user_cert.certificate_pem,
        data=signed_attrs_der,
        signature=signature_bytes,
    )

    if not ok:
        raise ValueError("ML-DSA signature over PAdES signedAttrs failed verification.")

    signed_attrs = cms.CMSAttributes.load(signed_attrs_der)
    prepared_digest = pickle.loads(session.prepared_digest_blob)

    ext_signer = _build_external_signer(
        user_cert=user_cert,
        signature_value=signature_bytes,
    )

    sig_cms = await ext_signer.async_sign_prescribed_attributes(
        CLIENT_PADES_DIGEST_ALGORITHM,
        signed_attrs=signed_attrs,
        timestamper=_get_timestamper(),
    )

    prepared_pdf_bytes = await sync_to_async(
        _read_prepared_pdf_bytes,
        thread_sensitive=True,
    )(session.id)

    output = BytesIO(prepared_pdf_bytes)

    # Nếu chưa làm PAdES-LT/LTA post processing, dùng fill_with_cms là đủ cho B/T demo.
    prepared_digest.fill_with_cms(output, sig_cms)

    signed_pdf_bytes = output.getvalue()
    signed_pdf_hash = sha256(signed_pdf_bytes).hexdigest()

    signature_record = await sync_to_async(
        _save_finished_client_pades_result,
        thread_sensitive=True,
    )(
        signing_request.id,
        session.id,
        user_cert.id,
        signature_b64,
        signed_pdf_bytes,
        signed_pdf_hash,
    )

    return signature_record


def finish_client_pades_session(
    signing_request: SigningRequest,
    signature_b64: str,
) -> SignatureRecord:
    signing_request = _reload_signing_request(signing_request.id)

    return asyncio.run(
        _async_finish_client_pades_session(
            signing_request=signing_request,
            signature_b64=signature_b64,
        )
    )