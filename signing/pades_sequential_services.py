import asyncio
import json
import shutil
import subprocess
import tempfile
from io import BytesIO
from pathlib import Path

from asn1crypto import cms
from asn1crypto.algos import SignedDigestAlgorithm
from django.conf import settings
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko_certvalidator.registry import SimpleCertificateStore

from accounts.models import User, UserCertificate
from documents.services import calculate_sha256_path
from signing.artifact_services import get_signature_artifact_dir
from signing.mldsa_openssl import mldsa_verify_with_cert_pem


ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18"
ML_DSA_65_SIGNATURE_SIZE = 3309

PADES_BYTES_RESERVED = 65536
PADES_DIGEST_ALGORITHM = "sha512"


def _resolve_private_key_path(private_key_path):
    key_path = Path(private_key_path)

    if not key_path.is_absolute():
        key_path = Path(settings.BASE_DIR) / key_path

    return key_path


def _get_input_pdf_for_next_signature(document):
    """
    Citizen signs original PDF.
    Officer signs the latest already-signed PDF.

    Với flow hiện tại:
    - Citizen client PAdES tạo current_signed_pdf.
    - Officer ký tiếp trên current_signed_pdf để tạo final_signed_pdf.
    """
    if document.current_signed_pdf:
        current_path = Path(document.current_signed_pdf.path)
        if current_path.exists():
            return current_path

    return Path(document.file.path)


def _get_role_name(signature_record):
    signer = signature_record.signing_request.signer
    document = signature_record.signing_request.document

    if signer and signer.id == document.owner_id:
        return "citizen"

    if signer and signer.role in {User.Role.OFFICER, User.Role.ADMIN}:
        return "officer"

    return "signer"


def _load_cert_from_pem_text(certificate_pem: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "signer_certificate.pem"
        cert_path.write_text(certificate_pem, encoding="utf-8")
        return load_cert_from_pemder(str(cert_path))


def _build_external_mldsa_signer(user_cert, signature_value: bytes):
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


def _get_timestamper():
    """
    Nếu sau này có HTTP TSA thì set trong settings.py:

        PYHANKO_TSA_URL = "http://tsa:8080/timestamp"

    Hiện chưa có thì return None, chữ ký vẫn tạo được nhưng chưa embedded timestamp.
    """
    tsa_url = getattr(settings, "PYHANKO_TSA_URL", "")

    if not tsa_url:
        return None

    return timestamps.HTTPTimeStamper(tsa_url)


def _sign_bytes_with_openssl_mldsa(private_key_path: Path, data: bytes) -> bytes:
    private_key_path = Path(private_key_path)

    if not private_key_path.exists():
        raise ValueError(f"Signer private key not found: {private_key_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        data_path = tmpdir / "signed_attrs.der"
        sig_path = tmpdir / "signature.bin"

        data_path.write_bytes(data)

        proc = subprocess.run(
            [
                str(settings.PKI_OPENSSL_BIN),
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key_path),
                "-rawin",
                "-in",
                str(data_path),
                "-out",
                str(sig_path),
            ],
            capture_output=True,
            text=True,
        )

        if proc.returncode != 0:
            raise ValueError(
                "OpenSSL ML-DSA signing failed.\n"
                f"STDOUT:\n{proc.stdout}\n"
                f"STDERR:\n{proc.stderr}"
            )

        return sig_path.read_bytes()


def _write_pkcs11_config(user_cert, config_path):
    """
    pyHanko config for PKCS#11 signer.
    Cert object must exist in SoftHSM with the same label as key label.
    """
    config_path.write_text(
        f"""
pkcs11-setups:
  signer-setup:
    module-path: {settings.PKCS11_LIB_PATH}
    token-criteria:
      label: {user_cert.pkcs11_token_label or settings.PKCS11_TOKEN_LABEL}
    cert-label: {user_cert.pkcs11_key_label}
    key-label: {user_cert.pkcs11_key_label}
    user-pin: {settings.PKCS11_TOKEN_PIN}

validation-contexts:
  lab:
    trust: {settings.PKI_ROOT_CA_CERT}
    trust-replace: true
    signer-key-usage: ["digital_signature", "non_repudiation"]
""".strip(),
        encoding="utf-8",
    )


def create_pades_signature_softhsm(
    input_pdf_path,
    output_pdf_path,
    user_cert,
    field_name,
):
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        config_path = tmpdir / "pyhanko.yml"

        _write_pkcs11_config(user_cert, config_path)

        cmd = [
            "pyhanko",
            "--config",
            str(config_path),
            "sign",
            "addsig",
            "--no-strict-syntax",
            "--field",
            field_name,
            "--use-pades",
            "pkcs11",
            "--p11-setup",
            "signer-setup",
            str(input_pdf_path),
            str(output_pdf_path),
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)

        return {
            "ok": proc.returncode == 0,
            "status": "created" if proc.returncode == 0 else "error",
            "message": (
                "Sequential PAdES signature created with SoftHSM."
                if proc.returncode == 0
                else "Sequential PAdES SoftHSM signing failed."
            ),
            "command": " ".join(cmd),
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "output_pdf": str(output_pdf_path),
        }


async def _async_create_pades_signature_external_mldsa(
    input_pdf_path,
    output_pdf_path,
    user_cert,
    private_key_path,
    field_name,
):
    input_pdf_path = Path(input_pdf_path)
    output_pdf_path = Path(output_pdf_path)
    private_key_path = Path(private_key_path)

    if not input_pdf_path.exists():
        return {
            "ok": False,
            "status": "error",
            "message": f"Input PDF not found: {input_pdf_path}",
        }

    if input_pdf_path.suffix.lower() != ".pdf":
        return {
            "ok": False,
            "status": "skipped",
            "message": "Sequential PAdES only supports PDF files.",
        }

    if not user_cert.certificate_pem:
        return {
            "ok": False,
            "status": "error",
            "message": "Signer certificate PEM is missing.",
        }

    try:
        dummy_signature = bytes(ML_DSA_65_SIGNATURE_SIZE)

        dummy_signer = _build_external_mldsa_signer(
            user_cert=user_cert,
            signature_value=dummy_signature,
        )

        pdf_signature_metadata = signers.PdfSignatureMetadata(
            field_name=field_name,
            md_algorithm=PADES_DIGEST_ALGORITHM,
            subfilter=fields.SigSeedSubFilter.PADES,
            certify=False,
        )

        pdf_signer = signers.PdfSigner(
            pdf_signature_metadata,
            signer=dummy_signer,
            timestamper=_get_timestamper(),
        )

        output = BytesIO()

        with open(input_pdf_path, "rb") as inf:
            writer = IncrementalPdfFileWriter(inf)

            prep_digest, tbs_document, output_handle = (
                await pdf_signer.async_digest_doc_for_signing(
                    writer,
                    bytes_reserved=PADES_BYTES_RESERVED,
                    output=output,
                )
            )

        signed_attrs = await dummy_signer.signed_attrs(
            prep_digest.document_digest,
            PADES_DIGEST_ALGORITHM,
            use_pades=True,
        )

        signed_attrs_der = signed_attrs.dump()

        signature_bytes = _sign_bytes_with_openssl_mldsa(
            private_key_path=private_key_path,
            data=signed_attrs_der,
        )

        verify_ok = mldsa_verify_with_cert_pem(
            cert_pem=user_cert.certificate_pem,
            data=signed_attrs_der,
            signature=signature_bytes,
        )

        if not verify_ok:
            return {
                "ok": False,
                "status": "error",
                "message": "ML-DSA signature over PAdES signedAttrs failed verification.",
            }

        real_signer = _build_external_mldsa_signer(
            user_cert=user_cert,
            signature_value=signature_bytes,
        )

        sig_cms = await real_signer.async_sign_prescribed_attributes(
            PADES_DIGEST_ALGORITHM,
            signed_attrs=cms.CMSAttributes.load(signed_attrs_der),
            timestamper=_get_timestamper(),
        )

        prepared_pdf_bytes = output_handle.getvalue()
        final_output = BytesIO(prepared_pdf_bytes)

        prep_digest.fill_with_cms(final_output, sig_cms)

        output_pdf_path.parent.mkdir(parents=True, exist_ok=True)
        output_pdf_path.write_bytes(final_output.getvalue())

        return {
            "ok": True,
            "status": "created",
            "message": "Sequential PAdES signature created with external ML-DSA signing.",
            "output_pdf": str(output_pdf_path),
            "field_name": field_name,
            "digest_algorithm": PADES_DIGEST_ALGORITHM,
            "document_digest": prep_digest.document_digest.hex(),
            "signature_size": len(signature_bytes),
            "timestamp_embedded": bool(_get_timestamper()),
        }

    except Exception as exc:
        return {
            "ok": False,
            "status": "error",
            "message": f"Sequential PAdES external ML-DSA signing failed: {str(exc)}",
        }


def create_pades_signature_external_mldsa(
    input_pdf_path,
    output_pdf_path,
    user_cert,
    private_key_path,
    field_name,
):
    return asyncio.run(
        _async_create_pades_signature_external_mldsa(
            input_pdf_path=input_pdf_path,
            output_pdf_path=output_pdf_path,
            user_cert=user_cert,
            private_key_path=private_key_path,
            field_name=field_name,
        )
    )


def create_sequential_pades_for_signature_record(signature_record):
    """
    Creates one sequential PAdES PDF.

    Citizen signature:
      original.pdf -> current_signed_pdf

    Officer signature:
      current_signed_pdf -> final_signed_pdf

    Với ML-DSA FILE key:
      không dùng pyHanko CLI pemder --key.
      dùng pyHanko external signing + OpenSSL pkeyutl ML-DSA.
    """
    signing_request = signature_record.signing_request
    document = signing_request.document
    signer = signing_request.signer

    if not document.file:
        return {
            "ok": False,
            "status": "skipped",
            "message": "Document file not found.",
        }

    input_pdf_path = _get_input_pdf_for_next_signature(document)

    if input_pdf_path.suffix.lower() != ".pdf":
        return {
            "ok": False,
            "status": "skipped",
            "message": "Sequential PAdES only supports PDF files.",
        }

    user_cert = UserCertificate.objects.filter(
        user=signer,
        status=UserCertificate.Status.ACTIVE,
    ).first()

    if not user_cert:
        return {
            "ok": False,
            "status": "error",
            "message": "Active signer certificate not found.",
        }

    role_name = _get_role_name(signature_record)
    field_name = f"Sig_{role_name}_{signature_record.id}"

    output_dir = (
        Path(settings.MEDIA_ROOT)
        / "documents"
        / "pades"
        / f"document_{document.id}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    if role_name == "officer":
        output_pdf_path = output_dir / "final_signed_document.pdf"
    else:
        output_pdf_path = output_dir / f"v1_citizen_signed_{signature_record.id}.pdf"

    artifact_dir = get_signature_artifact_dir(signature_record)
    artifact_pades_dir = artifact_dir / "pades"
    artifact_pades_dir.mkdir(parents=True, exist_ok=True)

    if user_cert.key_storage_type == UserCertificate.KeyStorageType.FILE:
        key_path = _resolve_private_key_path(user_cert.private_key_path)

        result = create_pades_signature_external_mldsa(
            input_pdf_path=input_pdf_path,
            output_pdf_path=output_pdf_path,
            user_cert=user_cert,
            private_key_path=key_path,
            field_name=field_name,
        )

    elif user_cert.key_storage_type == UserCertificate.KeyStorageType.SOFTHSM:
        result = create_pades_signature_softhsm(
            input_pdf_path=input_pdf_path,
            output_pdf_path=output_pdf_path,
            user_cert=user_cert,
            field_name=field_name,
        )

    else:
        result = {
            "ok": False,
            "status": "error",
            "message": f"Unsupported key storage type: {user_cert.key_storage_type}",
        }

    if result.get("ok"):
        shutil.copyfile(output_pdf_path, artifact_pades_dir / "signed_document.pdf")

        rel_path = output_pdf_path.relative_to(settings.MEDIA_ROOT)

        document.current_signed_pdf.name = str(rel_path)
        update_fields = ["current_signed_pdf"]

        current_pdf_hash = calculate_sha256_path(output_pdf_path)

        if hasattr(document, "current_signed_pdf_sha256"):
            document.current_signed_pdf_sha256 = current_pdf_hash
            update_fields.append("current_signed_pdf_sha256")
            result["current_signed_pdf_sha256"] = current_pdf_hash

        if role_name == "officer":
            document.final_signed_pdf.name = str(rel_path)
            update_fields.append("final_signed_pdf")

            final_pdf_hash = calculate_sha256_path(output_pdf_path)
            document.final_signed_pdf_sha256 = final_pdf_hash
            update_fields.append("final_signed_pdf_sha256")

            result["final_signed_pdf_sha256"] = final_pdf_hash

        document.save(update_fields=update_fields)

    (artifact_pades_dir / "pades_status.txt").write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result