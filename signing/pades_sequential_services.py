import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings

from accounts.models import User, UserCertificate
from signing.artifact_services import get_signature_artifact_dir
from signing.pades_services import create_pades_signature
from documents.services import calculate_sha256_path

def _resolve_private_key_path(private_key_path):
    key_path = Path(private_key_path)
    if not key_path.is_absolute():
        key_path = Path(settings.BASE_DIR) / key_path
    return key_path


def _get_input_pdf_for_next_signature(document):
    """
    Citizen signs original PDF.
    Officer signs the latest already-signed PDF.
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


def create_sequential_pades_for_signature_record(signature_record):
    """
    Creates one sequential PAdES PDF.

    Citizen signature:
      original.pdf -> current_signed_pdf

    Officer signature:
      current_signed_pdf -> final_signed_pdf
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

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            signer_cert_path = tmpdir / "signer_certificate.pem"
            signer_cert_path.write_text(user_cert.certificate_pem, encoding="utf-8")

            result = create_pades_signature(
                input_pdf_path=str(input_pdf_path),
                signer_cert_path=str(signer_cert_path),
                signer_key_path=str(key_path),
                output_pdf_path=str(output_pdf_path),
                ca_cert_path=str(settings.PKI_ROOT_CA_CERT),
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

    # Save status into this signature's artifact folder
    (artifact_pades_dir / "pades_status.txt").write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if result.get("ok"):
        # Keep per-signature package compatibility
        shutil.copyfile(output_pdf_path, artifact_pades_dir / "signed_document.pdf")

        rel_path = output_pdf_path.relative_to(settings.MEDIA_ROOT)

        # Sau mỗi lần ký, current_signed_pdf là bản mới nhất.
        document.current_signed_pdf.name = str(rel_path)

        update_fields = ["current_signed_pdf"]

        if role_name == "officer":
            document.final_signed_pdf.name = str(rel_path)
            update_fields.append("final_signed_pdf")

            # Chỉ áp dụng Mức 3 cho luồng 2: citizen tự điền form.
            if document.form_type == "citizen_generated_form":
                final_pdf_hash = calculate_sha256_path(output_pdf_path)

                document.final_signed_pdf_sha256 = final_pdf_hash
                update_fields.append("final_signed_pdf_sha256")

                result["final_signed_pdf_sha256"] = final_pdf_hash

        document.save(update_fields=update_fields)

    return result