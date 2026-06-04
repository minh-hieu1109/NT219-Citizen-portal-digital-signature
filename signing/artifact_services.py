import base64
import json
import tempfile
from pathlib import Path

from django.conf import settings

from accounts.models import UserCertificate
from signing.cms_services import create_cms_detached_signature
from signing.pades_services import create_pades_signature
import subprocess

def get_signature_artifact_dir(signature_record):
    return (
        Path(settings.MEDIA_ROOT)
        / "signature_artifacts"
        / f"signature_{signature_record.id}"
    )


def _resolve_private_key_path(private_key_path):
    key_path = Path(private_key_path)

    if not key_path.is_absolute():
        key_path = Path(settings.BASE_DIR) / key_path

    return key_path


def generate_signature_artifacts(signature_record):
    """
    Production-like behavior:
    generate RAW/CAdES/PAdES artifacts immediately after signing,
    not when downloading the package.
    """

    signing_request = signature_record.signing_request
    document = signing_request.document
    signer = signing_request.signer

    artifact_dir = get_signature_artifact_dir(signature_record)
    signature_dir = artifact_dir / "signature"
    certs_dir = artifact_dir / "certs"
    pades_dir = artifact_dir / "pades"
    timestamp_dir = artifact_dir / "timestamp"

    signature_dir.mkdir(parents=True, exist_ok=True)
    certs_dir.mkdir(parents=True, exist_ok=True)
    pades_dir.mkdir(parents=True, exist_ok=True)
    timestamp_dir.mkdir(parents=True, exist_ok=True)

    result = {
        "ok": True,
        "signature_record_id": signature_record.id,
        "raw": {"ok": False, "message": ""},
        "cades": {"ok": False, "message": ""},
        "pades": {"ok": False, "message": ""},
    }

    # 1. RAW signature artifact
    try:
        (signature_dir / "signature.sig").write_text(
            signature_record.signature_value,
            encoding="utf-8",
        )
        result["raw"] = {
            "ok": True,
            "message": "RAW signature artifact created.",
            "file": "signature/signature.sig",
        }
    except Exception as exc:
        result["raw"] = {
            "ok": False,
            "message": f"RAW signature artifact failed: {exc}",
        }
        result["ok"] = False

    # 2. Certificate artifacts
    try:
        (certs_dir / "signer_certificate.pem").write_text(
            signature_record.certificate_pem or "",
            encoding="utf-8",
        )

        ca_cert_path = Path(settings.PKI_ROOT_CA_CERT)
        if ca_cert_path.exists():
            (certs_dir / "ca_certificate.pem").write_bytes(ca_cert_path.read_bytes())
    except Exception as exc:
        result["certificate_warning"] = str(exc)

    # 3. Timestamp artifact
    if signature_record.timestamp_token:
        try:
            timestamp_bytes = base64.b64decode(signature_record.timestamp_token)
            (timestamp_dir / "timestamp.tsr").write_bytes(timestamp_bytes)
        except Exception:
            (timestamp_dir / "timestamp_token_base64.txt").write_text(
                signature_record.timestamp_token,
                encoding="utf-8",
            )

    # 4. Resolve signer private key for CAdES/PAdES demo
    signer_cert_profile = UserCertificate.objects.filter(
        user=signer,
        status=UserCertificate.Status.ACTIVE,
    ).first()

    key_path = None
    key_error = ""

    if not signer_cert_profile:
        key_error = "Active signer certificate profile not found."

    elif signer_cert_profile.key_storage_type == UserCertificate.KeyStorageType.FILE:
        if not signer_cert_profile.private_key_path:
            key_error = "Signer private key path is not available."
        else:
            key_path = _resolve_private_key_path(signer_cert_profile.private_key_path)

            if not key_path.exists():
                key_error = f"Signer private key not found: {key_path}"
                key_path = None

    elif signer_cert_profile.key_storage_type == UserCertificate.KeyStorageType.SOFTHSM:
        if not signer_cert_profile.pkcs11_token_label:
            key_error = "PKCS#11 token label is missing."
        elif not signer_cert_profile.pkcs11_key_label:
            key_error = "PKCS#11 key label is missing."
        else:
            key_error = ""

    else:
        key_error = f"Unsupported key storage type: {signer_cert_profile.key_storage_type}"

        # if not key_path.exists():
        #     key_error = f"Signer private key not found: {key_path}"
        #     key_path = None

    # 5. CAdES/CMS artifact
    try:
        if key_error:
            result["cades"] = {
                "ok": False,
                "message": key_error,
            }

        else:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmpdir = Path(tmpdir)

                signer_cert_path = tmpdir / "signer_certificate.pem"
                signer_cert_path.write_text(
                    signature_record.certificate_pem,
                    encoding="utf-8",
                )

                cms_signature_path = signature_dir / "signature.p7s"

                if signer_cert_profile.key_storage_type == UserCertificate.KeyStorageType.FILE:
                    cms_result = create_cms_detached_signature(
                        input_file=document.file.path,
                        signer_cert_path=str(signer_cert_path),
                        signer_key_path=str(key_path),
                        ca_cert_path=str(settings.PKI_ROOT_CA_CERT),
                        output_path=str(cms_signature_path),
                    )

                elif signer_cert_profile.key_storage_type == UserCertificate.KeyStorageType.SOFTHSM:
                    cms_result = create_cms_detached_signature_softhsm(
                        input_file=document.file.path,
                        signer_cert_path=str(signer_cert_path),
                        token_label=signer_cert_profile.pkcs11_token_label,
                        key_label=signer_cert_profile.pkcs11_key_label,
                        output_path=str(cms_signature_path),
                    )

                else:
                    cms_result = {
                        "ok": False,
                        "message": f"Unsupported key storage type: {signer_cert_profile.key_storage_type}",
                    }

                result["cades"] = cms_result

                if cms_result.get("ok"):
                    result["cades"]["file"] = "signature/signature.p7s"
                else:
                    result["ok"] = False

    except Exception as exc:
        result["cades"] = {
            "ok": False,
            "message": f"CAdES generation failed: {exc}",
        }
        result["ok"] = False

    (signature_dir / "cms_status.txt").write_text(
        json.dumps(result["cades"], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    # 6. PAdES artifact
    # try:
    #     document_path = Path(document.file.path)

    #     if document_path.suffix.lower() != ".pdf":
    #         result["pades"] = {
    #             "ok": False,
    #             "status": "skipped",
    #             "message": "PAdES skipped because document is not a PDF.",
    #         }
    #     elif not key_path:
    #         result["pades"] = {
    #             "ok": False,
    #             "status": "skipped",
    #             "message": key_error,
    #         }
    #     else:
    #         with tempfile.TemporaryDirectory() as tmpdir:
    #             tmpdir = Path(tmpdir)

    #             signer_cert_path = tmpdir / "signer_certificate.pem"
    #             signer_cert_path.write_text(
    #                 signature_record.certificate_pem,
    #                 encoding="utf-8",
    #             )

    #             signed_pdf_path = pades_dir / "signed_document.pdf"

    #             pades_result = create_pades_signature(
    #                 input_pdf_path=str(document_path),
    #                 signer_cert_path=str(signer_cert_path),
    #                 signer_key_path=str(key_path),
    #                 output_pdf_path=str(signed_pdf_path),
    #                 ca_cert_path=str(settings.PKI_ROOT_CA_CERT),
    #             )

    #             result["pades"] = pades_result

    #             if pades_result.get("ok"):
    #                 result["pades"]["file"] = "pades/signed_document.pdf"
    #             else:
    #                 result["ok"] = False

    # except Exception as exc:
    #     result["pades"] = {
    #         "ok": False,
    #         "status": "error",
    #         "message": f"PAdES generation failed: {exc}",
    #     }
    #     result["ok"] = False

    # (pades_dir / "pades_status.txt").write_text(
    #     json.dumps(result["pades"], indent=2, ensure_ascii=False),
    #     encoding="utf-8",
    # )
    result["pades"] = {
        "ok": False,
        "status": "skipped",
        "message": (
            "PAdES is handled by sequential PAdES service. "
            "This artifact generator only creates RAW/CAdES package."
        ),
    }

    (pades_dir / "pades_status.txt").write_text(
        json.dumps(result["pades"], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # 7. Metadata artifact
    metadata = {
        "signature_record_id": signature_record.id,
        "signing_request_id": signing_request.id,
        "document_title": document.title,
        "document_sha256": document.sha256_hash,
        "signed_hash": signature_record.signed_hash,
        "signature_format": "RAW + CAdES/CMS detached + PAdES PDF",
        "signature_encoding": "base64",
        "algorithm": signature_record.algorithm,
        "signer_email": signer.email if signer else "",
        "requester_email": signing_request.requested_by.email,
        "certificate_subject": signature_record.certificate_subject,
        "certificate_serial": signature_record.certificate_serial,
        "signed_at": signature_record.signed_at.isoformat(),
        "timestamp_status": signature_record.timestamp_status,
        "timestamp_message": signature_record.timestamp_message,
        "raw_signature_file": "signature/signature.sig",
        "cms_signature_file": "signature/signature.p7s",
        "cms_signature_created": bool(result["cades"].get("ok")),
        "cms_signature_message": result["cades"].get("message", ""),
        "pades_signed_pdf_file": "pades/signed_document.pdf",
        "pades_signature_created": bool(result["pades"].get("ok")),
        "pades_signature_message": result["pades"].get("message", ""),
    }

    (artifact_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    (artifact_dir / "artifact_status.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result

def create_cms_detached_signature_softhsm(
    input_file,
    signer_cert_path,
    token_label,
    key_label,
    output_path,
):
    """
    Create CMS/CAdES detached signature using SoftHSM private key via OpenSSL PKCS#11 engine.
    """
    openssl_bin = str(getattr(settings, "PKI_OPENSSL_BIN", "openssl") or "openssl")

    pkcs11_uri = (
        f"pkcs11:token={token_label};"
        f"object={key_label};"
        f"type=private;"
        f"pin-value={settings.PKCS11_TOKEN_PIN}"
    )

    cmd = [
        openssl_bin,
        "cms",
        "-sign",
        "-binary",
        "-engine",
        "pkcs11",
        "-keyform",
        "engine",
        "-in",
        str(input_file),
        "-signer",
        str(signer_cert_path),
        "-inkey",
        pkcs11_uri,
        "-outform",
        "DER",
        "-out",
        str(output_path),
        "-nosmimecap",
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)

    message = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()

    if proc.returncode != 0:
        return {
            "ok": False,
            "status": "error",
            "message": message,
            "command": " ".join(cmd),
        }

    return {
        "ok": True,
        "status": "created",
        "message": "CAdES/CMS detached signature created using SoftHSM PKCS#11 key.",
        "file": "signature/signature.p7s",
        "command": " ".join(cmd),
    }