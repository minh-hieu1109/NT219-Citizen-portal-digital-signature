import base64
import hashlib
import json
from pathlib import Path

from django.conf import settings

from signing.models import SignatureRecord
from verification.models import ValidationEvidence


def _safe_read_text(path: Path) -> str:
    try:
        if path.exists():
            return path.read_text(encoding="utf-8")
    except Exception:
        return ""
    return ""


def _compute_evidence_hash(payload: dict) -> str:
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def archive_validation_evidence(signature_record: SignatureRecord, ocsp_result: dict | None = None) -> ValidationEvidence:
    root_ca_pem = _safe_read_text(Path(settings.PKI_ROOT_CA_CERT))
    crl_pem = _safe_read_text(Path(settings.PKI_CRL_DIR) / "lab_ca.crl.pem")

    ocsp_response_b64 = ""
    if ocsp_result:
        raw_message = ocsp_result.get("message", "")
        if raw_message:
            ocsp_response_b64 = base64.b64encode(raw_message.encode("utf-8")).decode("utf-8")

    payload_for_hash = {
        "signature_record_id": signature_record.id,
        "signer_certificate_pem": signature_record.certificate_pem or "",
        "certificate_chain_pem": root_ca_pem,
        "crl_pem": crl_pem,
        "ocsp_response_base64": ocsp_response_b64,
        "timestamp_token_base64": signature_record.timestamp_token or "",
        "ocsp_status": (ocsp_result or {}).get("status", "missing"),
    }
    evidence_hash = _compute_evidence_hash(payload_for_hash)

    evidence, _ = ValidationEvidence.objects.update_or_create(
        signature_record=signature_record,
        defaults={
            "signer_certificate_pem": signature_record.certificate_pem or "",
            "certificate_chain_pem": root_ca_pem,
            "crl_pem": crl_pem,
            "ocsp_response_base64": ocsp_response_b64,
            "timestamp_token_base64": signature_record.timestamp_token or "",
            "evidence_hash": evidence_hash,
            "detail": {
                "ocsp_status": (ocsp_result or {}).get("status", "missing"),
                "ocsp_message": (ocsp_result or {}).get("message", ""),
                "has_root_ca_chain": bool(root_ca_pem),
                "has_crl": bool(crl_pem),
                "has_timestamp": bool(signature_record.timestamp_token),
            },
        },
    )
    return evidence


def verify_ltv(signature_record: SignatureRecord) -> dict:
    try:
        evidence = signature_record.validation_evidence
    except ValidationEvidence.DoesNotExist:
        return {
            "valid": False,
            "evidence_exists": False,
            "evidence_hash_valid": False,
            "has_timestamp": False,
            "has_certificate": False,
            "has_ocsp_or_crl": False,
            "detail": {"message": "Validation evidence is missing."},
        }

    payload_for_hash = {
        "signature_record_id": signature_record.id,
        "signer_certificate_pem": evidence.signer_certificate_pem or "",
        "certificate_chain_pem": evidence.certificate_chain_pem or "",
        "crl_pem": evidence.crl_pem or "",
        "ocsp_response_base64": evidence.ocsp_response_base64 or "",
        "timestamp_token_base64": evidence.timestamp_token_base64 or "",
        "ocsp_status": evidence.detail.get("ocsp_status", "missing"),
    }
    computed_hash = _compute_evidence_hash(payload_for_hash)
    hash_valid = computed_hash == (evidence.evidence_hash or "")

    has_certificate = bool(evidence.signer_certificate_pem)
    has_timestamp = bool(evidence.timestamp_token_base64)
    has_ocsp_or_crl = bool(evidence.ocsp_response_base64 or evidence.crl_pem)

    return {
        "valid": bool(hash_valid and has_certificate),
        "evidence_exists": True,
        "evidence_hash_valid": hash_valid,
        "has_timestamp": has_timestamp,
        "has_certificate": has_certificate,
        "has_ocsp_or_crl": has_ocsp_or_crl,
        "detail": {
            "archived_at": evidence.archived_at.isoformat(),
            "stored_evidence_hash": evidence.evidence_hash,
            "computed_evidence_hash": computed_hash,
            "ocsp_status": evidence.detail.get("ocsp_status", "missing"),
        },
    }
