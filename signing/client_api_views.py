import base64
import hashlib
import json
import time

from django.http import JsonResponse, FileResponse
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from cryptography.hazmat.primitives import serialization

from .models import SigningRequest
from .services import (
    complete_client_signing_request,
    prepare_client_signing_request,
    hash_pairing_code,
)


def verify_device_binding(request, signing_request):
    """
    Verify that the current request is sent by the same local signer device
    that paired with this SigningRequest.

    This is NOT the ML-DSA document signature.
    This only protects the client_token from being reused by another device.
    """
    public_key_pem = signing_request.signer_device_public_key_pem

    if not public_key_pem:
        return False, "Missing paired device public key."

    timestamp = request.headers.get("X-Device-Timestamp", "")
    body_hash = request.headers.get("X-Device-Body-SHA256", "")
    signature_b64 = request.headers.get("X-Device-Signature", "")

    if not timestamp or not body_hash or not signature_b64:
        return False, "Missing device binding headers."

    try:
        ts = int(timestamp)
    except ValueError:
        return False, "Invalid device timestamp."

    if abs(int(time.time()) - ts) > 120:
        return False, "Device signature timestamp expired."

    actual_body_hash = hashlib.sha256(request.body or b"").hexdigest()
    if actual_body_hash != body_hash:
        return False, "Device body hash mismatch."

    message = "\n".join([
        request.method.upper(),
        request.path,
        timestamp,
        body_hash,
    ]).encode("utf-8")

    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )
        public_key.verify(
            base64.b64decode(signature_b64),
            message,
        )
    except Exception:
        return False, "Invalid device signature."

    return True, ""


def _get_request_by_client_session(request, request_id=None):
    """
    Get SigningRequest from internal client_token.

    After device pairing, every request using client_token must also contain
    device binding headers signed by the ephemeral device private key.
    """
    token = request.headers.get("X-Client-Signing-Session", "").strip()

    if not token:
        return None, JsonResponse(
            {"ok": False, "error": "Missing client signing session."},
            status=401,
        )

    qs = SigningRequest.objects.select_related("document", "signer").filter(
        client_token=token,
        signing_type=SigningRequest.SigningType.CLIENT,
        status=SigningRequest.Status.PENDING,
    )

    if request_id is not None:
        qs = qs.filter(id=request_id)

    signing_request = qs.first()

    if not signing_request:
        return None, JsonResponse(
            {"ok": False, "error": "Invalid client signing session."},
            status=403,
        )

    now = timezone.now()

    if (
        signing_request.client_token_expires_at
        and now > signing_request.client_token_expires_at
    ):
        return None, JsonResponse(
            {"ok": False, "error": "Client signing session expired."},
            status=403,
        )

    if signing_request.used_at:
        return None, JsonResponse(
            {"ok": False, "error": "Signing request has already been used."},
            status=403,
        )

    if (
        signing_request.expires_at
        and now > signing_request.expires_at
    ):
        return None, JsonResponse(
            {"ok": False, "error": "Signing request expired."},
            status=403,
        )

    if signing_request.pairing_status == SigningRequest.PairingStatus.DEVICE_PAIRED:
        return None, JsonResponse(
            {
                "ok": True,
                "request": None,
                "status": "waiting_portal_confirmation",
                "message": "Device paired. Waiting for signer confirmation in portal.",
            },
            status=200,
        )

    if signing_request.pairing_status != SigningRequest.PairingStatus.CONFIRMED:
        return None, JsonResponse(
            {
                "ok": False,
                "error": "Signing session has not been confirmed by the signer.",
            },
            status=403,
        )

    if signing_request.signer_device_public_key_pem:
        ok, error_message = verify_device_binding(request, signing_request)
        if not ok:
            return None, JsonResponse(
                {"ok": False, "error": error_message},
                status=403,
            )

    return signing_request, None


@csrf_exempt
@require_POST
def pair_client_device(request):
    """
    First step from local signer.

    Local signer sends:
    - pairing_code shown on portal
    - device_name
    - ephemeral device_public_key_pem

    Server returns internal client_token, but signed_attrs_b64 is still blocked
    until citizen confirms the device in portal.
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse(
            {"ok": False, "error": "Invalid JSON body."},
            status=400,
        )

    pairing_code = body.get("pairing_code", "")
    device_name = body.get("device_name", "Local ML-DSA Signer")
    device_public_key_pem = body.get("device_public_key_pem", "")

    if not pairing_code:
        return JsonResponse(
            {"ok": False, "error": "Missing pairing_code."},
            status=400,
        )

    if not device_public_key_pem:
        return JsonResponse(
            {"ok": False, "error": "Missing device_public_key_pem."},
            status=400,
        )

    code_hash = hash_pairing_code(pairing_code)
    now = timezone.now()

    signing_request = (
        SigningRequest.objects
        .select_related("document", "signer")
        .filter(
            pairing_code_hash=code_hash,
            signing_type=SigningRequest.SigningType.CLIENT,
            status=SigningRequest.Status.PENDING,
        )
        .first()
    )

    if not signing_request:
        return JsonResponse(
            {"ok": False, "error": "Invalid pairing code."},
            status=403,
        )

    if signing_request.pairing_attempts >= 5:
        signing_request.pairing_status = SigningRequest.PairingStatus.FAILED
        signing_request.save(update_fields=["pairing_status"])
        return JsonResponse(
            {"ok": False, "error": "Too many pairing attempts."},
            status=429,
        )

    if (
        signing_request.pairing_code_expires_at
        and now > signing_request.pairing_code_expires_at
    ):
        signing_request.pairing_status = SigningRequest.PairingStatus.EXPIRED
        signing_request.save(update_fields=["pairing_status"])
        return JsonResponse(
            {"ok": False, "error": "Pairing code expired."},
            status=403,
        )

    if (
        signing_request.client_token_expires_at
        and now > signing_request.client_token_expires_at
    ):
        signing_request.pairing_status = SigningRequest.PairingStatus.EXPIRED
        signing_request.save(update_fields=["pairing_status"])
        return JsonResponse(
            {"ok": False, "error": "Signing session expired."},
            status=403,
        )

    signing_request.pairing_status = SigningRequest.PairingStatus.DEVICE_PAIRED
    signing_request.paired_at = now
    signing_request.signer_device_name = device_name[:120]
    signing_request.signer_device_public_key_pem = device_public_key_pem
    signing_request.signer_device_last_seen_at = now

    signing_request.save(update_fields=[
        "pairing_status",
        "paired_at",
        "signer_device_name",
        "signer_device_public_key_pem",
        "signer_device_last_seen_at",
    ])

    return JsonResponse({
        "ok": True,
        "client_token": signing_request.client_token,
        "request_id": signing_request.id,
        "document_title": signing_request.document.title,
        "status": "waiting_portal_confirmation",
        "message": "Device paired. Please confirm this signing session in the portal.",
    })


@require_GET
def pending_client_requests(request):
    """
    Local signer calls this after pairing.

    Before portal confirmation:
      returns waiting_portal_confirmation

    After portal confirmation:
      returns signed_attrs_b64 for ML-DSA signing.
    """
    r, error = _get_request_by_client_session(request)
    if error:
        return error

    try:
        payload = prepare_client_signing_request(r)

        return JsonResponse({
            "ok": True,
            "request": {
                "request_id": payload["signing_request_id"],
                "document_id": payload["document_id"],
                "document_title": payload["document_title"],
                "algorithm": payload["algorithm"],

                "mode": payload.get("mode", "pades_external_signing"),
                "digest_algorithm": payload.get("digest_algorithm", "sha512"),
                "document_digest": payload["document_digest"],
                "document_hash": payload["document_digest"],
                "field_name": payload.get("field_name", ""),
                "signed_attrs_b64": payload["signed_attrs_b64"],
                "certificate_serial": payload.get("certificate_serial", ""),

                "submit_url": f"/api/signing/api/client/{payload['signing_request_id']}/submit/",
            },
        })

    except Exception as e:
        return JsonResponse(
            {
                "ok": False,
                "error": f"Failed to prepare client PAdES signing session: {str(e)}",
            },
            status=500,
        )


@require_GET
def client_request_file(request, request_id):
    r, error = _get_request_by_client_session(request, request_id)
    if error:
        return error

    if not r.document.file:
        return JsonResponse(
            {"ok": False, "error": "Document has no file."},
            status=400,
        )

    return FileResponse(
        open(r.document.file.path, "rb"),
        as_attachment=True,
        filename=r.document.file.name.split("/")[-1],
    )


@csrf_exempt
@require_POST
def submit_client_signature(request, request_id):
    r, error = _get_request_by_client_session(request, request_id)
    if error:
        return error

    try:
        body = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse(
            {"ok": False, "error": "Invalid JSON body."},
            status=400,
        )

    signature_b64 = body.get("signature_b64", "")
    algorithm = body.get("algorithm", "ML-DSA-65")

    if not signature_b64:
        return JsonResponse(
            {"ok": False, "error": "Missing signature_b64."},
            status=400,
        )

    try:
        record = complete_client_signing_request(
            signing_request=r,
            signature_b64=signature_b64,
            algorithm=algorithm,
        )

        r.client_token = None
        r.client_token_expires_at = None
        r.pairing_code_hash = ""
        r.pairing_code_expires_at = None
        r.pairing_status = SigningRequest.PairingStatus.CONSUMED
        r.used_at = timezone.now()
        r.signer_device_last_seen_at = timezone.now()

        r.save(update_fields=[
            "client_token",
            "client_token_expires_at",
            "pairing_code_hash",
            "pairing_code_expires_at",
            "pairing_status",
            "used_at",
            "signer_device_last_seen_at",
        ])

        return JsonResponse({
            "ok": True,
            "message": "Signature submitted and embedded successfully.",
            "signature_record_id": record.id,
            "document_id": r.document.id,
            "document_title": r.document.title,
        })

    except Exception as e:
        return JsonResponse(
            {"ok": False, "error": str(e)},
            status=400,
        )