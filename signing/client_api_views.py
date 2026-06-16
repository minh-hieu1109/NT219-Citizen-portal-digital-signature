import json
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from django.utils import timezone
from .models import SigningRequest
from .services import complete_client_signing_request, prepare_client_signing_request
from django.urls import reverse



def _get_request_by_client_session(request, request_id=None):
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

    if signing_request.client_token_expires_at and timezone.now() > signing_request.client_token_expires_at:
        return None, JsonResponse(
            {"ok": False, "error": "Client signing session expired."},
            status=403,
        )

    return signing_request, None



@require_GET
def pending_client_requests(request):
    token = request.headers.get("X-Client-Signing-Session", "").strip()

    if not token:
        return JsonResponse(
            {
                "ok": False,
                "error": "Missing X-Client-Signing-Session header.",
            },
            status=401,
        )

    now = timezone.now()

    r = (
        SigningRequest.objects
        .select_related("document", "signer")
        .filter(
            signing_type=SigningRequest.SigningType.CLIENT,
            status=SigningRequest.Status.PENDING,
            client_token=token,
            client_token_expires_at__gt=now,
        )
        .first()
    )

    if not r:
        return JsonResponse(
            {
                "ok": True,
                "request": None,
            }
        )

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

                "submit_url": reverse(
                    "client-submit-signature",
                    args=[payload["signing_request_id"]],
                ),
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
        return JsonResponse({"ok": False, "error": "Document has no file."}, status=400)

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
        return JsonResponse({"ok": False, "error": "Invalid JSON body."}, status=400)

    signature_b64 = body.get("signature_b64", "")
    algorithm = body.get("algorithm", "ML-DSA-65")

    try:
        record = complete_client_signing_request(
            signing_request=r,
            signature_b64=signature_b64,
            algorithm=algorithm,
        )

        r.client_token = None
        r.client_token_expires_at = None
        r.used_at = timezone.now()
        r.save(update_fields=["client_token", "client_token_expires_at", "used_at"])

        return JsonResponse({
            "ok": True,
            "signature_record_id": record.id,
            "algorithm": record.algorithm,
            "signed_hash": record.signed_hash,
            "signer": record.signing_request.signer.email,
        })

    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=400)