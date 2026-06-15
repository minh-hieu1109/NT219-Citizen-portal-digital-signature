import json
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from django.utils import timezone
from .models import SigningRequest
from .services import complete_client_signing_request, prepare_client_signing_request




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
    r, error = _get_request_by_client_session(request)
    if error:
        return error

    payload = prepare_client_signing_request(r)

    return JsonResponse({
        "ok": True,
        "request": {
            "request_id": r.id,
            "document_id": r.document.id,
            "document_title": r.document.title,
            "document_hash": payload["digest_hex"],
            "algorithm": payload["algorithm"],
            "signer_email": r.signer.email,
            "file_url": f"/api/signing/api/client/requests/{r.id}/file/",
            "submit_url": f"/api/signing/api/client/requests/{r.id}/submit/",
        }
    })


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