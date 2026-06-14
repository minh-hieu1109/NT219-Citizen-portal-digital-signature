import json

from django.conf import settings
from django.http import JsonResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from accounts.models import User
from .models import SigningRequest
from .services import complete_client_signing_request, prepare_client_signing_request


def _check_client_token(request):
    expected = getattr(settings, "CLIENT_SIGNER_DEMO_TOKEN", "client-demo-token")
    token = request.headers.get("X-Client-Signer-Token")
    return token == expected


def _forbidden():
    return JsonResponse({"ok": False, "error": "Invalid client signer token."}, status=403)


@require_GET
def pending_client_requests(request):
    if not _check_client_token(request):
        return _forbidden()

    email = request.GET.get("email", "").strip()
    if not email:
        return JsonResponse({"ok": False, "error": "Missing email."}, status=400)

    signer = User.objects.get(email=email)

    requests = (
        SigningRequest.objects
        .filter(
            signer=signer,
            signing_type=SigningRequest.SigningType.CLIENT,
            status=SigningRequest.Status.PENDING,
        )
        .select_related("document", "signer")
        .order_by("-id")
    )

    data = []
    for r in requests:
        payload = prepare_client_signing_request(r)
        data.append({
            "request_id": r.id,
            "document_id": r.document.id,
            "document_title": r.document.title,
            "document_hash": payload["digest_hex"],
            "algorithm": payload["algorithm"],
            "signer_email": r.signer.email,
            "file_url": f"/api/signing/api/client/requests/{r.id}/file/",
            "submit_url": f"/api/signing/api/client/requests/{r.id}/submit/",
        })

    return JsonResponse({"ok": True, "requests": data})


@require_GET
def client_request_file(request, request_id):
    if not _check_client_token(request):
        return _forbidden()

    r = SigningRequest.objects.select_related("document").get(id=request_id)

    if r.signing_type != SigningRequest.SigningType.CLIENT:
        return JsonResponse({"ok": False, "error": "Not a client signing request."}, status=400)

    if r.status != SigningRequest.Status.PENDING:
        return JsonResponse({"ok": False, "error": "Request is not pending."}, status=400)

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
    if not _check_client_token(request):
        return _forbidden()

    try:
        body = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse(
            {"ok": False, "error": "Invalid JSON body."},
            status=400,
        )

    signature_b64 = body.get("signature_b64", "")
    algorithm = body.get("algorithm", "ML-DSA-65")

    try:
        r = SigningRequest.objects.get(id=request_id)

        record = complete_client_signing_request(
            signing_request=r,
            signature_b64=signature_b64,
            algorithm=algorithm,
        )

        return JsonResponse({
            "ok": True,
            "signature_record_id": record.id,
            "algorithm": record.algorithm,
            "signed_hash": record.signed_hash,
            "signer": record.signing_request.signer.email,
        })

    except Exception as e:
        return JsonResponse(
            {
                "ok": False,
                "error": str(e),
                "request_id": request_id,
            },
            status=400,
        )