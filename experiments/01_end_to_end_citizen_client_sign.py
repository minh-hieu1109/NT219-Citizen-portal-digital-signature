import base64

from common import create_demo_document, ensure_demo_certificate, ensure_demo_citizen, log
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from django.conf import settings
from signing.models import SigningRequest
from signing.services import complete_client_signing_request, prepare_client_signing_request
from verification.ltv_services import verify_ltv
from verification.services import verify_signature_record


def main():
    user = ensure_demo_citizen(email="citizen_client_exp@example.com")
    user_cert = ensure_demo_certificate(user)
    doc = create_demo_document(
        user,
        title_prefix="citizen_client_sign",
        content=b"citizen client signing experiment",
    )
    req = SigningRequest.objects.create(
        document=doc,
        requested_by=user,
        signer=user,
        signing_type=SigningRequest.SigningType.CLIENT,
        status=SigningRequest.Status.PENDING,
    )

    prepare = prepare_client_signing_request(req)
    with open(user_cert.private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    signature_bytes = private_key.sign(
        bytes.fromhex(prepare["digest_hex"]),
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256()),
    )

    original_ocsp_flag = settings.ENABLE_OCSP_CHECK
    settings.ENABLE_OCSP_CHECK = False
    try:
        sig = complete_client_signing_request(
            req,
            base64.b64encode(signature_bytes).decode("utf-8"),
            prepare["algorithm"],
        )
        ver = verify_signature_record(sig)
        ltv = verify_ltv(sig)
    finally:
        settings.ENABLE_OCSP_CHECK = original_ocsp_flag

    log("INFO", f"signer_email={sig.signer.email}")
    log("INFO", f"signature_purpose={sig.signature_purpose}")
    log("INFO", f"certificate_serial={sig.certificate_serial}")
    log("INFO", f"verification_status={ver.status} is_signature_valid={ver.is_signature_valid}")
    log("INFO", f"ltv_valid={ltv.get('valid')} evidence_exists={ltv.get('evidence_exists')}")


if __name__ == "__main__":
    main()
