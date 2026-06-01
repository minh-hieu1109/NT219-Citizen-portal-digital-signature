from common import ensure_demo_citizen, log, run_remote_sign_and_verify
from django.conf import settings
from verification.services import verify_signature_record


def main():
    user = ensure_demo_citizen(email="ocsp_exp_citizen@example.com")
    result = run_remote_sign_and_verify(user, content=b"ocsp unavailable demo")
    sig = result["signature_record"]

    original_url = settings.OCSP_RESPONDER_URL
    original_flag = settings.ENABLE_OCSP_CHECK
    settings.ENABLE_OCSP_CHECK = True
    settings.OCSP_RESPONDER_URL = "http://127.0.0.1:65534"

    try:
        ver = verify_signature_record(sig)
    finally:
        settings.OCSP_RESPONDER_URL = original_url
        settings.ENABLE_OCSP_CHECK = original_flag

    ocsp_status = ver.detail.get("ocsp_status") if isinstance(ver.detail, dict) else None
    log("INFO", f"signature_record_id={sig.id}")
    log("INFO", f"verification_status={ver.status}")
    log("INFO", f"ocsp_status={ocsp_status}")
    log("INFO", f"detail={ver.detail}")


if __name__ == "__main__":
    main()
