from common import ensure_demo_citizen, log, run_remote_sign_and_verify
from django.conf import settings


def main():
    user = ensure_demo_citizen(email="laqun0211@gmail.com")

    original_ocsp_flag = settings.ENABLE_OCSP_CHECK
    settings.ENABLE_OCSP_CHECK = False
    log("INFO", "OCSP disabled for baseline E2E demo.")

    try:
        result = run_remote_sign_and_verify(user, content=b"phase6 remote sign baseline")
    finally:
        settings.ENABLE_OCSP_CHECK = original_ocsp_flag

    sig = result["signature_record"]
    ver = result["verification_result"]
    ltv = result["ltv_result"]

    log("INFO", f"signature_record_id={sig.id}")
    log("INFO", f"verification_status={ver.status} is_signature_valid={ver.is_signature_valid}")
    log("INFO", f"ltv_valid={ltv.get('valid')} evidence_exists={ltv.get('evidence_exists')}")
    log("INFO", f"timings_ms={result['timings_ms']}")


if __name__ == "__main__":
    main()
