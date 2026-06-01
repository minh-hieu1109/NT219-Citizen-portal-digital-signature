from common import create_demo_document, create_remote_request, ensure_demo_certificate, ensure_demo_citizen, log
from django.conf import settings
from signing.services import remote_sign_signing_request


def main():
    user = ensure_demo_citizen(email="tsa_exp_citizen@example.com")
    ensure_demo_certificate(user)
    doc = create_demo_document(user, title_prefix="tsa_unavailable", content=b"tsa unavailable demo")
    req = create_remote_request(user, doc)

    original_tsa_conf = settings.PKI_TSA_CONF
    settings.PKI_TSA_CONF = "/tmp/nonexistent_tsa.conf"

    try:
        sig = remote_sign_signing_request(req)
    finally:
        settings.PKI_TSA_CONF = original_tsa_conf

    log("INFO", f"signature_record_id={sig.id}")
    log("INFO", f"timestamp_status={sig.timestamp_status}")
    log("INFO", f"timestamp_message={sig.timestamp_message}")


if __name__ == "__main__":
    main()
