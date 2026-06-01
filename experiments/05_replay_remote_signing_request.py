from common import create_demo_document, create_remote_request, ensure_demo_certificate, ensure_demo_citizen, log
from signing.services import remote_sign_signing_request


def main():
    user = ensure_demo_citizen(email="laqun0211@gmail.com")
    ensure_demo_certificate(user)
    doc = create_demo_document(user, title_prefix="replay_doc", content=b"replay test")
    req = create_remote_request(user, doc)

    first_sig = remote_sign_signing_request(req)
    log("INFO", f"first_sign_ok signature_record_id={first_sig.id}")

    try:
        remote_sign_signing_request(req)
        log("ERROR", "Unexpected success on replay attempt")
    except Exception as exc:
        log("INFO", f"replay_rejected message={exc}")


if __name__ == "__main__":
    main()
