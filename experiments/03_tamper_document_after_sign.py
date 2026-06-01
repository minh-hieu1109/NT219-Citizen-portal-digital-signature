from common import ensure_demo_citizen, log, run_remote_sign_and_verify
from verification.services import verify_signature_record


def main():
    user = ensure_demo_citizen(email="tamper_exp_citizen@example.com")
    result = run_remote_sign_and_verify(user, content=b"original document content")

    doc = result["document"]
    sig = result["signature_record"]

    with open(doc.file.path, "wb") as f:
        f.write(b"tampered content after signature")

    ver2 = verify_signature_record(sig)

    log("INFO", f"signature_record_id={sig.id}")
    log("INFO", f"tampered_verification_status={ver2.status}")
    log("INFO", f"tampered_detail={ver2.detail}")


if __name__ == "__main__":
    main()
