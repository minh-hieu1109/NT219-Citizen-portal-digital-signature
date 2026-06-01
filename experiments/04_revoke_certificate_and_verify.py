from accounts.models import UserCertificate
from accounts.revocation_services import revoke_user_certificate
from common import ensure_demo_citizen, log, run_remote_sign_and_verify
from verification.services import verify_signature_record


def main():
    user = ensure_demo_citizen(email="revoke_exp_citizen@example.com")
    result = run_remote_sign_and_verify(user, content=b"content before revocation")
    sig = result["signature_record"]

    user_cert = UserCertificate.objects.get(user=user)
    revoke_user_certificate(user_cert)

    ver2 = verify_signature_record(sig)

    log("INFO", f"signature_record_id={sig.id}")
    log("INFO", f"certificate_status_after_revoke={UserCertificate.objects.get(user=user).status}")
    log("INFO", f"verification_after_revoke_status={ver2.status}")
    log("INFO", f"verification_after_revoke_detail={ver2.detail}")


if __name__ == "__main__":
    main()
