import os
import subprocess
import sys
from pathlib import Path

from common import create_demo_document, log
from accounts.models import User
from signing.models import SigningRequest


def main():
    pkcs11_lib = os.getenv("PKCS11_LIB_PATH", "/usr/lib/softhsm/libsofthsm2.so")
    token_label = os.getenv("PKCS11_TOKEN_LABEL", "citizen-client-token")
    key_label = os.getenv("PKCS11_KEY_LABEL", "CitizenClientKey")
    key_id = os.getenv("PKCS11_KEY_ID", "")
    pin = os.getenv("PKCS11_USER_PIN", "")
    signer_email = os.getenv("TOOL_EMAIL", "")

    if not signer_email:
        log("WARNING", "TOOL_EMAIL is missing. Cannot select signer for client PKCS#11 experiment.")
        log("WARNING", "Run setup script: scripts/setup_client_softhsm_token.sh or .ps1")
        return

    try:
        user = User.objects.get(email=signer_email)
    except User.DoesNotExist:
        log("WARNING", f"Signer user not found: {signer_email}")
        log("WARNING", "Please create/enroll user first, then rerun this experiment.")
        return

    if not hasattr(user, "certificate_profile"):
        log("WARNING", f"User {signer_email} has no certificate profile.")
        log("WARNING", "Please enroll certificate bound to PKCS#11 key first.")
        return

    doc = create_demo_document(user, title_prefix="client_pkcs11_exp", content=b"client pkcs11 signing demo")
    req = SigningRequest.objects.create(
        document=doc,
        requested_by=user,
        signer=user,
        signing_type=SigningRequest.SigningType.CLIENT,
        status=SigningRequest.Status.PENDING,
    )

    tool_path = Path(__file__).resolve().parent.parent / "tools" / "client_pkcs11_sign_app.py"
    cmd = [
        sys.executable,
        str(tool_path),
        str(req.id),
        "--use-orm",
        "--pkcs11-lib",
        pkcs11_lib,
        "--token-label",
        token_label,
        "--key-label",
        key_label,
        "--allow-warning-exit",
    ]
    if key_id:
        cmd += ["--key-id", key_id]
    if pin:
        cmd += ["--pin", pin]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    print(proc.stdout)
    if proc.stderr:
        print(proc.stderr)

    if proc.returncode == 0:
        log("OK", "Client PKCS#11 experiment finished (success or warning-safe exit).")
    else:
        log("WARNING", f"Client PKCS#11 experiment failed with exit code={proc.returncode}.")
        log("WARNING", "Run setup script and ensure enrolled certificate matches PKCS#11 key.")


if __name__ == "__main__":
    main()
