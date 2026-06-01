import subprocess
from pathlib import Path

from common import log
from signing.cms_services import (
    create_cms_detached_signature,
    verify_cms_detached_signature,
)


def _find_demo_cert_key():
    candidates = [
        (
            Path("/app/pki-lab/certs/users/user_4.crt"),
            Path("/app/pki-lab/users/private/user_4_key.pem"),
            Path("/app/pki-lab/certs/rootCA.crt"),
        ),
        (
            Path("/app/keys/client_certificate.pem"),
            Path("/app/keys/client_private_key.pem"),
            Path("/app/pki-lab/certs/rootCA.crt"),
        ),
    ]
    for cert, key, ca in candidates:
        if cert.exists() and key.exists():
            return cert, key, ca
    return None, None, None


def main():
    results_dir = Path(__file__).resolve().parent / "results" / "cms"
    results_dir.mkdir(parents=True, exist_ok=True)

    input_file = results_dir / "cms_demo_input.txt"
    input_file.write_bytes(b"CMS detached signature demo payload")

    cert_path, key_path, ca_path = _find_demo_cert_key()
    if not cert_path or not key_path:
        log("WARNING", "No suitable cert/key found for CMS demo.")
        log("WARNING", "Please configure cert/key paths (e.g. /app/pki-lab/certs/users/user_4.crt and /app/pki-lab/users/private/user_4_key.pem).")
        return

    sig_path = results_dir / "cms_demo_signature.p7s"

    create_res = create_cms_detached_signature(
        input_file=str(input_file),
        signer_cert_path=str(cert_path),
        signer_key_path=str(key_path),
        ca_cert_path=str(ca_path) if ca_path and ca_path.exists() else None,
        output_path=str(sig_path),
    )

    if not create_res.get("ok"):
        log("WARNING", f"CMS create failed: {create_res.get('message')}")
        return

    log("OK", "CMS detached signature created")

    verify_res = verify_cms_detached_signature(
        input_file=str(input_file),
        cms_signature_path=str(sig_path),
        ca_cert_path=str(ca_path) if ca_path and ca_path.exists() else None,
    )

    if not verify_res.get("ok"):
        log("WARNING", f"CMS verify failed: {verify_res.get('message')}")
        return

    log("OK", "CMS detached signature verified")
    if verify_res.get("warning"):
        log("WARNING", verify_res["warning"])


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        log("WARNING", f"OpenSSL command failed: {exc}")
