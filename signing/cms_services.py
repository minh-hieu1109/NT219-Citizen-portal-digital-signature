import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile

from django.conf import settings


def _openssl_bin() -> str:
    return str(getattr(settings, "OPENSSL_BIN", "openssl") or "openssl")


def create_cms_detached_signature(
    input_file,
    signer_cert_path,
    signer_key_path,
    ca_cert_path=None,
    output_path=None,
):
    input_path = Path(input_file)
    cert_path = Path(signer_cert_path)
    key_path = Path(signer_key_path)

    for p, label in ((input_path, "input_file"), (cert_path, "signer_cert_path"), (key_path, "signer_key_path")):
        if not p.exists():
            return {
                "ok": False,
                "status": "error",
                "message": f"Missing {label}: {p}",
            }

    if output_path:
        sig_path = Path(output_path)
    else:
        sig_path = input_path.with_suffix(input_path.suffix + ".p7s")

    cmd = [
        _openssl_bin(),
        "cms",
        "-sign",
        "-binary",
        "-in",
        str(input_path),
        "-signer",
        str(cert_path),
        "-inkey",
        str(key_path),
        "-outform",
        "DER",
        "-out",
        str(sig_path),
        "-nosmimecap",
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return {
            "ok": False,
            "status": "error",
            "message": ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip(),
            "command": cmd,
        }

    return {
        "ok": True,
        "status": "created",
        "signature_path": str(sig_path),
        "message": "CMS detached signature created.",
        "command": cmd,
    }


def verify_cms_detached_signature(input_file, cms_signature_path, ca_cert_path=None):
    input_path = Path(input_file)
    sig_path = Path(cms_signature_path)

    for p, label in ((input_path, "input_file"), (sig_path, "cms_signature_path")):
        if not p.exists():
            return {
                "ok": False,
                "status": "error",
                "message": f"Missing {label}: {p}",
            }

    with NamedTemporaryFile(delete=False, suffix=".verified") as tmp:
        verified_out = Path(tmp.name)

    cmd = [
        _openssl_bin(),
        "cms",
        "-verify",
        "-binary",
        "-inform",
        "DER",
        "-in",
        str(sig_path),
        "-content",
        str(input_path),
    ]

    verification_mode = "noverify"
    if ca_cert_path:
        ca_path = Path(ca_cert_path)
        if ca_path.exists():
            cmd += ["-CAfile", str(ca_path)]
            verification_mode = "cafile"
        else:
            return {
                "ok": False,
                "status": "error",
                "message": f"Missing ca_cert_path: {ca_path}",
            }
    else:
        cmd += ["-noverify"]

    cmd += ["-out", str(verified_out)]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return {
            "ok": False,
            "status": "invalid",
            "verification_mode": verification_mode,
            "message": ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip(),
            "command": cmd,
        }

    return {
        "ok": True,
        "status": "valid",
        "verification_mode": verification_mode,
        "verified_output_path": str(verified_out),
        "message": "CMS detached signature verified.",
        "command": cmd,
        "warning": "Used -noverify mode for lab demo." if verification_mode == "noverify" else "",
    }
