import subprocess
from pathlib import Path
import tempfile

def create_pades_signature(
    input_pdf_path,
    signer_cert_path,
    signer_key_path,
    output_pdf_path,
    ca_cert_path=None,
    field_name="Sig1",
):
    """
    Create a PAdES signed PDF.

    PAdES output:
    - input: original PDF
    - output: signed_document.pdf
    """

    input_pdf_path = Path(input_pdf_path)
    signer_cert_path = Path(signer_cert_path)
    signer_key_path = Path(signer_key_path)
    output_pdf_path = Path(output_pdf_path)

    if not input_pdf_path.exists():
        return {
            "ok": False,
            "status": "error",
            "message": f"Input PDF not found: {input_pdf_path}",
        }

    if input_pdf_path.suffix.lower() != ".pdf":
        return {
            "ok": False,
            "status": "skipped",
            "message": "PAdES only supports PDF files.",
        }

    if not signer_cert_path.exists():
        return {
            "ok": False,
            "status": "error",
            "message": f"Signer certificate not found: {signer_cert_path}",
        }

    if not signer_key_path.exists():
        return {
            "ok": False,
            "status": "error",
            "message": f"Signer private key not found: {signer_key_path}",
        }

    cmd = [
        "pyhanko",
        "sign",
        "addsig",
        "--no-strict-syntax",
        "--field",
        field_name,
        "pemder",
        "--key",
        str(signer_key_path),
        "--cert",
        str(signer_cert_path),
        "--no-pass",
    ]

    if ca_cert_path:
        cmd.extend(["--chain", str(ca_cert_path)])

    cmd.extend([str(input_pdf_path), str(output_pdf_path)])

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )

    if proc.returncode != 0:
        return {
            "ok": False,
            "status": "error",
            "message": "PAdES signing failed.",
            "command": " ".join(cmd),
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }

    return {
        "ok": True,
        "status": "created",
        "message": "PAdES signed PDF created.",
        "output_pdf": str(output_pdf_path),
        "command": " ".join(cmd),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def verify_pades_signature(signed_pdf_path, ca_cert_path=None):
    signed_pdf_path = Path(signed_pdf_path)

    if not signed_pdf_path.exists():
        return {
            "ok": False,
            "status": "error",
            "message": f"Signed PDF not found: {signed_pdf_path}",
        }

    if signed_pdf_path.suffix.lower() != ".pdf":
        return {
            "ok": False,
            "status": "error",
            "message": "PAdES verification requires a PDF file.",
        }

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            pyhanko_config = tmpdir / "pyhanko.yml"

            if ca_cert_path:
                pyhanko_config.write_text(
                    f"""
validation-contexts:
    lab:
        trust: "{ca_cert_path}"
        trust-replace: true
        signer-key-usage: []
""".strip(),
                    encoding="utf-8",
                )

                cmd = [
                    "pyhanko",
                    "--config",
                    str(pyhanko_config),
                    "sign",
                    "validate",
                    "--validation-context",
                    "lab",
                    "--pretty-print",
                    "--no-strict-syntax",
                    str(signed_pdf_path),
                ]
            else:
                cmd = [
                    "pyhanko",
                    "sign",
                    "validate",
                    "--pretty-print",
                    "--no-strict-syntax",
                    str(signed_pdf_path),
                ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()

            return {
                "ok": proc.returncode == 0,
                "status": "valid" if proc.returncode == 0 else "invalid",
                "message": (
                    "PAdES PDF signature verified."
                    if proc.returncode == 0
                    else "PAdES PDF signature invalid."
                ),
                "details": output,
                "command": " ".join(cmd),
            }

    except Exception as exc:
        return {
            "ok": False,
            "status": "error",
            "message": str(exc),
        }