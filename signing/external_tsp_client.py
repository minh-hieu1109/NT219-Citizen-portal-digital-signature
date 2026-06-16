import subprocess
import tempfile
from pathlib import Path
from django.conf import settings


def external_tsp_sign(signing_request, user_cert, data: bytes) -> bytes:
    """
    PoC external TSP signing client.

    Trong production:
    - Portal không giữ private key.
    - Portal gọi HTTPS/mTLS sang TSP.
    - TSP/HSM giữ key và ký.
    - Key không export về Portal.

    Trong demo:
    - Hàm này mô phỏng TSP bằng cách dùng private_key_path như key reference.
    """

    if not user_cert.private_key_path:
        raise ValueError("TSP key reference is missing for this certificate.")

    key_path = Path(user_cert.private_key_path)

    if not key_path.is_absolute():
        key_path = Path(settings.BASE_DIR) / key_path

    if not key_path.exists():
        raise ValueError(f"TSP key not found for key reference: {key_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        data_path = tmpdir / "data.bin"
        sig_path = tmpdir / "signature.bin"

        data_path.write_bytes(data)

        proc = subprocess.run(
            [
                str(settings.PKI_OPENSSL_BIN),
                "pkeyutl",
                "-sign",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                str(data_path),
                "-out",
                str(sig_path),
            ],
            capture_output=True,
            text=True,
        )

        if proc.returncode != 0:
            raise ValueError(
                "External TSP signing failed.\n"
                f"STDOUT:\n{proc.stdout}\n"
                f"STDERR:\n{proc.stderr}"
            )

        return sig_path.read_bytes()