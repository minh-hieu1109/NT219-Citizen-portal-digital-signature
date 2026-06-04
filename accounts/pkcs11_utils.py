from django.conf import settings
from cryptography.hazmat.primitives.asymmetric import rsa
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

def _require_pkcs11():
    try:
        import pkcs11
        return pkcs11
    except ModuleNotFoundError as e:
        raise RuntimeError(
            "python-pkcs11 is not installed in this environment. "
            "SoftHSM/PKCS#11 features are only available where pkcs11 is installed."
        ) from e


def get_pkcs11_lib():
    pkcs11 = _require_pkcs11()
    return pkcs11.lib(settings.PKCS11_LIB_PATH)


def get_token():
    lib = get_pkcs11_lib()
    return lib.get_token(token_label=settings.PKCS11_TOKEN_LABEL)


def create_user_keypair_in_softhsm(user):
    pkcs11 = _require_pkcs11()
    KeyType = pkcs11.KeyType
    Attribute = pkcs11.Attribute
    ObjectClass = pkcs11.ObjectClass

    token = get_token()
    key_label = f"{settings.PKCS11_KEY_LABEL_PREFIX}-{user.id}"
    key_id = f"user-{user.id}".encode("utf-8")

    with token.open(user_pin=settings.PKCS11_TOKEN_PIN, rw=True) as session:
        existing = list(session.get_objects({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.LABEL: key_label,
        }))
        if existing:
            raise ValueError(f"SoftHSM key already exists for user {user.id}")

        public_key, private_key = session.generate_keypair(
            KeyType.RSA,
            2048,
            store=True,
            label=key_label,
            id=key_id,
            public_template={
                Attribute.ENCRYPT: True,
                Attribute.VERIFY: True,
                Attribute.MODULUS_BITS: 2048,
                Attribute.PUBLIC_EXPONENT: (0x01, 0x00, 0x01),
            },
            private_template={
                Attribute.SIGN: True,
                Attribute.DECRYPT: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
            },
        )

    return {
        "token_label": settings.PKCS11_TOKEN_LABEL,
        "key_label": key_label,
        "key_id": key_id.hex(),
    }


def load_public_key_from_softhsm(key_label: str):
    pkcs11 = _require_pkcs11()
    Attribute = pkcs11.Attribute
    ObjectClass = pkcs11.ObjectClass

    token = get_token()

    with token.open(user_pin=settings.PKCS11_TOKEN_PIN) as session:
        objs = list(session.get_objects({
            Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            Attribute.LABEL: key_label,
        }))
        if not objs:
            raise ValueError(f"Public key not found for label={key_label}")

        pub = objs[0]
        modulus = pub[Attribute.MODULUS]
        exponent = pub[Attribute.PUBLIC_EXPONENT]

        public_numbers = rsa.RSAPublicNumbers(
            int.from_bytes(exponent, "big"),
            int.from_bytes(modulus, "big"),
        )
        return public_numbers.public_key()
    
def import_certificate_to_softhsm(user_cert):
    """
    Import user's X.509 certificate into SoftHSM so pyHanko PKCS#11
    can find cert-label + key-label in the token.
    """
    if user_cert.key_storage_type != user_cert.KeyStorageType.SOFTHSM:
        return {
            "ok": False,
            "message": "Certificate profile is not SoftHSM-backed.",
        }

    if not user_cert.pkcs11_key_label or not user_cert.pkcs11_key_id:
        return {
            "ok": False,
            "message": "Missing pkcs11_key_label or pkcs11_key_id.",
        }

    cert = x509.load_pem_x509_certificate(
        user_cert.certificate_pem.encode("utf-8")
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_der_path = Path(tmpdir) / "signer_cert.der"
        cert_der_path.write_bytes(
            cert.public_bytes(serialization.Encoding.DER)
        )

        cmd = [
            "pkcs11-tool",
            "--module",
            str(settings.PKCS11_LIB_PATH),
            "--token-label",
            user_cert.pkcs11_token_label or settings.PKCS11_TOKEN_LABEL,
            "--login",
            "--pin",
            settings.PKCS11_TOKEN_PIN,
            "--write-object",
            str(cert_der_path),
            "--type",
            "cert",
            "--label",
            user_cert.pkcs11_key_label,
            "--id",
            user_cert.pkcs11_key_id,
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)

        if proc.returncode != 0:
            # Fallback: some pkcs11-tool versions may not like --token-label
            fallback_cmd = [
                "pkcs11-tool",
                "--module",
                str(settings.PKCS11_LIB_PATH),
                "--login",
                "--pin",
                settings.PKCS11_TOKEN_PIN,
                "--write-object",
                str(cert_der_path),
                "--type",
                "cert",
                "--label",
                user_cert.pkcs11_key_label,
                "--id",
                user_cert.pkcs11_key_id,
            ]

            proc = subprocess.run(fallback_cmd, capture_output=True, text=True)
            cmd = fallback_cmd

        return {
            "ok": proc.returncode == 0,
            "command": " ".join(cmd),
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }