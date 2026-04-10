from django.conf import settings
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def _require_pkcs11():
    try:
        import pkcs11
        return pkcs11
    except ModuleNotFoundError as e:
        raise RuntimeError(
            "python-pkcs11 is not installed in this environment. "
            "SoftHSM signing is only available where pkcs11 is installed."
        ) from e


class FilePemSignerBackend:
    def sign(self, user_cert, data: bytes) -> bytes:
        if not user_cert.private_key_path:
            raise ValueError("private_key_path is empty for file-based signer.")

        with open(user_cert.private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        return private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )


class SoftHSMSignerBackend:
    def sign(self, user_cert, data: bytes) -> bytes:
        if not user_cert.pkcs11_token_label or not user_cert.pkcs11_key_label:
            raise ValueError("Missing PKCS#11 metadata on user certificate.")

        pkcs11 = _require_pkcs11()
        Attribute = pkcs11.Attribute
        Mechanism = pkcs11.Mechanism
        ObjectClass = pkcs11.ObjectClass

        lib = pkcs11.lib(settings.PKCS11_LIB_PATH)
        token = lib.get_token(token_label=user_cert.pkcs11_token_label)

        with token.open(user_pin=settings.PKCS11_TOKEN_PIN) as session:
            private_keys = list(session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.LABEL: user_cert.pkcs11_key_label,
            }))

            if not private_keys:
                raise ValueError("SoftHSM private key not found.")

            private_key = private_keys[0]

            return private_key.sign(
                data,
                mechanism=Mechanism.SHA256_RSA_PKCS
            )


def get_signer_backend(user_cert):
    if user_cert.key_storage_type == "file":
        return FilePemSignerBackend()

    if user_cert.key_storage_type == "softhsm":
        return SoftHSMSignerBackend()

    raise ValueError(f"Unsupported key storage type: {user_cert.key_storage_type}")