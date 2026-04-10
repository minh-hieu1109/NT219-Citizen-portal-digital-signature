from django.conf import settings
from cryptography.hazmat.primitives.asymmetric import rsa


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