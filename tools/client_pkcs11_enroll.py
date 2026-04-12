import os
import sys
import json
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from pkcs11 import lib, KeyType, ObjectClass, Mechanism, Attribute


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

BASE_URL = os.getenv("PORTAL_BASE_URL", "http://web:8000").rstrip("/")
EMAIL = os.getenv("TOOL_EMAIL")
PASSWORD = os.getenv("TOOL_PASSWORD")

PKCS11_LIB_PATH = os.getenv("PKCS11_LIB_PATH", "/usr/lib/softhsm/libsofthsm2.so")
PKCS11_TOKEN_LABEL = os.getenv("PKCS11_TOKEN_LABEL", "citizen-client-token")
PKCS11_USER_PIN = os.getenv("PKCS11_USER_PIN", "123456")
PKCS11_KEY_LABEL = os.getenv("PKCS11_KEY_LABEL", "CitizenClientKey")
PKCS11_KEY_ID = os.getenv("PKCS11_KEY_ID", "10")
PKCS11_SLOT = os.getenv("PKCS11_SLOT", "")

CLIENT_CERT_FILENAME = os.getenv("CLIENT_CERT_FILENAME", "client_certificate.pem")
CLIENT_KEY_DIR = os.getenv("CLIENT_KEY_DIR", "keys")

CSR_COUNTRY = os.getenv("CLIENT_CSR_COUNTRY", "VN")
CSR_STATE = os.getenv("CLIENT_CSR_STATE", "HCM")
CSR_LOCALITY = os.getenv("CLIENT_CSR_LOCALITY", "HCM")
CSR_ORG = os.getenv("CLIENT_CSR_ORG", "Citizen Portal")
CSR_OU = os.getenv("CLIENT_CSR_OU", "Citizen")
CSR_COMMON_NAME = os.getenv("CLIENT_CSR_COMMON_NAME", "citizen-client")
CSR_EMAIL = os.getenv("CLIENT_CSR_EMAIL", EMAIL or "citizen@example.com")


def get_basic_auth():
    if not EMAIL or not PASSWORD:
        raise ValueError("TOOL_EMAIL / TOOL_PASSWORD is missing.")
    return (EMAIL, PASSWORD)


def get_token():
    p11 = lib(PKCS11_LIB_PATH)
    return p11.get_token(token_label=PKCS11_TOKEN_LABEL)


class PKCS11RSAPrivateKey(rsa.RSAPrivateKey):
    """
    Adapter để cryptography có thể dùng private key PKCS#11 khi ký CSR.
    """

    def __init__(self, pkcs11_private_key, pkcs11_public_key):
        self._private_key = pkcs11_private_key
        self._public_key_obj = pkcs11_public_key

        modulus = int.from_bytes(pkcs11_public_key[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pkcs11_public_key[Attribute.PUBLIC_EXPONENT], "big")
        self._public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()

    @property
    def key_size(self) -> int:
        return self._public_key.key_size

    def public_key(self):
        return self._public_key

    def sign(self, data: bytes, chosen_padding, algorithm) -> bytes:
        if not isinstance(chosen_padding, padding.PKCS1v15):
            raise ValueError("Only PKCS1v15 padding is supported for CSR signing.")

        if not isinstance(algorithm, hashes.SHA256):
            raise ValueError("Only SHA256 is supported in this tool.")

        return self._private_key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

    def decrypt(self, ciphertext, chosen_padding):
        raise NotImplementedError("decrypt is not supported")

    def private_numbers(self):
        raise NotImplementedError("private_numbers is not supported for PKCS#11 key")

    def private_bytes(self, encoding, format, encryption_algorithm):
        raise NotImplementedError("private_bytes is not supported for PKCS#11 key")

    # cryptography có thể gọi method này trong vài context
    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def get_pkcs11_keypair():
    token = get_token()
    with token.open(user_pin=PKCS11_USER_PIN) as session:
        private_key = session.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            key_type=KeyType.RSA,
            label=PKCS11_KEY_LABEL,
        )
        public_key = session.get_key(
            object_class=ObjectClass.PUBLIC_KEY,
            key_type=KeyType.RSA,
            label=PKCS11_KEY_LABEL,
        )
        return private_key, public_key


def build_subject():
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, CSR_COUNTRY),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CSR_STATE),
        x509.NameAttribute(NameOID.LOCALITY_NAME, CSR_LOCALITY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CSR_ORG),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, CSR_OU),
        x509.NameAttribute(NameOID.COMMON_NAME, CSR_COMMON_NAME),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, CSR_EMAIL),
    ])


def create_csr_pem() -> str:
    token = get_token()

    with token.open(user_pin=PKCS11_USER_PIN) as session:
        private_key = session.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            key_type=KeyType.RSA,
            label=PKCS11_KEY_LABEL,
        )
        public_key = session.get_key(
            object_class=ObjectClass.PUBLIC_KEY,
            key_type=KeyType.RSA,
            label=PKCS11_KEY_LABEL,
        )

        adapter = PKCS11RSAPrivateKey(private_key, public_key)

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(build_subject())
            .sign(adapter, hashes.SHA256())
        )

        return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def save_certificate_if_present(certificate_pem: Optional[str]):
    if not certificate_pem:
        return

    out_dir = BASE_DIR / CLIENT_KEY_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    cert_path = out_dir / CLIENT_CERT_FILENAME
    cert_path.write_text(certificate_pem, encoding="utf-8")
    print(f"[OK] Certificate saved to: {cert_path}")


def enroll_certificate():
    csr_pem = create_csr_pem()

    url = f"{BASE_URL}/api/accounts/certificates/enroll-file-client/"
    payload = {
        "csr_pem": csr_pem,
        "key_storage_type": "softhsm",
        "pkcs11_token_label": PKCS11_TOKEN_LABEL,
        "pkcs11_key_label": PKCS11_KEY_LABEL,
        "pkcs11_key_id": PKCS11_KEY_ID,
        "pkcs11_slot": PKCS11_SLOT,
    }

    resp = requests.post(url, json=payload, auth=get_basic_auth(), timeout=60)

    if not resp.ok:
        print("[ERROR] Enroll failed.")
        print("Status code:", resp.status_code)
        print("Response text:", resp.text)
        resp.raise_for_status()

    data = resp.json()
    print("[OK] Enroll response:")
    print(json.dumps(data, indent=2, ensure_ascii=False))

    save_certificate_if_present(data.get("certificate_pem"))


def show_config():
    print("=== PKCS#11 Enroll Config ===")
    print("BASE_URL:", BASE_URL)
    print("EMAIL:", EMAIL)
    print("PKCS11_LIB_PATH:", PKCS11_LIB_PATH)
    print("PKCS11_TOKEN_LABEL:", PKCS11_TOKEN_LABEL)
    print("PKCS11_KEY_LABEL:", PKCS11_KEY_LABEL)
    print("PKCS11_KEY_ID:", PKCS11_KEY_ID)
    print("PKCS11_SLOT:", PKCS11_SLOT)
    print("CSR_EMAIL:", CSR_EMAIL)
    print("=============================")


def main():
    show_config()
    enroll_certificate()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[FATAL] {type(e).__name__}: {e}")
        sys.exit(1)