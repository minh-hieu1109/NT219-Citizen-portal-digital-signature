import os
import sys
import json
import base64
from pathlib import Path

import requests
from dotenv import load_dotenv
from pkcs11 import lib, KeyType, ObjectClass, Mechanism


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

BASE_URL = os.getenv("PORTAL_BASE_URL", "http://web:8000").rstrip("/")
EMAIL = os.getenv("TOOL_EMAIL")
PASSWORD = os.getenv("TOOL_PASSWORD")

PKCS11_LIB_PATH = os.getenv("PKCS11_LIB_PATH", "/usr/lib/softhsm/libsofthsm2.so")
PKCS11_TOKEN_LABEL = os.getenv("PKCS11_TOKEN_LABEL", "citizen-client-token")
PKCS11_USER_PIN = os.getenv("PKCS11_USER_PIN", "123456")
PKCS11_KEY_LABEL = os.getenv("PKCS11_KEY_LABEL", "CitizenClientKey")


def get_basic_auth():
    if not EMAIL or not PASSWORD:
        raise ValueError("TOOL_EMAIL / TOOL_PASSWORD is missing.")
    return (EMAIL, PASSWORD)


def prepare_client_sign(signing_request_id: int):
    url = f"{BASE_URL}/api/signing/requests/{signing_request_id}/prepare-client-sign/"
    resp = requests.post(url, auth=get_basic_auth(), timeout=60)

    if not resp.ok:
        print("[ERROR] Prepare client sign failed.")
        print("Status code:", resp.status_code)
        print("Response text:", resp.text)
        resp.raise_for_status()

    data = resp.json()
    print("[OK] Prepare response:")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return data


def complete_client_sign(signing_request_id: int, signature_b64: str):
    url = f"{BASE_URL}/api/signing/requests/{signing_request_id}/complete-client-sign/"
    payload = {
        "signature_value": signature_b64,
        "algorithm": "RSA-SHA256-PREHASHED",
    }

    resp = requests.post(url, json=payload, auth=get_basic_auth(), timeout=60)

    if not resp.ok:
        print("[ERROR] Complete client sign failed.")
        print("Status code:", resp.status_code)
        print("Response text:", resp.text)
        resp.raise_for_status()

    data = resp.json()
    print("[OK] Complete response:")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return data


def sign_digest_hex(digest_hex: str) -> str:
    digest_bytes = bytes.fromhex(digest_hex)

    sha256_digestinfo_prefix = bytes.fromhex(
        "3031300d060960864801650304020105000420"
    )
    digest_info = sha256_digestinfo_prefix + digest_bytes

    p11 = lib(PKCS11_LIB_PATH)
    token = p11.get_token(token_label=PKCS11_TOKEN_LABEL)

    with token.open(user_pin=PKCS11_USER_PIN) as session:
        private_key = session.get_key(
            object_class=ObjectClass.PRIVATE_KEY,
            key_type=KeyType.RSA,
            label=PKCS11_KEY_LABEL,
        )

        signature = private_key.sign(digest_info, mechanism=Mechanism.RSA_PKCS)
        return base64.b64encode(signature).decode("utf-8")


def sign_request(signing_request_id: int):
    prepare_data = prepare_client_sign(signing_request_id)
    digest_hex = prepare_data["digest_hex"]

    signature_b64 = sign_digest_hex(digest_hex)
    print("[OK] PKCS#11 signature generated.")

    complete_client_sign(signing_request_id, signature_b64)


def main():
    if len(sys.argv) != 2:
        print("Usage: python tools/client_pkcs11_sign.py <signing_request_id>")
        sys.exit(1)

    try:
        request_id = int(sys.argv[1])
    except ValueError:
        print("Signing request id must be a number.")
        sys.exit(1)

    sign_request(request_id)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[FATAL] {type(e).__name__}: {e}")
        sys.exit(1)