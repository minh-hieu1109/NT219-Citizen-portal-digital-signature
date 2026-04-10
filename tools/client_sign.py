import os
import sys
import json
import base64
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key


BASE_URL = os.environ.get("PORTAL_BASE_URL", "http://127.0.0.1:8000/api/signing")
ACCESS_TOKEN = os.environ.get("PORTAL_TOKEN", "")
PRIVATE_KEY_PATH = os.environ.get("CLIENT_KEY_PATH", "./client_key.pem")
CERT_PATH = os.environ.get("CLIENT_CERT_PATH", "./client_cert.pem")


def headers():
    return {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }


def prepare_client_sign(request_id: int):
    url = f"{BASE_URL}/requests/{request_id}/prepare-client-sign/"
    resp = requests.post(url, headers=headers(), timeout=30)
    resp.raise_for_status()
    return resp.json()


def complete_client_sign(request_id: int, signature_b64: str, certificate_pem: str):
    url = f"{BASE_URL}/requests/{request_id}/complete-client-sign/"
    payload = {
        "signature_value": signature_b64,
        "certificate_pem": certificate_pem,
        "algorithm": "RSA-SHA256",
    }
    resp = requests.post(url, headers=headers(), data=json.dumps(payload), timeout=30)
    resp.raise_for_status()
    return resp.json()


def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return load_pem_private_key(f.read(), password=None)


def load_certificate_pem():
    with open(CERT_PATH, "r", encoding="utf-8") as f:
        return f.read()


def sign_digest_hex(digest_hex: str) -> str:
    digest_bytes = bytes.fromhex(digest_hex)
    private_key = load_private_key()

    signature = private_key.sign(
        digest_bytes,
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256()),
    )
    return base64.b64encode(signature).decode("utf-8")


def main():
    if len(sys.argv) != 2:
        print("Usage: python tools/client_sign.py <signing_request_id>")
        sys.exit(1)

    request_id = int(sys.argv[1])

    prepare_data = prepare_client_sign(request_id)
    digest_hex = prepare_data["digest_hex"]

    signature_b64 = sign_digest_hex(digest_hex)
    certificate_pem = load_certificate_pem()

    result = complete_client_sign(request_id, signature_b64, certificate_pem)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()