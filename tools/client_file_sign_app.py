import base64
import json
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID


BASE_URL = "http://127.0.0.1:8000"
EMAIL = "citizen6@example.com"
PASSWORD = "Mhiu@123"

KEY_DIR = Path(r"C:\Users\LENOVO\Desktop\mmh\citizen-portal\keys")
PRIVATE_KEY_PATH = KEY_DIR / "client_private_key.pem"
CSR_PATH = KEY_DIR / "client_request.csr"
CERT_PATH = KEY_DIR / "client_certificate.pem"


def ensure_key_dir():
    KEY_DIR.mkdir(parents=True, exist_ok=True)


def get_basic_auth():
    return (EMAIL, PASSWORD)


def generate_private_key_if_missing():
    ensure_key_dir()

    if PRIVATE_KEY_PATH.exists():
        print(f"[OK] Private key already exists: {PRIVATE_KEY_PATH}")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    PRIVATE_KEY_PATH.write_bytes(pem)
    print(f"[OK] Generated private key: {PRIVATE_KEY_PATH}")


def load_private_key():
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError(f"Private key not found: {PRIVATE_KEY_PATH}")

    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=None,
    )


def create_csr():
    private_key = load_private_key()

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "HCM"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "HCM"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Citizen Portal"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Citizen"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "Citizen Four"),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, EMAIL),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    CSR_PATH.write_bytes(csr_pem)
    print(f"[OK] CSR written: {CSR_PATH}")
    return csr_pem.decode("utf-8")


def enroll_certificate():
    enroll_url = f"{BASE_URL}/api/accounts/certificates/enroll-file-client/"
    csr_pem = create_csr()

    headers = {
        "Content-Type": "application/json",
    }

    payload = {
        "csr_pem": csr_pem,
        "key_storage_type": "file",
    }

    resp = requests.post(
        enroll_url,
        headers=headers,
        auth=get_basic_auth(),
        data=json.dumps(payload),
        timeout=60,
    )

    try:
        resp.raise_for_status()
    except requests.HTTPError:
        print("[ERROR] Enroll failed.")
        print("Status code:", resp.status_code)
        print("Response text:", resp.text)
        raise

    data = resp.json()

    cert_pem = data["certificate_pem"]
    CERT_PATH.write_text(cert_pem, encoding="utf-8")
    print(f"[OK] Certificate saved: {CERT_PATH}")
    print(f"[OK] Certificate serial: {data.get('certificate_serial')}")
    return data


def prepare_client_sign(signing_request_id: int):
    url = f"{BASE_URL}/api/signing/requests/{signing_request_id}/prepare-client-sign/"

    resp = requests.post(
        url,
        auth=get_basic_auth(),
        timeout=60,
    )

    try:
        resp.raise_for_status()
    except requests.HTTPError:
        print("[ERROR] Prepare client sign failed.")
        print("Status code:", resp.status_code)
        print("Response text:", resp.text)
        raise

    data = resp.json()
    print("[OK] Prepare response:")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return data


def sign_digest_hex(digest_hex: str) -> str:
    private_key = load_private_key()
    digest_bytes = bytes.fromhex(digest_hex)

    signature_bytes = private_key.sign(
        digest_bytes,
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256()),
    )

    signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")
    return signature_b64


def complete_client_sign(signing_request_id: int, signature_b64: str):
    url = f"{BASE_URL}/api/signing/requests/{signing_request_id}/complete-client-sign/"
    headers = {
        "Content-Type": "application/json",
    }

    payload = {
        "signature_value": signature_b64,
        "algorithm": "RSA-SHA256-PREHASHED",
    }

    resp = requests.post(
        url,
        headers=headers,
        auth=get_basic_auth(),
        json=payload,
        timeout=60,
    )

    try:
        resp.raise_for_status()
    except requests.HTTPError:
        print("[ERROR] Complete client sign failed.")
        print("Status code:", resp.status_code)
        print("Response text:", resp.text)
        raise

    data = resp.json()
    print("[OK] Complete response:")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return data


def enroll_only():
    generate_private_key_if_missing()
    enroll_certificate()


def sign_request(signing_request_id: int):
    prepare_data = prepare_client_sign(signing_request_id)
    digest_hex = prepare_data["digest_hex"]

    signature_b64 = sign_digest_hex(digest_hex)
    print("[OK] Signature generated.")

    complete_client_sign(signing_request_id, signature_b64)


if __name__ == "__main__":
    # Dùng lần đầu để sinh key + CSR + enroll cert:
    # enroll_only()

    # Sau khi đã có SigningRequest loại client:
    sign_request(19)