from pathlib import Path
import json
import os

from dotenv import load_dotenv
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# =========================
# CẤU HÌNH
# =========================
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')

key_dir_value = os.getenv('CLIENT_KEY_DIR', str(BASE_DIR / 'keys'))
KEY_DIR = Path(key_dir_value)
if not KEY_DIR.is_absolute():
    KEY_DIR = (BASE_DIR / KEY_DIR).resolve()
KEY_PATH = KEY_DIR / os.getenv('CLIENT_PRIVATE_KEY_FILENAME', 'client_private_key.pem')
CSR_PATH = KEY_DIR / os.getenv('CLIENT_CSR_FILENAME', 'client_request.csr')
CERT_PATH = KEY_DIR / os.getenv('CLIENT_CERT_FILENAME', 'client_certificate.pem')

BASE_URL = os.getenv('PORTAL_BASE_URL', 'http://127.0.0.1:8000')
ENROLL_URL = f"{BASE_URL}/api/accounts/certificates/enroll-file-client/"

# Basic Auth giống Postman
USERNAME = os.getenv('TOOL_EMAIL', 'citizen6@example.com')
PASSWORD = os.getenv('TOOL_PASSWORD', 'Mhiu@123')

# Thông tin subject cho CSR
CSR_COUNTRY = os.getenv('CLIENT_CSR_COUNTRY', 'VN')
CSR_STATE = os.getenv('CLIENT_CSR_STATE', 'HCM')
CSR_LOCALITY = os.getenv('CLIENT_CSR_LOCALITY', 'HCM')
CSR_ORG = os.getenv('CLIENT_CSR_ORG', 'Citizen Portal')
CSR_OU = os.getenv('CLIENT_CSR_OU', 'Citizen')
CSR_COMMON_NAME = os.getenv('CLIENT_CSR_COMMON_NAME', USERNAME)
CSR_EMAIL = os.getenv('CLIENT_CSR_EMAIL', USERNAME)


# =========================
# HÀM TIỆN ÍCH
# =========================
def ensure_base_dir():
    BASE_DIR.mkdir(parents=True, exist_ok=True)


def get_basic_auth():
    return (USERNAME, PASSWORD)


# =========================
# KEY
# =========================
def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    ensure_base_dir()

    with open(KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print(f"[OK] Generated private key: {KEY_PATH}")
    return private_key


def load_or_create_private_key():
    ensure_base_dir()

    if KEY_PATH.exists():
        with open(KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        print(f"[OK] Loaded existing private key: {KEY_PATH}")
        return private_key

    return generate_private_key()


# =========================
# CSR
# =========================
def build_csr(private_key):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, CSR_COUNTRY),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CSR_STATE),
                x509.NameAttribute(NameOID.LOCALITY_NAME, CSR_LOCALITY),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, CSR_ORG),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, CSR_OU),
                x509.NameAttribute(NameOID.COMMON_NAME, CSR_COMMON_NAME),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, CSR_EMAIL),
            ])
        )
        .sign(private_key, hashes.SHA256())
    )

    with open(CSR_PATH, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"[OK] CSR written: {CSR_PATH}")
    return csr


def read_csr_pem():
    if not CSR_PATH.exists():
        raise FileNotFoundError(f"CSR file not found: {CSR_PATH}")

    with open(CSR_PATH, "r", encoding="utf-8") as f:
        return f.read()


# =========================
# ENROLL CERTIFICATE
# =========================
def enroll_certificate():
    csr_pem = read_csr_pem()

    payload = {
        "csr_pem": csr_pem,
        "key_storage_type": "file",
        "private_key_path": os.getenv("CLIENT_PRIVATE_KEY_PATH", "/app/keys/" + os.getenv('CLIENT_PRIVATE_KEY_FILENAME', 'client_private_key.pem')),
    }

    headers = {
        "Content-Type": "application/json",
    }

    resp = requests.post(
        ENROLL_URL,
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
    print("[OK] Enroll API call succeeded.")
    return data


def save_certificate(cert_pem: str):
    with open(CERT_PATH, "w", encoding="utf-8") as f:
        f.write(cert_pem)
    print(f"[OK] Certificate saved: {CERT_PATH}")


# =========================
# FLOW CHÍNH
# =========================
def main():
    print("=== CLIENT ENROLL FLOW START ===")

    private_key = load_or_create_private_key()
    build_csr(private_key)

    print("[INFO] Sending CSR to server for certificate issuance via Basic Auth...")
    result = enroll_certificate()

    cert_pem = result.get("certificate_pem")
    if not cert_pem:
        raise ValueError(f"Server response missing certificate_pem: {result}")

    save_certificate(cert_pem)

    print("\n=== ENROLL SUCCESS ===")
    print("Message:", result.get("message"))
    print("Certificate subject:", result.get("certificate_subject"))
    print("Certificate serial:", result.get("certificate_serial"))


if __name__ == "__main__":
    main()