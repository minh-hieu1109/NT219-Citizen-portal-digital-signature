import base64
import json
import os
from pathlib import Path

from dotenv import load_dotenv
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')

BASE_URL = os.getenv('PORTAL_BASE_URL', 'http://127.0.0.1:8000')
EMAIL = os.getenv('TOOL_EMAIL', 'client@example.com')
PASSWORD = os.getenv('TOOL_PASSWORD', 'Client@123456')

key_dir_value = os.getenv('CLIENT_KEY_DIR', str(BASE_DIR / 'keys'))
KEY_DIR = Path(key_dir_value)
if not KEY_DIR.is_absolute():
    KEY_DIR = (BASE_DIR / KEY_DIR).resolve()
PRIVATE_KEY_PATH = KEY_DIR / os.getenv('CLIENT_PRIVATE_KEY_FILENAME', 'client_private_key.pem')
CSR_PATH = KEY_DIR / os.getenv('CLIENT_CSR_FILENAME', 'client_request.csr')
CERT_PATH = KEY_DIR / os.getenv('CLIENT_CERT_FILENAME', 'client_certificate.pem')

CSR_COUNTRY = os.getenv('CLIENT_CSR_COUNTRY', 'VN')
CSR_STATE = os.getenv('CLIENT_CSR_STATE', 'HCM')
CSR_LOCALITY = os.getenv('CLIENT_CSR_LOCALITY', 'HCM')
CSR_ORG = os.getenv('CLIENT_CSR_ORG', 'Citizen Portal')
CSR_OU = os.getenv('CLIENT_CSR_OU', 'Citizen')
CSR_COMMON_NAME = os.getenv('CLIENT_CSR_COMMON_NAME', EMAIL)
CSR_EMAIL = os.getenv('CLIENT_CSR_EMAIL', EMAIL)


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
                    x509.NameAttribute(NameOID.COUNTRY_NAME, CSR_COUNTRY),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CSR_STATE),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, CSR_LOCALITY),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, CSR_ORG),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, CSR_OU),
                    x509.NameAttribute(NameOID.COMMON_NAME, CSR_COMMON_NAME),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, CSR_EMAIL),
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
        "private_key_path": os.getenv(
            "CLIENT_PRIVATE_KEY_PATH",
            f"/app/keys/{PRIVATE_KEY_PATH.name}",
        ),
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
        if resp.status_code == 400 and 'Signer does not have a certificate' in resp.text:
            print("-> No certificate found for signer. Run: python tools/client_enroll_file.py")
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
    import sys

    if len(sys.argv) == 2 and sys.argv[1] == '--enroll':
        enroll_only()
        sys.exit(0)

    if len(sys.argv) != 2:
        print("Usage: python tools/client_file_sign_app.py <signing_request_id>")
        print("       python tools/client_file_sign_app.py --enroll")
        print("Example: python tools/client_file_sign_app.py 3")
        sys.exit(1)

    try:
        request_id = int(sys.argv[1])
    except ValueError:
        print("Signing request id must be a number.")
        sys.exit(1)

    sign_request(request_id)
