from datetime import datetime, timedelta, timezone

from django.conf import settings
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from pathlib import Path
from typing import Optional
from .models import UserCertificate
from .pkcs11_utils import create_user_keypair_in_softhsm, load_public_key_from_softhsm, import_certificate_to_softhsm
import subprocess
import tempfile

def issue_certificate_for_user(user) -> UserCertificate:
    existing = getattr(user, "certificate_profile", None)
    if existing:
        return existing

    key_meta = create_user_keypair_in_softhsm(user)

    public_key = load_public_key_from_softhsm(key_meta["key_label"])

    with open(settings.PKI_ROOT_CA_KEY, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    with open(settings.PKI_ROOT_CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "HCM"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "HCM"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Citizen Portal"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, user.role.capitalize()),
        x509.NameAttribute(NameOID.COMMON_NAME, user.full_name or user.email),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, user.email),
    ])

    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=825))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        )
        .sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
        )
    )

    cert_pem = cert.public_bytes(
        serialization.Encoding.PEM
    ).decode("utf-8")
    
    user_cert_dir = Path(settings.PKI_USER_CERT_DIR)
    user_cert_dir.mkdir(parents=True, exist_ok=True)

    cert_path = user_cert_dir / f"user_{user.id}.crt"
    cert_path.write_text(cert_pem, encoding="utf-8")

    user_cert = UserCertificate.objects.create(
        user=user,
        certificate_pem=cert_pem,
        certificate_subject=cert.subject.rfc4514_string(),
        certificate_serial=str(cert.serial_number),
        key_storage_type=UserCertificate.KeyStorageType.SOFTHSM,
        private_key_path=None,
        pkcs11_token_label=key_meta["token_label"],
        pkcs11_key_label=key_meta["key_label"],
        pkcs11_key_id=key_meta["key_id"],
        issued_by=cert.issuer.rfc4514_string(),
        valid_from=cert.not_valid_before_utc,
        valid_to=cert.not_valid_after_utc,
        status=UserCertificate.Status.ACTIVE,
    )

    try:
        import_certificate_to_softhsm(user_cert)
    except Exception:
        pass

    return user_cert

def issue_certificate_from_csr_for_user(
    user,
    csr_pem: str,
    key_storage_type: str = UserCertificate.KeyStorageType.FILE,
    private_key_path: Optional[str] = None,
    pkcs11_token_label: Optional[str] = None,
    pkcs11_key_label: Optional[str] = None,
    pkcs11_key_id: Optional[str] = None,
    pkcs11_slot: Optional[str] = None,
):
    if user.role == user.Role.CITIZEN and not user.is_verified_identity:
        raise ValueError("Citizen identity must be verified before certificate issuance.")

    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid CSR PEM: {str(e)}")

    try:
        csr_email = csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value
        if csr_email.lower() != user.email.lower():
            raise ValueError("CSR email does not match authenticated user.")
    except IndexError:
        raise ValueError("CSR must contain an email address.")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        csr_path = tmpdir / "client_request.csr"
        cert_path = tmpdir / "client_certificate.pem"

        csr_path.write_text(csr_pem, encoding="utf-8")

        cmd = [
            str(settings.PKI_OPENSSL_BIN),
            "x509",
            "-req",
            "-in",
            str(csr_path),
            "-CA",
            str(settings.PKI_ROOT_CA_CERT),
            "-CAkey",
            str(settings.PKI_ROOT_CA_KEY),
            "-CAcreateserial",
            "-out",
            str(cert_path),
            "-days",
            "365",
            "-sha256",
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise ValueError(
                f"OpenSSL certificate issuance failed: {(proc.stdout or '')} {(proc.stderr or '')}".strip()
            )

        cert_pem = cert_path.read_text(encoding="utf-8")
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

    cert_subject = cert.subject.rfc4514_string()
    cert_serial = str(cert.serial_number)
    issued_by = cert.issuer.rfc4514_string()
    valid_from = cert.not_valid_before_utc
    valid_to = cert.not_valid_after_utc

    user_cert, created = UserCertificate.objects.update_or_create(
        user=user,
        defaults={
            "certificate_pem": cert_pem,
            "certificate_subject": cert_subject,
            "certificate_serial": cert_serial,
            "key_storage_type": key_storage_type,
            "private_key_path": private_key_path if key_storage_type == UserCertificate.KeyStorageType.FILE else None,
            "pkcs11_token_label": pkcs11_token_label if key_storage_type == UserCertificate.KeyStorageType.SOFTHSM else None,
            "pkcs11_key_label": pkcs11_key_label if key_storage_type == UserCertificate.KeyStorageType.SOFTHSM else None,
            "pkcs11_key_id": pkcs11_key_id if key_storage_type == UserCertificate.KeyStorageType.SOFTHSM else None,
            "pkcs11_slot": pkcs11_slot if key_storage_type == UserCertificate.KeyStorageType.SOFTHSM else None,
            "issued_by": issued_by,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "status": UserCertificate.Status.ACTIVE,
        },
    )

    return {
        "user_certificate": user_cert,
        "certificate_pem": cert_pem,
        "certificate_subject": cert_subject,
        "certificate_serial": cert_serial,
        "created": created,
    }
