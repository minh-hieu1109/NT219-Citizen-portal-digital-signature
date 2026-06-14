from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from accounts.models import UserCertificate


def _load_lab_ca():
    with open(settings.PKI_ROOT_CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    with open(settings.PKI_ROOT_CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    return ca_cert, ca_key


def regenerate_lab_crl() -> Path:
    ca_cert, ca_key = _load_lab_ca()

    now = datetime.now(dt_timezone.utc)
    next_update = now + timedelta(days=30)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
        .add_extension(
            x509.CRLNumber(int(now.timestamp())),
            critical=False,
        )
    )

    revoked_profiles = UserCertificate.objects.filter(
        status=UserCertificate.Status.REVOKED
    )

    for profile in revoked_profiles:
        cert = x509.load_pem_x509_certificate(
            profile.certificate_pem.encode("utf-8")
        )

        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(cert.serial_number)
            .revocation_date(now)
            .add_extension(
                x509.CRLReason(x509.ReasonFlags.key_compromise),
                critical=False,
            )
            .build()
        )

        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )

    crl_dir = Path(settings.PKI_CRL_DIR)
    crl_dir.mkdir(parents=True, exist_ok=True)

    crl_path = crl_dir / "lab_ca.crl.pem"
    crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    return crl_path


def revoke_user_certificate(user_cert: UserCertificate) -> Path:
    if user_cert.status != UserCertificate.Status.REVOKED:
        user_cert.status = UserCertificate.Status.REVOKED
        user_cert.save(update_fields=["status"])

    return regenerate_lab_crl()