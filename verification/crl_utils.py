from cryptography import x509
from django.conf import settings

def is_cert_revoked_in_crl(cert_serial: int) -> bool:
    crl_path = settings.PKI_CRL_DIR / "lab_ca.crl.pem"
    if not crl_path.exists():
        return False

    with open(crl_path, "rb") as f:
        crl = x509.load_pem_x509_crl(f.read())

    for revoked_cert in crl:
        if revoked_cert.serial_number == cert_serial:
            return True

    return False