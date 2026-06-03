from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand

from accounts.models import UserCertificate
from accounts.services import issue_certificate_from_csr_for_user
from documents.models import Document
from signing.models import SigningRequest

User = get_user_model()


class Command(BaseCommand):
    help = "Create deterministic demo data for file-based client signing."

    def add_arguments(self, parser):
        parser.add_argument("--email", default="client@example.com")
        parser.add_argument("--password", default="Client@123456")
        parser.add_argument("--key-dir", default="keys")
        parser.add_argument("--key-file", default="client_demo_private_key.pem")
        parser.add_argument("--csr-file", default="client_demo_request.csr")
        parser.add_argument("--cert-file", default="client_demo_certificate.pem")

    def _resolve_path(self, path_value):
        path = Path(path_value)
        if path.is_absolute():
            return path
        return settings.BASE_DIR / path

    def _upsert_client_user(self, email, password):
        user, _created = User.objects.get_or_create(
            email=email,
            defaults={
                "username": email,
                "full_name": "Demo Client Signer",
                "citizen_id": "DEMO-CLIENT-SIGNER-001",
                "role": User.Role.CITIZEN,
            },
        )
        user.username = email
        user.full_name = "Demo Client Signer"
        user.citizen_id = "DEMO-CLIENT-SIGNER-001"
        user.role = User.Role.CITIZEN
        user.is_verified_identity = True
        user.is_active = True
        user.set_password(password)
        user.save()
        return user

    def _load_or_create_private_key(self, key_path):
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            return serialization.load_pem_private_key(key_path.read_bytes(), password=None)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        return private_key

    def _build_csr(self, user, private_key, csr_path):
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "HCM"),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, "HCM"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Citizen Portal"),
                        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Client Signing Demo"),
                        x509.NameAttribute(NameOID.COMMON_NAME, user.full_name),
                        x509.NameAttribute(NameOID.EMAIL_ADDRESS, user.email),
                    ]
                )
            )
            .sign(private_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        csr_path.write_text(csr_pem, encoding="utf-8")
        return csr_pem

    def _cert_matches_private_key(self, cert_pem, private_key):
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        return cert.public_key().public_numbers() == private_key.public_key().public_numbers()

    def _ensure_certificate(self, user, private_key, key_path, csr_path, cert_path):
        existing = UserCertificate.objects.filter(
            user=user,
            status=UserCertificate.Status.ACTIVE,
        ).first()

        if existing and existing.certificate_pem:
            try:
                if self._cert_matches_private_key(existing.certificate_pem, private_key):
                    cert_path.write_text(existing.certificate_pem, encoding="utf-8")
                    return existing
            except Exception:
                pass

        csr_pem = self._build_csr(user, private_key, csr_path)
        issued = issue_certificate_from_csr_for_user(
            user=user,
            csr_pem=csr_pem,
            key_storage_type=UserCertificate.KeyStorageType.FILE,
            private_key_path=str(key_path),
        )
        cert_pem = issued["certificate_pem"]
        cert_path.write_text(cert_pem, encoding="utf-8")
        return issued["user_certificate"]

    def handle(self, *args, **options):
        email = options["email"]
        password = options["password"]
        key_dir = self._resolve_path(options["key_dir"])
        key_path = key_dir / options["key_file"]
        csr_path = key_dir / options["csr_file"]
        cert_path = key_dir / options["cert_file"]

        user = self._upsert_client_user(email, password)
        private_key = self._load_or_create_private_key(key_path)
        user_cert = self._ensure_certificate(user, private_key, key_path, csr_path, cert_path)

        content = b"client file signing demo payload"
        doc = Document.objects.create(
            owner=user,
            title="Client File Signing Demo Document",
            sha256_hash=sha256(content).hexdigest(),
            status=Document.Status.PENDING_SIGN,
        )
        doc.file.save("client_file_sign_demo_document.txt", ContentFile(content), save=True)

        signing_request = SigningRequest.objects.create(
            document=doc,
            requested_by=user,
            signer=user,
            signing_type=SigningRequest.SigningType.CLIENT,
            status=SigningRequest.Status.PENDING,
        )

        self.stdout.write(self.style.SUCCESS(f"[OK] Client signer ready: {email} / {password}"))
        self.stdout.write(self.style.SUCCESS(f"[OK] Active certificate serial: {user_cert.certificate_serial}"))
        self.stdout.write(self.style.SUCCESS(f"[OK] Private key: {key_path}"))
        self.stdout.write(self.style.SUCCESS(f"[OK] Certificate: {cert_path}"))
        self.stdout.write(self.style.SUCCESS(f"[OK] Client signing request id: {signing_request.id}"))
        self.stdout.write("")
        self.stdout.write("Run this from the host terminal:")
        self.stdout.write(
            "docker compose exec "
            "-e CLIENT_PRIVATE_KEY_FILENAME=%s "
            "-e CLIENT_CSR_FILENAME=%s "
            "-e CLIENT_CERT_FILENAME=%s "
            "-e TOOL_EMAIL=%s "
            "-e TOOL_PASSWORD=%s "
            "-e PORTAL_BASE_URL=http://127.0.0.1:8000 "
            "web python tools/client_file_sign_app.py %s"
            % (
                options["key_file"],
                options["csr_file"],
                options["cert_file"],
                email,
                password,
                signing_request.id,
            )
        )
