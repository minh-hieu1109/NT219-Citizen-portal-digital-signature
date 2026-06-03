import subprocess
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand

from accounts.models import UserCertificate
from accounts.services import issue_certificate_from_csr_for_user
from documents.models import Document
from signing.models import SigningRequest
from verification.crl_utils import is_cert_revoked_in_crl

User = get_user_model()


class Command(BaseCommand):
    help = "Create deterministic web demo data for citizen document signing."

    def _upsert_user(self, *, email, password, full_name, citizen_id, role, verified, is_staff=False, is_superuser=False):
        user, _created = User.objects.get_or_create(
            email=email,
            defaults={
                "username": email,
                "full_name": full_name,
                "citizen_id": citizen_id,
                "role": User.Role.CITIZEN,
            },
        )
        user.username = email
        user.full_name = full_name
        user.citizen_id = citizen_id
        user.role = role
        user.is_verified_identity = verified
        user.is_staff = is_staff
        user.is_superuser = is_superuser
        user.is_active = True
        user.set_password(password)
        user.save()
        return user

    def _cert_key_match(self, cert_pem: str, key_path: str) -> bool:
        key_file = Path(key_path)
        if not key_file.exists():
            return False
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        return cert.public_key().public_numbers() == private_key.public_key().public_numbers()

    def _ensure_file_cert(self, user, key_path: Path, csr_path: Path) -> UserCertificate:
        existing = UserCertificate.objects.filter(
            user=user,
            status=UserCertificate.Status.ACTIVE,
            key_storage_type=UserCertificate.KeyStorageType.FILE,
        ).first()
        if existing and existing.private_key_path:
            try:
                cert = x509.load_pem_x509_certificate(existing.certificate_pem.encode("utf-8"))
                if (
                    self._cert_key_match(existing.certificate_pem, existing.private_key_path)
                    and not is_cert_revoked_in_crl(cert.serial_number)
                ):
                    return existing
            except Exception:
                pass

        key_path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [str(settings.PKI_OPENSSL_BIN), "genrsa", "-out", str(key_path), "2048"],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                str(settings.PKI_OPENSSL_BIN),
                "req",
                "-new",
                "-key",
                str(key_path),
                "-out",
                str(csr_path),
                "-subj",
                f"/C=VN/ST=HCM/L=HCM/O=Citizen Portal/OU={user.role}/CN={user.full_name}/emailAddress={user.email}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        issued = issue_certificate_from_csr_for_user(
            user=user,
            csr_pem=csr_path.read_text(encoding="utf-8"),
            key_storage_type=UserCertificate.KeyStorageType.FILE,
            private_key_path=str(key_path),
        )
        user_cert = issued["user_certificate"]
        cert = x509.load_pem_x509_certificate(user_cert.certificate_pem.encode("utf-8"))
        if is_cert_revoked_in_crl(cert.serial_number):
            raise RuntimeError(f"Generated certificate for {user.email} is revoked in CRL.")
        if not self._cert_key_match(user_cert.certificate_pem, user_cert.private_key_path or ""):
            raise RuntimeError(f"Generated certificate/private key for {user.email} do not match.")
        return user_cert

    def handle(self, *args, **options):
        admin = self._upsert_user(
            email="admin@example.com",
            password="Admin@123456",
            full_name="Demo Admin",
            citizen_id="DEMO-ADMIN-001",
            role=User.Role.ADMIN,
            verified=True,
            is_staff=True,
            is_superuser=True,
        )
        officer = self._upsert_user(
            email="officer@example.com",
            password="Officer@123456",
            full_name="Demo Officer",
            citizen_id="DEMO-OFFICER-001",
            role=User.Role.OFFICER,
            verified=True,
            is_staff=True,
        )
        citizen = self._upsert_user(
            email="citizen@example.com",
            password="Citizen@123456",
            full_name="Demo Citizen",
            citizen_id="DEMO-CITIZEN-001",
            role=User.Role.CITIZEN,
            verified=True,
        )

        out_dir = Path("/app/experiments/results/keys")
        citizen_cert = self._ensure_file_cert(
            citizen,
            out_dir / "web_demo_citizen_key.pem",
            out_dir / "web_demo_citizen.csr",
        )
        self.stdout.write(self.style.SUCCESS(f"[OK] Citizen active certificate ready: serial={citizen_cert.certificate_serial}"))

        for user, key_name, csr_name in [
            (admin, "web_demo_admin_key.pem", "web_demo_admin.csr"),
            (officer, "web_demo_officer_key.pem", "web_demo_officer.csr"),
        ]:
            try:
                self._ensure_file_cert(user, out_dir / key_name, out_dir / csr_name)
                self.stdout.write(self.style.SUCCESS(f"[OK] {user.email} certificate ready for RA/approval demos."))
            except Exception as exc:
                self.stdout.write(self.style.WARNING(f"[WARNING] Could not ensure certificate for {user.email}: {exc}"))

        content = b"web demo citizen signing payload"
        doc = Document.objects.create(
            owner=citizen,
            title="Citizen Signing Demo Document",
            status=Document.Status.UPLOADED,
            sha256_hash=sha256(content).hexdigest(),
        )
        doc.file.save("citizen_signing_demo_document.txt", ContentFile(content), save=True)

        existing_pending = SigningRequest.objects.filter(
            requested_by=citizen,
            signer=citizen,
            signing_type=SigningRequest.SigningType.CLIENT,
            status=SigningRequest.Status.PENDING,
        ).first()

        if existing_pending:
            req = existing_pending
        else:
            req = SigningRequest.objects.create(
                document=doc,
                requested_by=citizen,
                signer=citizen,
                signing_type=SigningRequest.SigningType.CLIENT,
                status=SigningRequest.Status.PENDING,
            )
            doc.status = Document.Status.PENDING_SIGN
            doc.save(update_fields=["status", "updated_at"])

        self.stdout.write(self.style.SUCCESS(f"[OK] Citizen client signing request ready: id={req.id}"))
        self.stdout.write("Next steps:")
        self.stdout.write("1) Login citizen@example.com -> Citizen Upload & Sign")
        self.stdout.write("2) Citizen signs with their own certificate/private key")
        self.stdout.write("3) Verify result and download verification package")
