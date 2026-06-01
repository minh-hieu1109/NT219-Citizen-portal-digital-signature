import subprocess
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
    help = "Create deterministic web demo data (users/cert/document/pending remote request)."

    def _upsert_user(self, *, email, password, full_name, citizen_id, role, verified, is_staff=False, is_superuser=False):
        user, _ = User.objects.get_or_create(
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

    def _ensure_file_cert(self, user, key_path: Path, csr_path: Path):
        key_path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [str(settings.PKI_OPENSSL_BIN), "genrsa", "-out", str(key_path), "2048"],
            check=True,
            capture_output=True,
            text=True,
        )
        subj = f"/C=VN/ST=HCM/L=HCM/O=Citizen Portal/OU={user.role}/CN={user.full_name}/emailAddress={user.email}"
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
                subj,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        csr_pem = csr_path.read_text(encoding="utf-8")
        issue_certificate_from_csr_for_user(
            user=user,
            csr_pem=csr_pem,
            key_storage_type=UserCertificate.KeyStorageType.FILE,
            private_key_path=str(key_path),
        )

    def _ensure_active_officer_certificate(self, officer):
        existing = UserCertificate.objects.filter(user=officer, status=UserCertificate.Status.ACTIVE).first()
        if existing and existing.key_storage_type == UserCertificate.KeyStorageType.FILE and existing.private_key_path:
            try:
                cert = x509.load_pem_x509_certificate(existing.certificate_pem.encode("utf-8"))
                if self._cert_key_match(existing.certificate_pem, existing.private_key_path) and not is_cert_revoked_in_crl(cert.serial_number):
                    return existing
            except Exception:
                pass

        # Try known-good lab pair first (if not revoked).
        lab_cert = Path("/app/pki-lab/certs/users/user_4.crt")
        lab_key = Path("/app/pki-lab/users/private/user_4_key.pem")
        if lab_cert.exists() and lab_key.exists():
            cert_pem = lab_cert.read_text(encoding="utf-8")
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            if not is_cert_revoked_in_crl(cert.serial_number) and self._cert_key_match(cert_pem, str(lab_key)):
                profile, _ = UserCertificate.objects.update_or_create(
                    user=officer,
                    defaults={
                        "certificate_pem": cert_pem,
                        "certificate_subject": cert.subject.rfc4514_string(),
                        "certificate_serial": str(cert.serial_number),
                        "key_storage_type": UserCertificate.KeyStorageType.FILE,
                        "private_key_path": str(lab_key),
                        "issued_by": cert.issuer.rfc4514_string(),
                        "valid_from": cert.not_valid_before_utc,
                        "valid_to": cert.not_valid_after_utc,
                        "status": UserCertificate.Status.ACTIVE,
                        "pkcs11_token_label": None,
                        "pkcs11_key_label": None,
                        "pkcs11_key_id": None,
                        "pkcs11_slot": None,
                    },
                )
                return profile

        # Fallback: generate demo-only file key/cert.
        out_dir = Path("/app/experiments/results/keys")
        key_path = out_dir / "web_demo_officer_key.pem"
        csr_path = out_dir / "web_demo_officer.csr"
        self._ensure_file_cert(officer, key_path, csr_path)
        profile = UserCertificate.objects.get(user=officer)
        cert = x509.load_pem_x509_certificate(profile.certificate_pem.encode("utf-8"))
        if is_cert_revoked_in_crl(cert.serial_number):
            raise RuntimeError("Generated officer certificate is revoked in CRL; cannot use for demo")
        if not self._cert_key_match(profile.certificate_pem, profile.private_key_path or ""):
            raise RuntimeError("Generated officer certificate/private key do not match")
        return profile

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
            is_superuser=False,
        )
        citizen = self._upsert_user(
            email="citizen@example.com",
            password="Citizen@123456",
            full_name="Demo Citizen",
            citizen_id="DEMO-CITIZEN-001",
            role=User.Role.CITIZEN,
            verified=True,
            is_staff=False,
            is_superuser=False,
        )

        officer_cert = self._ensure_active_officer_certificate(officer)
        self.stdout.write(self.style.SUCCESS(f"[OK] Officer active certificate ready: serial={officer_cert.certificate_serial}"))

        # Optional: try to ensure admin cert (best effort)
        try:
            if not UserCertificate.objects.filter(user=admin, status=UserCertificate.Status.ACTIVE).exists():
                out_dir = Path("/app/experiments/results/keys")
                self._ensure_file_cert(admin, out_dir / "web_demo_admin_key.pem", out_dir / "web_demo_admin.csr")
                self.stdout.write(self.style.SUCCESS("[OK] Admin active certificate ensured."))
        except Exception as exc:
            self.stdout.write(self.style.WARNING(f"[WARNING] Could not ensure admin certificate: {exc}"))

        doc = Document.objects.create(
            owner=citizen,
            title="Web Demo Document",
            status=Document.Status.UPLOADED,
            sha256_hash="",
        )
        content = b"web demo deterministic payload"
        doc.file.save("web_demo_document.txt", ContentFile(content), save=True)

        existing_pending = SigningRequest.objects.filter(
            requested_by=citizen,
            signer=officer,
            signing_type=SigningRequest.SigningType.REMOTE,
            status=SigningRequest.Status.PENDING,
        ).first()

        if existing_pending:
            req = existing_pending
        else:
            req = SigningRequest.objects.create(
                document=doc,
                requested_by=citizen,
                signer=officer,
                signing_type=SigningRequest.SigningType.REMOTE,
                status=SigningRequest.Status.PENDING,
            )
            doc.status = Document.Status.PENDING_SIGN
            doc.save(update_fields=["status", "updated_at"])

        self.stdout.write(self.style.SUCCESS(f"[OK] Demo request ready: id={req.id}"))
        self.stdout.write("Next steps:")
        self.stdout.write("1) Login citizen@example.com -> view document/request")
        self.stdout.write("2) Login officer@example.com -> remote sign")
        self.stdout.write("3) Login citizen/admin -> verify result")
