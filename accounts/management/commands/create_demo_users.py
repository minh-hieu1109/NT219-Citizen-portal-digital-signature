from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from accounts.models import UserCertificate
from accounts.services import issue_certificate_for_user

User = get_user_model()


class Command(BaseCommand):
    help = "Create/update demo users for web portal walkthrough."

    def add_arguments(self, parser):
        parser.add_argument(
            "--citizen-unverified",
            action="store_true",
            help="Create citizen demo account as unverified identity.",
        )

    def _upsert_user(self, email, password, full_name, citizen_id, role, is_verified, is_staff, is_superuser):
        user, _ = User.objects.get_or_create(
            email=email,
            defaults={
                "username": email,
                "full_name": full_name,
                "citizen_id": citizen_id,
                # Avoid triggering admin auto-certificate signal on initial create.
                "role": User.Role.CITIZEN,
            },
        )

        user.username = email
        user.full_name = full_name
        user.citizen_id = citizen_id
        user.role = role
        user.is_verified_identity = is_verified
        user.is_staff = is_staff
        user.is_superuser = is_superuser
        user.is_active = True
        user.set_password(password)
        user.save()

        return user

    def handle(self, *args, **options):
        citizen_verified = not options["citizen_unverified"]

        admin = self._upsert_user(
            email="admin@example.com",
            password="Admin@123456",
            full_name="Demo Admin",
            citizen_id="DEMO-ADMIN-001",
            role=User.Role.ADMIN,
            is_verified=True,
            is_staff=True,
            is_superuser=True,
        )
        officer = self._upsert_user(
            email="officer@example.com",
            password="Officer@123456",
            full_name="Demo Officer",
            citizen_id="DEMO-OFFICER-001",
            role=User.Role.OFFICER,
            is_verified=True,
            is_staff=True,
            is_superuser=False,
        )
        citizen = self._upsert_user(
            email="citizen@example.com",
            password="Citizen@123456",
            full_name="Demo Citizen",
            citizen_id="DEMO-CITIZEN-001",
            role=User.Role.CITIZEN,
            is_verified=citizen_verified,
            is_staff=False,
            is_superuser=False,
        )

        for demo_user in [admin, officer, citizen]:
            cert = UserCertificate.objects.filter(
                user=demo_user,
                status=UserCertificate.Status.ACTIVE,
            ).first()
            if cert:
                continue
            try:
                issue_certificate_for_user(demo_user)
                self.stdout.write(self.style.SUCCESS(f"[OK] Active certificate ensured for {demo_user.email}"))
            except Exception as exc:
                self.stdout.write(self.style.WARNING(f"[WARNING] Could not issue certificate for {demo_user.email}: {exc}"))
                self.stdout.write(self.style.WARNING("Please use RA panel and PKI/SoftHSM setup before remote-sign demo."))

        self.stdout.write(self.style.SUCCESS("Demo users created/updated."))
        self.stdout.write("Demo credentials only (not for production):")
        self.stdout.write(f"- {admin.email} / Admin@123456")
        self.stdout.write(f"- {officer.email} / Officer@123456")
        self.stdout.write(f"- {citizen.email} / Citizen@123456 (verified={citizen.is_verified_identity})")
