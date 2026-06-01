from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from accounts.models import UserCertificate
from documents.models import Document
from signing.models import SigningRequest


User = get_user_model()


class SignerEligibilityTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            email="officerui@example.com",
            password="pass123",
            full_name="Officer UI",
            citizen_id="OFFICER-UI-001",
            role=User.Role.OFFICER,
            is_verified_identity=True,
            is_staff=True,
            is_superuser=False,
        )
        self.client.force_login(self.admin)

        self.doc = Document.objects.create(
            owner=self.admin,
            title="Doc for signer filter",
            file="documents/test.txt",
            sha256_hash="",
            status=Document.Status.UPLOADED,
        )

    def test_create_signing_request_page_filters_ineligible_signers(self):
        eligible = User.objects.create_user(
            email="eligible@example.com",
            password="pass123",
            full_name="Eligible",
            citizen_id="ELI-001",
            role=User.Role.CITIZEN,
            is_verified_identity=True,
        )
        User.objects.create_user(
            email="unverified@example.com",
            password="pass123",
            full_name="Unverified",
            citizen_id="UNV-001",
            role=User.Role.CITIZEN,
            is_verified_identity=False,
        )
        no_cert = User.objects.create_user(
            email="nocert@example.com",
            password="pass123",
            full_name="No Cert",
            citizen_id="NOC-001",
            role=User.Role.CITIZEN,
            is_verified_identity=True,
        )

        UserCertificate.objects.create(
            user=eligible,
            certificate_pem="pem",
            certificate_subject="CN=eligible",
            certificate_serial="ELI-SERIAL-001",
            key_storage_type=UserCertificate.KeyStorageType.FILE,
            private_key_path="/tmp/key.pem",
            status=UserCertificate.Status.ACTIVE,
        )

        response = self.client.get("/signing/requests/create/")
        self.assertEqual(response.status_code, 200)
        signer_qs = response.context["form"].fields["signer"].queryset
        self.assertIn(eligible, signer_qs)
        self.assertNotIn(no_cert, signer_qs)
        self.assertFalse(signer_qs.filter(email="unverified@example.com").exists())

    def test_signing_detail_hides_remote_sign_when_signer_has_no_certificate(self):
        signer = User.objects.create_user(
            email="signer-no-cert@example.com",
            password="pass123",
            full_name="Signer No Cert",
            citizen_id="SNC-001",
            role=User.Role.CITIZEN,
            is_verified_identity=True,
        )

        req = SigningRequest.objects.create(
            document=self.doc,
            requested_by=self.admin,
            signer=signer,
            signing_type=SigningRequest.SigningType.REMOTE,
            status=SigningRequest.Status.PENDING,
        )

        response = self.client.get(f"/signing/requests/{req.id}/")
        self.assertEqual(response.status_code, 200)
        content = response.content.decode("utf-8")
        self.assertIn("Signer has no certificate. Go to RA panel and issue a certificate first.", content)
        self.assertNotIn("Remote Sign</button>", content)


class CreateDemoUsersCommandTests(TestCase):
    @patch("accounts.management.commands.create_demo_users.issue_certificate_for_user")
    def test_create_demo_users_demo_ready_state(self, mock_issue_cert):
        call_command("create_demo_users")

        admin = User.objects.get(email="admin@example.com")
        officer = User.objects.get(email="officer@example.com")
        citizen = User.objects.get(email="citizen@example.com")

        self.assertTrue(admin.is_verified_identity)
        self.assertTrue(officer.is_verified_identity)
        self.assertTrue(citizen.is_verified_identity)
        self.assertEqual(citizen.role, User.Role.CITIZEN)
        self.assertGreaterEqual(mock_issue_cert.call_count, 1)
