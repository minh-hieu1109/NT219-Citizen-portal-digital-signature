from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from accounts.models import UserCertificate
from audit.models import AuditLog
from documents.models import Document
from signing.models import SignatureRecord, SigningRequest

User = get_user_model()


class FinalWebUXTests(TestCase):
    def setUp(self):
        self.citizen = User.objects.create_user(
            email="citizen-ux@example.com",
            password="pass123",
            full_name="Citizen UX",
            citizen_id="UX-CIT-001",
            role=User.Role.CITIZEN,
            is_verified_identity=True,
        )
        self.officer = User.objects.create_user(
            email="officer-ux@example.com",
            password="pass123",
            full_name="Officer UX",
            citizen_id="UX-OFF-001",
            role=User.Role.OFFICER,
            is_verified_identity=True,
            is_staff=True,
        )
        UserCertificate.objects.create(
            user=self.officer,
            certificate_pem="pem",
            certificate_subject="CN=officer",
            certificate_serial="UX-OFF-CERT-001",
            key_storage_type=UserCertificate.KeyStorageType.FILE,
            private_key_path="/tmp/officer.key",
            status=UserCertificate.Status.ACTIVE,
        )
        UserCertificate.objects.create(
            user=self.citizen,
            certificate_pem="pem",
            certificate_subject="CN=citizen",
            certificate_serial="UX-CIT-CERT-001",
            key_storage_type=UserCertificate.KeyStorageType.FILE,
            private_key_path="/tmp/citizen.key",
            status=UserCertificate.Status.ACTIVE,
        )
        self.document = Document.objects.create(
            owner=self.citizen,
            title="UX Document",
            file="documents/ux.txt",
            sha256_hash="123",
            status=Document.Status.UPLOADED,
        )

    def test_create_signing_request_creates_audit_log(self):
        self.client.force_login(self.citizen)
        response = self.client.post(
            "/signing/requests/create/",
            {"document": self.document.id, "signing_type": "client"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.SIGNING_REQUEST_CREATED,
                object_type="SigningRequest",
            ).exists()
        )

    @patch("frontend.views.remote_sign_signing_request")
    def test_remote_sign_creates_audit_log(self, mock_remote_sign):
        req = SigningRequest.objects.create(
            document=self.document,
            requested_by=self.citizen,
            signer=self.officer,
            signing_type=SigningRequest.SigningType.REMOTE,
            status=SigningRequest.Status.PENDING,
        )
        mock_remote_sign.return_value = SignatureRecord.objects.create(
            signing_request=req,
            signature_value="sig",
            signed_hash="abc",
        )
        self.client.force_login(self.officer)
        response = self.client.post(f"/signing/requests/{req.id}/remote-sign/", follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.OFFICER_APPROVAL_SIGNED,
                object_type="SignatureRecord",
            ).exists()
        )

    @patch("frontend.views.verify_signature_record")
    def test_verify_signature_creates_audit_log(self, mock_verify):
        req = SigningRequest.objects.create(
            document=self.document,
            requested_by=self.citizen,
            signer=self.officer,
            signing_type=SigningRequest.SigningType.REMOTE,
            status=SigningRequest.Status.SIGNED,
        )
        signature = SignatureRecord.objects.create(
            signing_request=req,
            signature_value="sig",
            signed_hash="abc",
        )
        fake_result = type("FakeResult", (), {"id": 777, "status": "valid"})()
        mock_verify.return_value = fake_result
        self.client.force_login(self.officer)
        response = self.client.post(f"/verification/signature/{signature.id}/verify/", follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.VERIFICATION_RUN,
                object_type="VerificationResult",
                object_id=777,
            ).exists()
        )

    def test_logout_works_via_post_and_requires_login_again(self):
        self.client.force_login(self.citizen)
        response = self.client.post("/accounts/logout/", follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Login")
        protected = self.client.get("/documents/", follow=False)
        self.assertEqual(protected.status_code, 302)
        self.assertIn("/accounts/login/", protected["Location"])

    def test_registration_page_loads_and_registers_unverified_citizen(self):
        response = self.client.get("/accounts/register/")
        self.assertEqual(response.status_code, 200)
        post = self.client.post(
            "/accounts/register/",
            {
                "email": "newcitizen@example.com",
                "full_name": "New Citizen",
                "citizen_id": "NEW-CIT-001",
                "password": "pass123ABC",
                "confirm_password": "pass123ABC",
            },
            follow=True,
        )
        self.assertEqual(post.status_code, 200)
        new_user = User.objects.get(email="newcitizen@example.com")
        self.assertEqual(new_user.role, User.Role.CITIZEN)
        self.assertFalse(new_user.is_verified_identity)
        self.client.force_login(self.officer)
        ra_response = self.client.get("/ra/pending/")
        self.assertContains(ra_response, "newcitizen@example.com")

    def test_registration_duplicate_email_rejected(self):
        response = self.client.post(
            "/accounts/register/",
            {
                "email": self.citizen.email,
                "full_name": "Dup Citizen",
                "citizen_id": "DUP-CIT-001",
                "password": "pass123ABC",
                "confirm_password": "pass123ABC",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Email is already registered.")

    def test_expired_request_hides_remote_sign_button(self):
        req = SigningRequest.objects.create(
            document=self.document,
            requested_by=self.citizen,
            signer=self.officer,
            signing_type=SigningRequest.SigningType.REMOTE,
            status=SigningRequest.Status.PENDING,
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        self.client.force_login(self.officer)
        response = self.client.get(f"/signing/requests/{req.id}/")
        self.assertEqual(response.status_code, 200)
        content = response.content.decode("utf-8")
        self.assertIn("This signing request has expired.", content)
        self.assertNotIn("Officer Approval Sign</button>", content)
