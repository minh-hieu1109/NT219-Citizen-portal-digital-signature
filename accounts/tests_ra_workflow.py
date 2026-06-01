from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework.test import APIClient

from audit.models import AuditLog
from documents.models import Document
from signing.models import SigningRequest


User = get_user_model()


class RAWorkflowTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.officer = User.objects.create_user(
            email="officer@example.com",
            password="pass123",
            full_name="Officer User",
            citizen_id="OFF001",
            role=User.Role.OFFICER,
            is_verified_identity=True,
        )
        self.citizen = User.objects.create_user(
            email="citizen@example.com",
            password="pass123",
            full_name="Citizen User",
            citizen_id="CIT001",
            role=User.Role.CITIZEN,
            is_verified_identity=False,
        )

    def test_pending_identity_list_requires_officer_or_admin(self):
        self.client.force_authenticate(user=self.citizen)
        response = self.client.get("/api/accounts/pending-identity/")
        self.assertEqual(response.status_code, 403)

        self.client.force_authenticate(user=self.officer)
        response = self.client.get("/api/accounts/pending-identity/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["id"], self.citizen.id)

    def test_verify_identity_creates_audit_log(self):
        self.client.force_authenticate(user=self.officer)
        response = self.client.post(f"/api/accounts/{self.citizen.id}/verify-identity/")

        self.assertEqual(response.status_code, 200)
        self.citizen.refresh_from_db()
        self.assertTrue(self.citizen.is_verified_identity)

        self.assertTrue(
            AuditLog.objects.filter(
                user=self.officer,
                action=AuditLog.Action.IDENTITY_VERIFIED,
                object_type="User",
                object_id=self.citizen.id,
            ).exists()
        )

    def test_reject_identity_creates_audit_log(self):
        self.citizen.is_verified_identity = True
        self.citizen.save(update_fields=["is_verified_identity"])

        self.client.force_authenticate(user=self.officer)
        response = self.client.post(f"/api/accounts/{self.citizen.id}/reject-identity/")

        self.assertEqual(response.status_code, 200)
        self.citizen.refresh_from_db()
        self.assertFalse(self.citizen.is_verified_identity)
        self.assertTrue(
            AuditLog.objects.filter(
                user=self.officer,
                action=AuditLog.Action.IDENTITY_REJECTED,
                object_type="User",
                object_id=self.citizen.id,
            ).exists()
        )

    def test_issue_certificate_rejects_unverified_citizen(self):
        self.client.force_authenticate(user=self.officer)
        response = self.client.post(f"/api/accounts/{self.citizen.id}/issue-certificate/")
        self.assertEqual(response.status_code, 400)
        self.assertIn("must be verified", response.data["detail"])

    @patch("accounts.views.issue_certificate_for_user")
    def test_issue_certificate_for_verified_citizen_creates_audit_log(self, mock_issue):
        self.citizen.is_verified_identity = True
        self.citizen.save(update_fields=["is_verified_identity"])

        mock_issue.return_value = SimpleNamespace(id=777, certificate_serial="SERIAL777")

        self.client.force_authenticate(user=self.officer)
        response = self.client.post(f"/api/accounts/{self.citizen.id}/issue-certificate/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["certificate_serial"], "SERIAL777")
        self.assertTrue(
            AuditLog.objects.filter(
                user=self.officer,
                action=AuditLog.Action.CERTIFICATE_ISSUED,
                object_type="UserCertificate",
                object_id=777,
            ).exists()
        )

    def test_unverified_citizen_remote_sign_is_rejected(self):
        document = Document.objects.create(
            owner=self.citizen,
            title="Doc 1",
            file=SimpleUploadedFile("doc.txt", b"hello world", content_type="text/plain"),
            sha256_hash="abc",
            status=Document.Status.UPLOADED,
        )

        signing_request = SigningRequest.objects.create(
            document=document,
            requested_by=self.citizen,
            signer=self.citizen,
            signing_type=SigningRequest.SigningType.REMOTE,
            status=SigningRequest.Status.PENDING,
        )

        self.client.force_authenticate(user=self.citizen)
        response = self.client.post(f"/api/signing/requests/{signing_request.id}/remote-sign/")

        self.assertEqual(response.status_code, 400)
        self.assertIn("not verified", str(response.data).lower())
