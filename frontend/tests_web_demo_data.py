from django.core.management import call_command
from django.test import TestCase

from accounts.models import UserCertificate
from documents.models import Document
from signing.models import SigningRequest


class WebDemoDataCommandTests(TestCase):
    def test_create_web_demo_data_creates_officer_active_certificate(self):
        call_command("create_web_demo_data")

        cert = UserCertificate.objects.filter(
            user__email="officer@example.com",
            status=UserCertificate.Status.ACTIVE,
        ).first()
        self.assertIsNotNone(cert)
        self.assertTrue(cert.private_key_path)

    def test_signer_dropdown_includes_officer_for_citizen(self):
        call_command("create_web_demo_data")

        self.client.login(username="citizen@example.com", password="Citizen@123456")
        response = self.client.get("/signing/requests/create/")
        self.assertEqual(response.status_code, 200)
        signer_qs = response.context["form"].fields["signer"].queryset
        self.assertTrue(signer_qs.filter(email="officer@example.com").exists())

    def test_officer_can_remote_sign_demo_request(self):
        call_command("create_web_demo_data")

        req = SigningRequest.objects.filter(
            requested_by__email="citizen@example.com",
            signer__email="officer@example.com",
            signing_type=SigningRequest.SigningType.REMOTE,
            status=SigningRequest.Status.PENDING,
        ).first()
        self.assertIsNotNone(req)

        self.client.login(username="officer@example.com", password="Officer@123456")
        response = self.client.post(f"/signing/requests/{req.id}/remote-sign/")
        self.assertEqual(response.status_code, 302)
        req.refresh_from_db()
        self.assertEqual(req.status, SigningRequest.Status.SIGNED)

    def test_ra_panel_shows_verified_users_without_cert_section(self):
        call_command("create_web_demo_data")

        self.client.login(username="admin@example.com", password="Admin@123456")
        response = self.client.get("/ra/pending/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Verified users without certificate")
        self.assertContains(response, "citizen@example.com")

    def test_demo_document_exists(self):
        call_command("create_web_demo_data")
        self.assertTrue(Document.objects.filter(owner__email="citizen@example.com").exists())
