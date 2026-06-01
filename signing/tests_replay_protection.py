from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import UserCertificate
from documents.models import Document
from signing.models import SignatureRecord, SigningRequest


User = get_user_model()


class RemoteSigningReplayProtectionTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.signer = User.objects.create_user(
            email="signer@example.com",
            password="pass123",
            full_name="Signer User",
            citizen_id="SGN001",
            role=User.Role.CITIZEN,
            is_verified_identity=True,
        )
        self.client.force_authenticate(user=self.signer)

        UserCertificate.objects.update_or_create(
            user=self.signer,
            defaults={
                "certificate_pem": "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
                "certificate_subject": "CN=Signer",
                "certificate_serial": "SERIAL-SIGNER-001",
                "key_storage_type": UserCertificate.KeyStorageType.FILE,
                "private_key_path": "/app/keys/client_private_key.pem",
                "status": UserCertificate.Status.ACTIVE,
                "valid_from": timezone.now() - timedelta(days=1),
                "valid_to": timezone.now() + timedelta(days=365),
            },
        )

    def _create_remote_signing_request(self) -> SigningRequest:
        doc = Document.objects.create(
            owner=self.signer,
            title="Replay Test Document",
            file=SimpleUploadedFile("doc.txt", b"hello replay", content_type="text/plain"),
            sha256_hash="dummy",
            status=Document.Status.UPLOADED,
        )
        return SigningRequest.objects.create(
            document=doc,
            requested_by=self.signer,
            signer=self.signer,
            signing_type=SigningRequest.SigningType.REMOTE,
            status=SigningRequest.Status.PENDING,
        )

    @patch("signing.services.create_timestamp_token_for_file")
    def test_first_remote_sign_succeeds_and_sets_used_at(self, mock_timestamp):
        mock_timestamp.return_value = {
            "ok": True,
            "timestamp_token_b64": "dGVzdA==",
            "message": "ok",
        }
        req = self._create_remote_signing_request()

        response = self.client.post(f"/api/signing/requests/{req.id}/remote-sign/")

        self.assertEqual(response.status_code, 200)
        req.refresh_from_db()
        self.assertEqual(req.status, SigningRequest.Status.SIGNED)
        self.assertIsNotNone(req.used_at)

    @patch("signing.services.create_timestamp_token_for_file")
    def test_replay_same_request_is_rejected(self, mock_timestamp):
        mock_timestamp.return_value = {
            "ok": True,
            "timestamp_token_b64": "dGVzdA==",
            "message": "ok",
        }
        req = self._create_remote_signing_request()

        first = self.client.post(f"/api/signing/requests/{req.id}/remote-sign/")
        self.assertEqual(first.status_code, 200)

        second = self.client.post(f"/api/signing/requests/{req.id}/remote-sign/")
        self.assertEqual(second.status_code, 400)
        self.assertIn("replay", str(second.data).lower())

    def test_expired_request_is_rejected(self):
        req = self._create_remote_signing_request()
        req.expires_at = timezone.now() - timedelta(minutes=1)
        req.save(update_fields=["expires_at"])

        response = self.client.post(f"/api/signing/requests/{req.id}/remote-sign/")

        self.assertEqual(response.status_code, 400)
        self.assertIn("expired", str(response.data).lower())

    def test_used_request_is_rejected(self):
        req = self._create_remote_signing_request()
        req.used_at = timezone.now() - timedelta(minutes=1)
        req.save(update_fields=["used_at"])

        response = self.client.post(f"/api/signing/requests/{req.id}/remote-sign/")

        self.assertEqual(response.status_code, 400)
        self.assertIn("used", str(response.data).lower())

    def test_already_signed_signature_record_is_rejected(self):
        req = self._create_remote_signing_request()
        SignatureRecord.objects.create(
            signing_request=req,
            signature_value="dGVzdA==",
            certificate_pem="pem",
            certificate_subject="subj",
            certificate_serial="SERIAL-REC-001",
            algorithm="RSA-SHA256",
            signed_hash="a" * 64,
        )

        response = self.client.post(f"/api/signing/requests/{req.id}/remote-sign/")

        self.assertEqual(response.status_code, 400)
        self.assertIn("already been signed", str(response.data).lower())
