from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.utils import timezone

from accounts.models import UserCertificate
from documents.models import Document
from signing.models import SignatureRecord, SigningRequest
from signing.services import remote_sign_signing_request
from verification.ltv_services import verify_ltv
from verification.models import ValidationEvidence


User = get_user_model()


class LTVArchiveTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="ltv@example.com",
            password="pass123",
            full_name="LTV User",
            citizen_id="LTV001",
            role=User.Role.CITIZEN,
            is_verified_identity=True,
        )
        UserCertificate.objects.update_or_create(
            user=self.user,
            defaults={
                "certificate_pem": "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
                "certificate_subject": "CN=LTV User",
                "certificate_serial": "LTV-SERIAL-001",
                "key_storage_type": UserCertificate.KeyStorageType.FILE,
                "private_key_path": "/app/keys/client_private_key.pem",
                "status": UserCertificate.Status.ACTIVE,
                "valid_from": timezone.now() - timedelta(days=1),
                "valid_to": timezone.now() + timedelta(days=365),
            },
        )

    def _create_remote_request(self):
        doc = Document.objects.create(
            owner=self.user,
            title="LTV Doc",
            file=SimpleUploadedFile("ltv.txt", b"hello ltv", content_type="text/plain"),
            sha256_hash="dummy",
            status=Document.Status.UPLOADED,
        )
        return SigningRequest.objects.create(
            document=doc,
            requested_by=self.user,
            signer=self.user,
            signing_type=SigningRequest.SigningType.REMOTE,
            status=SigningRequest.Status.PENDING,
        )

    @patch("signing.services.create_timestamp_token_for_file")
    def test_remote_sign_creates_validation_evidence(self, mock_timestamp):
        mock_timestamp.return_value = {
            "ok": True,
            "timestamp_token_b64": "dGVzdA==",
            "message": "ok",
        }
        req = self._create_remote_request()
        sig = remote_sign_signing_request(req)

        evidence = ValidationEvidence.objects.get(signature_record=sig)
        self.assertTrue(evidence.signer_certificate_pem)
        self.assertTrue(evidence.evidence_hash)
        self.assertEqual(evidence.timestamp_token_base64, "dGVzdA==")

    @patch("signing.services.create_timestamp_token_for_file")
    def test_evidence_hash_verifies(self, mock_timestamp):
        mock_timestamp.return_value = {
            "ok": True,
            "timestamp_token_b64": "dGVzdA==",
            "message": "ok",
        }
        req = self._create_remote_request()
        sig = remote_sign_signing_request(req)

        result = verify_ltv(sig)
        self.assertTrue(result["evidence_exists"])
        self.assertTrue(result["evidence_hash_valid"])
        self.assertTrue(result["has_certificate"])

    def test_verify_ltv_missing_evidence_returns_safe_result(self):
        doc = Document.objects.create(
            owner=self.user,
            title="No Evidence Doc",
            file=SimpleUploadedFile("no_evidence.txt", b"abc", content_type="text/plain"),
            sha256_hash="dummy",
            status=Document.Status.SIGNED,
        )
        req = SigningRequest.objects.create(
            document=doc,
            requested_by=self.user,
            signer=self.user,
            signing_type=SigningRequest.SigningType.CLIENT,
            status=SigningRequest.Status.SIGNED,
        )
        sig = SignatureRecord.objects.create(
            signing_request=req,
            signature_value="dGVzdA==",
            certificate_pem="pem",
            certificate_subject="subj",
            certificate_serial="SER-NE-1",
            algorithm="RSA-SHA256",
            signed_hash="a" * 64,
        )

        result = verify_ltv(sig)
        self.assertFalse(result["valid"])
        self.assertFalse(result["evidence_exists"])
        self.assertIn("missing", result["detail"]["message"].lower())
