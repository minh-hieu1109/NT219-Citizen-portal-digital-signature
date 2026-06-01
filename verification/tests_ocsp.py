import base64
from datetime import datetime, timedelta, timezone as dt_timezone
from hashlib import sha256
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from documents.models import Document
from signing.models import SigningRequest, SignatureRecord
from verification.models import VerificationResult
from verification.services import verify_signature_record


User = get_user_model()


class FakeName:
    def __init__(self, value: str):
        self._value = value

    def rfc4514_string(self):
        return self._value

    def __eq__(self, other):
        return isinstance(other, FakeName) and self._value == other._value


class FakeCert:
    def __init__(self, serial: int, issuer: str, subject: str):
        self.serial_number = serial
        self.issuer = FakeName(issuer)
        self.subject = FakeName(subject)
        self.not_valid_before_utc = datetime.now(dt_timezone.utc) - timedelta(days=1)
        self.not_valid_after_utc = datetime.now(dt_timezone.utc) + timedelta(days=365)
        self._public_key = Mock()
        self._public_key.verify = Mock(return_value=None)

    def public_key(self):
        return self._public_key


class OCSPVerificationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="ocsp-user@example.com",
            password="pass123",
            full_name="OCSP User",
            citizen_id="OCSP001",
            role=User.Role.CITIZEN,
            is_verified_identity=True,
        )
        self.document = Document.objects.create(
            owner=self.user,
            title="OCSP Test Doc",
            file=SimpleUploadedFile("ocsp.txt", b"hello ocsp", content_type="text/plain"),
            sha256_hash="dummy",
            status=Document.Status.UPLOADED,
        )
        self.signing_request = SigningRequest.objects.create(
            document=self.document,
            requested_by=self.user,
            signer=self.user,
            signing_type=SigningRequest.SigningType.REMOTE,
            status=SigningRequest.Status.SIGNED,
        )
        with open(self.document.file.path, "rb") as f:
            file_bytes = f.read()
        self.signature_record = SignatureRecord.objects.create(
            signing_request=self.signing_request,
            signature_value=base64.b64encode(b"dummy-signature").decode("utf-8"),
            certificate_pem="-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
            certificate_subject="CN=Signer",
            certificate_serial="123456",
            algorithm="RSA-SHA256",
            signed_hash=sha256(file_bytes).hexdigest(),
            timestamp_token="",
        )

    def _cert_side_effect(self):
        signer_cert = FakeCert(serial=123456, issuer="CN=Root", subject="CN=Signer")
        root_cert = FakeCert(serial=999999, issuer="CN=Root", subject="CN=Root")
        return [signer_cert, root_cert]

    @override_settings(ENABLE_OCSP_CHECK=False)
    @patch("verification.services.is_cert_revoked_in_crl", return_value=False)
    @patch("verification.services.x509.load_pem_x509_certificate")
    @patch("verification.services.check_certificate_ocsp_status")
    def test_ocsp_disabled_does_not_affect_verification(
        self,
        mock_ocsp_check,
        mock_load_cert,
        _mock_crl_check,
    ):
        mock_load_cert.side_effect = self._cert_side_effect()

        result = verify_signature_record(self.signature_record)

        self.assertEqual(result.status, VerificationResult.Status.VALID)
        self.assertEqual(result.detail.get("ocsp_status"), "disabled")
        mock_ocsp_check.assert_not_called()

    @override_settings(ENABLE_OCSP_CHECK=True)
    @patch("verification.services.is_cert_revoked_in_crl", return_value=False)
    @patch("verification.services.x509.load_pem_x509_certificate")
    @patch(
        "verification.services.check_certificate_ocsp_status",
        return_value={"status": "unavailable", "message": "connection refused", "serial": "123456"},
    )
    def test_ocsp_unavailable_no_crash(
        self,
        _mock_ocsp_check,
        mock_load_cert,
        _mock_crl_check,
    ):
        mock_load_cert.side_effect = self._cert_side_effect()

        result = verify_signature_record(self.signature_record)

        self.assertEqual(result.status, VerificationResult.Status.VALID)
        self.assertEqual(result.detail.get("ocsp_status"), "unavailable")
        self.assertIn("connection refused", result.detail.get("ocsp_message", ""))

    @override_settings(ENABLE_OCSP_CHECK=True)
    @patch("verification.services.is_cert_revoked_in_crl", return_value=False)
    @patch("verification.services.x509.load_pem_x509_certificate")
    @patch(
        "verification.services.check_certificate_ocsp_status",
        return_value={"status": "good", "message": "good", "serial": "123456"},
    )
    def test_ocsp_good_keeps_valid(
        self,
        _mock_ocsp_check,
        mock_load_cert,
        _mock_crl_check,
    ):
        mock_load_cert.side_effect = self._cert_side_effect()

        result = verify_signature_record(self.signature_record)

        self.assertEqual(result.status, VerificationResult.Status.VALID)
        self.assertEqual(result.detail.get("ocsp_status"), "good")

    @override_settings(ENABLE_OCSP_CHECK=True)
    @patch("verification.services.is_cert_revoked_in_crl", return_value=False)
    @patch("verification.services.x509.load_pem_x509_certificate")
    @patch(
        "verification.services.check_certificate_ocsp_status",
        return_value={"status": "revoked", "message": "revoked", "serial": "123456"},
    )
    def test_ocsp_revoked_invalidates_signature(
        self,
        _mock_ocsp_check,
        mock_load_cert,
        _mock_crl_check,
    ):
        mock_load_cert.side_effect = self._cert_side_effect()

        result = verify_signature_record(self.signature_record)

        self.assertEqual(result.status, VerificationResult.Status.INVALID)
        self.assertEqual(result.detail.get("ocsp_status"), "revoked")
