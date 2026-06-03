import base64
import json
import tempfile
import zipfile
from datetime import timedelta
from io import BytesIO
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import User, UserCertificate
from documents.models import Document
from frontend.forms import SigningRequestForm
from signing.models import SigningRequest, SignatureRecord
from signing.services import complete_client_signing_request, prepare_client_signing_request
from verification.models import VerificationResult
from verification.services import verify_signature_record


class CitizenSigningSemanticsTests(TestCase):
    def setUp(self):
        self.citizen = User.objects.create_user(
            email="citizen_semantics@example.com",
            password="Citizen@123456",
            full_name="Citizen Semantics",
            citizen_id="CIT-SEM-001",
            role=User.Role.CITIZEN,
            is_verified_identity=True,
        )
        self.officer = User.objects.create_user(
            email="officer_semantics@example.com",
            password="Officer@123456",
            full_name="Officer Semantics",
            citizen_id="OFF-SEM-001",
            role=User.Role.OFFICER,
            is_verified_identity=True,
        )
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert_pem, cert_serial, cert_subject = self._build_certificate(self.private_key, self.citizen.email)
        self.key_file = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pem")
        self.key_file.write(
            self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.key_file.flush()
        self.citizen_cert = UserCertificate.objects.create(
            user=self.citizen,
            certificate_pem=cert_pem,
            certificate_subject=cert_subject,
            certificate_serial=cert_serial,
            key_storage_type=UserCertificate.KeyStorageType.FILE,
            private_key_path=self.key_file.name,
            status=UserCertificate.Status.ACTIVE,
            valid_from=timezone.now() - timedelta(days=1),
            valid_to=timezone.now() + timedelta(days=365),
        )

    def _build_certificate(self, key, email):
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Citizen Portal"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Citizen Semantics"),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(timezone.now() - timedelta(days=1))
            .not_valid_after(timezone.now() + timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            str(cert.serial_number),
            cert.subject.rfc4514_string(),
        )

    def _create_document(self, content=b"citizen document payload"):
        document = Document.objects.create(
            owner=self.citizen,
            title="Citizen Document",
            sha256_hash="",
            status=Document.Status.UPLOADED,
        )
        document.file.save("citizen_document.txt", ContentFile(content), save=True)
        return document

    def _create_client_request(self, document=None):
        return SigningRequest.objects.create(
            document=document or self._create_document(),
            requested_by=self.citizen,
            signer=self.citizen,
            signing_type=SigningRequest.SigningType.CLIENT,
            status=SigningRequest.Status.PENDING,
        )

    def _complete_request(self, signing_request):
        prepare = prepare_client_signing_request(signing_request)
        signature_bytes = self.private_key.sign(
            bytes.fromhex(prepare["digest_hex"]),
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256()),
        )
        with patch(
            "signing.services.create_timestamp_token_for_file",
            return_value={"ok": False, "timestamp_token_b64": "", "message": "test timestamp skipped"},
        ):
            return complete_client_signing_request(
                signing_request,
                base64.b64encode(signature_bytes).decode("utf-8"),
                prepare["algorithm"],
            )

    def test_citizen_client_sign_uses_citizen_certificate(self):
        signature_record = self._complete_request(self._create_client_request())

        self.assertEqual(signature_record.signer, self.citizen)
        self.assertEqual(signature_record.signature_purpose, "citizen_signature")
        self.assertEqual(signature_record.certificate_serial, self.citizen_cert.certificate_serial)
        self.assertIn(self.citizen.email, signature_record.certificate_subject)

    def test_signature_record_signer_is_citizen_for_client_signing(self):
        signature_record = self._complete_request(self._create_client_request())

        self.assertEqual(signature_record.signing_request.signer, self.citizen)
        self.assertEqual(signature_record.signing_request.requested_by, self.citizen)

    def test_officer_cannot_sign_as_citizen(self):
        signing_request = self._create_client_request()
        api_client = APIClient()
        api_client.force_authenticate(user=self.officer)

        response = api_client.post(f"/api/signing/requests/{signing_request.id}/prepare-client-sign/")

        self.assertEqual(response.status_code, 400)
        self.assertIn("assigned signer", str(response.data).lower())

    def test_unverified_citizen_cannot_sign(self):
        self.citizen.is_verified_identity = False
        self.citizen.save(update_fields=["is_verified_identity"])
        form = SigningRequestForm(
            data={"document": self._create_document().id, "signing_type": SigningRequest.SigningType.CLIENT},
            user=self.citizen,
        )

        self.assertFalse(form.is_valid())
        self.assertIn("verified", str(form.errors).lower())

    def test_citizen_without_certificate_cannot_sign(self):
        UserCertificate.objects.filter(user=self.citizen).delete()
        self.citizen.refresh_from_db()
        form = SigningRequestForm(
            data={"document": self._create_document().id, "signing_type": SigningRequest.SigningType.CLIENT},
            user=self.citizen,
        )

        self.assertFalse(form.is_valid())
        self.assertIn("certificate", str(form.errors).lower())

    def test_public_verification_package_contains_citizen_certificate(self):
        signature_record = self._complete_request(self._create_client_request())
        client = Client(SERVER_NAME="localhost")
        client.force_login(self.citizen)

        response = client.get(f"/signatures/{signature_record.id}/download-package/", SERVER_NAME="localhost")

        self.assertEqual(response.status_code, 200)
        with zipfile.ZipFile(BytesIO(response.content)) as package:
            metadata = json.loads(package.read("metadata.json").decode("utf-8"))
            signer_cert = package.read("certs/signer_certificate.pem").decode("utf-8")
        self.assertEqual(metadata["signature_purpose"], "citizen_signature")
        self.assertEqual(metadata["signer_email"], self.citizen.email)
        self.assertEqual(metadata["signer_role"], User.Role.CITIZEN)
        self.assertEqual(metadata["document_owner_email"], self.citizen.email)
        self.assertEqual(metadata["signer_certificate_serial"], self.citizen_cert.certificate_serial)
        self.assertEqual(signer_cert, self.citizen_cert.certificate_pem)

    def test_tampered_document_after_citizen_sign_fails(self):
        document = self._create_document()
        signature_record = self._complete_request(self._create_client_request(document))
        with open(document.file.path, "wb") as f:
            f.write(b"tampered payload")

        result = verify_signature_record(signature_record)

        self.assertEqual(result.status, VerificationResult.Status.INVALID)
        self.assertFalse(result.is_hash_match)

    def test_replay_client_signing_request_rejected(self):
        signing_request = self._create_client_request()
        self._complete_request(signing_request)
        signing_request.refresh_from_db()

        with self.assertRaisesMessage(ValueError, "already been used"):
            prepare_client_signing_request(signing_request)
