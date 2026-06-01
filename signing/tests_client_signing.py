import base64
import tempfile
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import User, UserCertificate
from documents.models import Document
from signing.models import SigningRequest


class ClientSigningFlowTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="client_signer@example.com",
            password="pass123",
            full_name="Client Signer",
            citizen_id="CLN001",
            role=User.Role.CITIZEN,
            is_verified_identity=True,
        )
        self.client.force_authenticate(user=self.user)

        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert_pem, cert_serial = self._build_self_signed_cert(self.private_key)

        temp_key = tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".pem")
        temp_key.write(
            self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        temp_key.flush()

        UserCertificate.objects.update_or_create(
            user=self.user,
            defaults={
                "certificate_pem": cert_pem,
                "certificate_subject": "CN=Client Signer",
                "certificate_serial": cert_serial,
                "key_storage_type": UserCertificate.KeyStorageType.FILE,
                "private_key_path": temp_key.name,
                "status": UserCertificate.Status.ACTIVE,
                "valid_from": timezone.now() - timedelta(days=1),
                "valid_to": timezone.now() + timedelta(days=365),
            },
        )

    def _build_self_signed_cert(self, key):
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Citizen Portal"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Client Signer"),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.user.email),
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
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return cert_pem, str(cert.serial_number)

    def _create_client_signing_request(self):
        doc = Document.objects.create(
            owner=self.user,
            title="Client Sign Doc",
            file=SimpleUploadedFile("doc.txt", b"client sign payload", content_type="text/plain"),
            sha256_hash="dummy",
            status=Document.Status.UPLOADED,
        )
        return SigningRequest.objects.create(
            document=doc,
            requested_by=self.user,
            signer=self.user,
            signing_type=SigningRequest.SigningType.CLIENT,
            status=SigningRequest.Status.PENDING,
        )

    def test_prepare_client_signing_returns_digest(self):
        req = self._create_client_signing_request()

        resp = self.client.post(f"/api/signing/requests/{req.id}/prepare-client-sign/")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("digest_hex", resp.data)
        self.assertEqual(resp.data["algorithm"], "RSA-SHA256-PREHASHED")
        self.assertEqual(resp.data["signing_request_id"], req.id)

    def test_complete_client_signing_rejects_invalid_signature(self):
        req = self._create_client_signing_request()

        prepare = self.client.post(f"/api/signing/requests/{req.id}/prepare-client-sign/")
        self.assertEqual(prepare.status_code, 200)

        invalid_signature = base64.b64encode(b"invalid-signature").decode("utf-8")
        resp = self.client.post(
            f"/api/signing/requests/{req.id}/complete-client-sign/",
            data={"signature_value": invalid_signature, "algorithm": "RSA-SHA256-PREHASHED"},
            format="json",
        )

        self.assertEqual(resp.status_code, 400)
        self.assertIn("client signing failed", str(resp.data).lower())

    def test_complete_client_signing_accepts_valid_signature(self):
        req = self._create_client_signing_request()

        prepare = self.client.post(f"/api/signing/requests/{req.id}/prepare-client-sign/")
        self.assertEqual(prepare.status_code, 200)

        digest_hex = prepare.data["digest_hex"]
        digest_bytes = bytes.fromhex(digest_hex)
        signature_bytes = self.private_key.sign(
            digest_bytes,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256()),
        )
        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

        resp = self.client.post(
            f"/api/signing/requests/{req.id}/complete-client-sign/",
            data={"signature_value": signature_b64, "algorithm": "RSA-SHA256-PREHASHED"},
            format="json",
        )

        self.assertEqual(resp.status_code, 200)
        req.refresh_from_db()
        self.assertEqual(req.status, SigningRequest.Status.SIGNED)
