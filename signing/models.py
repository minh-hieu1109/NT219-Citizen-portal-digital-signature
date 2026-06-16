from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import uuid
from documents.models import Document


def default_signing_request_nonce():
    return uuid.uuid4().hex


def default_signing_request_expiry():
    ttl_minutes = getattr(settings, "REMOTE_SIGNING_REQUEST_TTL_MINUTES", 10)
    return timezone.now() + timedelta(minutes=ttl_minutes)


class SigningRequest(models.Model):
    class SigningType(models.TextChoices):
        REMOTE = "remote", "Remote"
        CLIENT = "client", "Client"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SIGNED = "signed", "Signed"
        FAILED = "failed", "Failed"
        REJECTED = "rejected", "Rejected"

    document = models.ForeignKey(
        Document,
        on_delete=models.CASCADE,
        related_name="signing_requests"
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="signing_requests"
    )
    signer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="signing_tasks",
        null=True,
        blank=True
    )
    signing_type = models.CharField(
        max_length=20,
        choices=SigningType.choices,
        default=SigningType.REMOTE
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING
    )
    client_token = models.CharField(
        max_length=128,
        blank=True,
        null=True,
        unique=True,
        db_index=True,
    )

    client_token_expires_at = models.DateTimeField(
        blank=True,
        null=True,
    )
    class SigningPurpose(models.TextChoices):
        CITIZEN_LOCAL_SIGN = "citizen_local_sign", "Citizen local signing"
        CITIZEN_REMOTE_SIGN = "citizen_remote_sign", "Citizen remote signing via TSP"
        OFFICER_APPROVAL = "officer_approval", "Officer approval"

    purpose = models.CharField(
        max_length=50,
        choices=SigningPurpose.choices,
        default=SigningPurpose.CITIZEN_LOCAL_SIGN,
    )

    request_document_hash = models.CharField(max_length=64, blank=True)
    request_nonce = models.CharField(max_length=128, blank=True)
    requester_ip = models.GenericIPAddressField(null=True, blank=True)
    requester_user_agent = models.TextField(blank=True)
    auth_method = models.CharField(max_length=100, default="password_session")
    consent_text = models.TextField(blank=True)
    consent_hash = models.CharField(max_length=64, blank=True)


    nonce = models.CharField(max_length=64, default=default_signing_request_nonce, db_index=True)
    expires_at = models.DateTimeField(default=default_signing_request_expiry)
    used_at = models.DateTimeField(null=True, blank=True)
    strong_auth_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"SigningRequest #{self.id} - {self.document.title} - {self.status}"

class ClientPadesSession(models.Model):
    class Status(models.TextChoices):
        PREPARED = "prepared", "Prepared"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    signing_request = models.OneToOneField(
        SigningRequest,
        on_delete=models.CASCADE,
        related_name="client_pades_session",
    )

    prepared_pdf = models.FileField(
        upload_to="documents/pades/prepared/",
        null=True,
        blank=True,
    )

    prepared_pdf_sha256 = models.CharField(
        max_length=64,
        blank=True,
        default="",
    )

    document_digest = models.CharField(
        max_length=128,
        blank=True,
        default="",
    )

    signed_attrs_b64 = models.TextField(
        blank=True,
        default="",
    )

    prepared_digest_blob = models.BinaryField(
        null=True,
        blank=True,
    )

    field_name = models.CharField(
        max_length=120,
        blank=True,
        default="",
    )

    bytes_reserved = models.PositiveIntegerField(
        default=65536,
    )

    digest_algorithm = models.CharField(
        max_length=30,
        default="sha512",
    )

    status = models.CharField(
        max_length=30,
        choices=Status.choices,
        default=Status.PREPARED,
    )

    error_message = models.TextField(
        blank=True,
        default="",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

class SignatureRecord(models.Model):
    signing_request = models.OneToOneField(
        SigningRequest,
        on_delete=models.CASCADE,
        related_name="signature_record"
    )
    signature_value = models.TextField()
    certificate_pem = models.TextField(blank=True)
    certificate_subject = models.CharField(max_length=255, blank=True)
    certificate_serial = models.CharField(max_length=255, blank=True)
    algorithm = models.CharField(max_length=100, default="ML-DSA-65")
    signed_hash = models.CharField(
        max_length=128,
        blank=True,
        default="",
    )
    signed_at = models.DateTimeField(auto_now_add=True)

    timestamp_token = models.TextField(blank=True)
    timestamp_status = models.CharField(max_length=50, blank=True)
    timestamp_message = models.TextField(blank=True)

    def __str__(self):
        return f"SignatureRecord #{self.id} - Request #{self.signing_request.id}"
