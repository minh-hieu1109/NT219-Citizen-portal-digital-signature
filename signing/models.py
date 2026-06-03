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
    nonce = models.CharField(max_length=64, default=default_signing_request_nonce, db_index=True)
    expires_at = models.DateTimeField(default=default_signing_request_expiry)
    used_at = models.DateTimeField(null=True, blank=True)
    strong_auth_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"SigningRequest #{self.id} - {self.document.title} - {self.status}"

    @property
    def signature_purpose(self):
        if self.signing_type == self.SigningType.CLIENT:
            return "citizen_signature"
        return "officer_approval_signature"


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
    algorithm = models.CharField(max_length=100, default="RSA-SHA256")
    signed_hash = models.CharField(max_length=64)
    signed_at = models.DateTimeField(auto_now_add=True)

    timestamp_token = models.TextField(blank=True)
    timestamp_status = models.CharField(max_length=50, blank=True)
    timestamp_message = models.TextField(blank=True)

    def __str__(self):
        return f"SignatureRecord #{self.id} - Request #{self.signing_request.id}"

    @property
    def signer(self):
        return self.signing_request.signer

    @property
    def signature_purpose(self):
        return self.signing_request.signature_purpose
