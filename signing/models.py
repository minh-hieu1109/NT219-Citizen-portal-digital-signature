from django.db import models
from django.conf import settings
from documents.models import Document


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
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"SigningRequest #{self.id} - {self.document.title} - {self.status}"


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