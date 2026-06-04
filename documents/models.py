from django.db import models
from django.conf import settings
import uuid

class Document(models.Model):
    class Status(models.TextChoices):
        UPLOADED = "uploaded", "Uploaded"
        PENDING_SIGN = "pending_sign", "Pending Sign"
        SIGNED = "signed", "Signed"
        REJECTED = "rejected", "Rejected"
        VERIFICATION_FAILED = "verification_failed", "Verification Failed"

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="documents"
    )
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to="documents/")
    sha256_hash = models.CharField(max_length=64, blank=True)
    status = models.CharField(
        max_length=30,
        choices=Status.choices,
        default=Status.UPLOADED
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    current_signed_pdf = models.FileField(
        upload_to="documents/pades/current/",
        null=True,
        blank=True,
    )

    final_signed_pdf = models.FileField(
        upload_to="documents/pades/final/",
        null=True,
        blank=True,
    )
    final_signed_pdf_sha256 = models.CharField(
        max_length=64,
        blank=True,
        default="",
    )
    verification_id = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
    )

    form_type = models.CharField(
        max_length=50,
        blank=True,
        default="uploaded_document",
    )
    def __str__(self):
        return f"{self.title} - {self.owner.email}"
    
