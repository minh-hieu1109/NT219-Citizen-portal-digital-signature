from django.db import models
from signing.models import SignatureRecord


class VerificationResult(models.Model):
    class Status(models.TextChoices):
        VALID = "valid", "Valid"
        INVALID = "invalid", "Invalid"

    signature_record = models.OneToOneField(
        SignatureRecord,
        on_delete=models.CASCADE,
        related_name="verification_result"
    )
    status = models.CharField(max_length=20, choices=Status.choices)
    is_signature_valid = models.BooleanField(default=False)
    is_hash_match = models.BooleanField(default=False)
    signer_subject = models.CharField(max_length=255, blank=True)
    signer_serial = models.CharField(max_length=255, blank=True)
    detail = models.JSONField(default=dict, blank=True)
    verified_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Verification #{self.id} - Signature #{self.signature_record.id} - {self.status}"