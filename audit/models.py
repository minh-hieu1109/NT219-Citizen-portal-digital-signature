from django.db import models
from django.conf import settings


class AuditLog(models.Model):
    class Action(models.TextChoices):
        DOCUMENT_UPLOAD = "document_upload", "Document Upload"
        SIGNING_REQUEST_CREATED = "signing_request_created", "Signing Request Created"
        REMOTE_SIGNED = "remote_signed", "Remote Signed"
        VERIFICATION_RUN = "verification_run", "Verification Run"
        IDENTITY_VERIFIED = "identity_verified", "Identity Verified"
        IDENTITY_REJECTED = "identity_rejected", "Identity Rejected"
        CERTIFICATE_ISSUED = "certificate_issued", "Certificate Issued"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    action = models.CharField(max_length=100, choices=Action.choices)
    object_type = models.CharField(max_length=100)
    object_id = models.PositiveIntegerField()
    detail = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.action}] {self.object_type}#{self.object_id} by {self.user}"
