from django.contrib import admin
from .models import VerificationResult


@admin.register(VerificationResult)
class VerificationResultAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "signature_record",
        "status",
        "is_signature_valid",
        "is_hash_match",
        "signer_subject",
        "verified_at",
    )
    list_filter = (
        "status",
        "is_signature_valid",
        "is_hash_match",
        "verified_at",
    )
    search_fields = (
        "signer_subject",
        "signer_serial",
        "signature_record__signing_request__document__title",
        "signature_record__signing_request__requested_by__email",
    )
    readonly_fields = (
        "verified_at",
    )
    ordering = ("-verified_at",)