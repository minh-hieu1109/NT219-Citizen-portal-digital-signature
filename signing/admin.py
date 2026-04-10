from django.contrib import admin
from .models import SigningRequest, SignatureRecord


@admin.register(SigningRequest)
class SigningRequestAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "document",
        "requested_by",
        "signing_type",
        "status",
        "created_at",
        "completed_at",
    )
    list_filter = (
        "signing_type",
        "status",
        "created_at",
    )
    search_fields = (
        "document__title",
        "requested_by__email",
        "requested_by__full_name",
    )
    readonly_fields = (
        "created_at",
        "completed_at",
    )
    ordering = ("-created_at",)


@admin.register(SignatureRecord)
class SignatureRecordAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "signing_request",
        "algorithm",
        "certificate_subject",
        "certificate_serial",
        "signed_hash",
        "signed_at",
    )
    list_filter = (
        "algorithm",
        "signed_at",
    )
    search_fields = (
        "signing_request__document__title",
        "signing_request__requested_by__email",
        "certificate_subject",
        "certificate_serial",
        "signed_hash",
    )
    readonly_fields = (
        "signed_at",
    )
    ordering = ("-signed_at",)