from django.contrib import admin
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "action",
        "user",
        "object_type",
        "object_id",
        "ip_address",
        "created_at",
    )
    list_filter = (
        "action",
        "object_type",
        "created_at",
    )
    search_fields = (
        "user__email",
        "user__full_name",
        "object_type",
        "object_id",
    )
    readonly_fields = (
        "user",
        "action",
        "object_type",
        "object_id",
        "detail",
        "ip_address",
        "created_at",
    )
    ordering = ("-created_at",)