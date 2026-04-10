from django.contrib import admin
from .models import Document


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "title",
        "owner",
        "status",
        "sha256_hash",
        "uploaded_at",
        "updated_at",
    )
    list_filter = ("status", "uploaded_at")
    search_fields = ("title", "owner__email", "sha256_hash")