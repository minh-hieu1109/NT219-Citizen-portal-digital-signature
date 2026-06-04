from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, UserCertificate
from django.contrib import messages
from .revocation_services import revoke_user_certificate

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    model = User

    list_display = (
        "id",
        "email",
        "full_name",
        "citizen_id",
        "role",
        "is_verified_identity",
        "is_staff",
        "is_active",
        "created_at",
    )

    list_filter = (
        "role",
        "is_verified_identity",
        "is_staff",
        "is_active",
    )

    ordering = ("-created_at",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {"fields": ("full_name", "citizen_id")}),
        ("Role & Identity", {"fields": ("role", "is_verified_identity")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Important Dates", {"fields": ("last_login", "created_at")}),
    )

    readonly_fields = ("created_at",)

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "email",
                "full_name",
                "citizen_id",
                "role",
                "is_verified_identity",
                "password1",
                "password2",
                "is_staff",
                "is_active",
            ),
        }),
    )

    search_fields = ("email", "full_name", "citizen_id")

@admin.action(description="Revoke selected certificates and regenerate CRL")
def revoke_certificates(modeladmin, request, queryset):
    count = 0

    for cert in queryset:
        try:
            revoke_user_certificate(cert)
            count += 1
        except Exception as e:
            messages.error(request, f"{cert.user.email}: {e}")

    messages.success(
        request,
        f"Revoked {count} certificate(s) and regenerated CRL."
    )

@admin.register(UserCertificate)
class UserCertificateAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "certificate_subject",
        "certificate_serial",
        "key_storage_type",
        "pkcs11_token_label",
        "pkcs11_key_label",
        "status",
        "created_at",
    )
    search_fields = (
        "user__email",
        "certificate_subject",
        "certificate_serial",
        "pkcs11_token_label",
        "pkcs11_key_label",
    )
    list_filter = ("status", "key_storage_type")
    actions = [revoke_certificates]

