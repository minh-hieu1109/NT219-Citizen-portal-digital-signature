from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.conf import settings


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        extra_fields.setdefault("username", email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("role", User.Role.ADMIN)
        extra_fields.setdefault("username", email)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    class Role(models.TextChoices):
        CITIZEN = "citizen", "Citizen"
        OFFICER = "officer", "Officer"
        ADMIN = "admin", "Admin"

    username = models.CharField(max_length=150, unique=True, blank=True)
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255)
    citizen_id = models.CharField(max_length=50, unique=True)
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.CITIZEN
    )
    is_verified_identity = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["full_name", "citizen_id"]

    objects = UserManager()

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.email} ({self.role})"


class UserCertificate(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        REVOKED = "revoked", "Revoked"
        EXPIRED = "expired", "Expired"

    class KeyStorageType(models.TextChoices):
        FILE = "file", "File PEM"
        SOFTHSM = "softhsm", "SoftHSM PKCS#11"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="certificate_profile"
    )
    certificate_pem = models.TextField()
    certificate_subject = models.CharField(max_length=255)
    certificate_serial = models.CharField(max_length=255, unique=True)

    key_storage_type = models.CharField(
        max_length=20,
        choices=KeyStorageType.choices,
        default=KeyStorageType.SOFTHSM
    )

    private_key_path = models.CharField(max_length=500, blank=True, null=True)

    pkcs11_token_label = models.CharField(max_length=100, blank=True, null=True)
    pkcs11_key_label = models.CharField(max_length=100, blank=True, null=True)
    pkcs11_key_id = models.CharField(max_length=100, blank=True, null=True)
    pkcs11_slot = models.CharField(max_length=50, blank=True, null=True)

    issued_by = models.CharField(max_length=255, blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE
    )
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_to = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)