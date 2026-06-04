from django import forms
from django.contrib.auth import get_user_model
from django.db.models import Q

from accounts.models import User, UserCertificate
from documents.models import Document
from signing.models import SigningRequest, SignatureRecord

UserModel = get_user_model()


def user_has_active_cert(user):
    return UserCertificate.objects.filter(
        user=user,
        status=UserCertificate.Status.ACTIVE,
    ).exists()


def document_has_citizen_signature(document):
    return SignatureRecord.objects.filter(
        signing_request__document=document,
        signing_request__signer=document.owner,
        signing_request__status=SigningRequest.Status.SIGNED,
    ).exists()


def document_has_officer_signature(document):
    return SignatureRecord.objects.filter(
        signing_request__document=document,
        signing_request__signer__role__in=[User.Role.OFFICER, User.Role.ADMIN],
        signing_request__status=SigningRequest.Status.SIGNED,
    ).exists()


class DocumentUploadForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ["title", "file"]
        widgets = {
            "title": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Document title",
                }
            ),
            "file": forms.FileInput(attrs={"class": "form-control-file"}),
        }


class SigningRequestForm(forms.ModelForm):
    signer = forms.ModelChoiceField(
        queryset=User.objects.none(),
        required=True,
    )

    class Meta:
        model = SigningRequest
        fields = ["document", "signing_type", "signer"]
        widgets = {
            "document": forms.Select(attrs={"class": "form-control"}),
            "signing_type": forms.Select(attrs={"class": "form-control"}),
            "signer": forms.Select(attrs={"class": "form-control"}),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

        if user is not None:
            self.fields["document"].queryset = Document.objects.filter(
                owner=user,
                status__in=[
                    Document.Status.UPLOADED,
                    Document.Status.PENDING_SIGN,
                ],
            )

            self.fields["signer"].queryset = User.objects.filter(
                Q(pk=user.pk) | Q(role__in=[User.Role.OFFICER, User.Role.ADMIN]),
                is_verified_identity=True,
                certificate_profile__status=UserCertificate.Status.ACTIVE,
            ).distinct()
        else:
            self.fields["document"].queryset = Document.objects.none()
            self.fields["signer"].queryset = User.objects.none()

        self.fields["signing_type"].empty_label = None

    def clean(self):
        cleaned = super().clean()
        user = self.user
        document = cleaned.get("document")
        signer = cleaned.get("signer")

        if not user or not document or not signer:
            return cleaned

        if document.owner != user:
            raise forms.ValidationError(
                "You can only create signing requests for your own documents."
            )

        if user.role == User.Role.CITIZEN:
            if not user.is_verified_identity:
                raise forms.ValidationError(
                    "Your identity has not been verified. You cannot create signing requests."
                )

            if not user_has_active_cert(user):
                raise forms.ValidationError(
                    "You do not have an active certificate. Please wait for RA certificate issuance."
                )

        if not user_has_active_cert(signer):
            raise forms.ValidationError(
                "Selected signer does not have an active certificate."
            )

        if document_has_officer_signature(document):
            raise forms.ValidationError(
                "This document already has an officer approval signature."
            )

        has_citizen_sig = document_has_citizen_signature(document)

        if not has_citizen_sig:
            if signer != user:
                raise forms.ValidationError(
                    "The first signature must be created by the citizen who owns the document."
                )
        else:
            if signer == user:
                raise forms.ValidationError(
                    "Citizen has already signed this document. Please select an officer for approval."
                )

            if signer.role not in [User.Role.OFFICER, User.Role.ADMIN]:
                raise forms.ValidationError(
                    "After citizen signing, the next signer must be an officer/admin."
                )

        if SigningRequest.objects.filter(
            document=document,
            signer=signer,
            status=SigningRequest.Status.PENDING,
        ).exists():
            raise forms.ValidationError(
                "There is already a pending signing request for this signer."
            )

        return cleaned


class CitizenRegistrationForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control"})
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control"})
    )

    class Meta:
        model = UserModel
        fields = ["email", "full_name", "citizen_id"]
        widgets = {
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "you@example.com",
                }
            ),
            "full_name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Full name",
                }
            ),
            "citizen_id": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Citizen ID",
                }
            ),
        }

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if UserModel.objects.filter(email=email).exists():
            raise forms.ValidationError("Email is already registered.")
        return email

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password") != cleaned.get("confirm_password"):
            self.add_error("confirm_password", "Password confirmation does not match.")
        return cleaned


class PublicVerifyUploadForm(forms.Form):
    SIGNATURE_FORMAT_CHOICES = [
        ("cades", "CAdES/CMS detached (.p7s)"),
        ("raw", "RAW signature + certificate PEM"),
        ("pades", "PAdES signed PDF"),
    ]

    signature_format = forms.ChoiceField(
        choices=SIGNATURE_FORMAT_CHOICES,
        widget=forms.Select(attrs={"class": "form-control"}),
    )

    document_file = forms.FileField(
        label="Original document",
        widget=forms.FileInput(attrs={"class": "form-control"}),
    )

    signature_file = forms.FileField(
        label="Signature file (.p7s / .sig / .txt)",
        required=False,
        widget=forms.FileInput(attrs={"class": "form-control"}),
    )

    certificate_file = forms.FileField(
        label="Signer certificate PEM/CRT",
        required=False,
        widget=forms.FileInput(attrs={"class": "form-control"}),
        help_text="Required only for RAW signature mode. CAdES usually carries signer certificate inside .p7s.",
    )

    def clean(self):
        cleaned = super().clean()
        signature_format = cleaned.get("signature_format")
        signature_file = cleaned.get("signature_file")
        certificate_file = cleaned.get("certificate_file")

        if signature_format == "raw":
            if not signature_file:
                self.add_error(
                    "signature_file",
                    "Signature file is required for RAW signature verification.",
                )
            if not certificate_file:
                self.add_error(
                    "certificate_file",
                    "Certificate file is required for RAW signature verification.",
                )

        if signature_format == "cades" and not signature_file:
            self.add_error(
                "signature_file",
                "Signature .p7s file is required for CAdES/CMS verification.",
            )

        return cleaned
    
class CitizenGeneratedDocumentForm(forms.Form):
    title = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )

    content = forms.CharField(
        widget=forms.Textarea(attrs={"class": "form-control", "rows": 8}),
    )