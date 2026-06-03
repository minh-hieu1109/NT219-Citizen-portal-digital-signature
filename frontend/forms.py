from django import forms
from django.contrib.auth import get_user_model
from accounts.models import User
from documents.models import Document
from signing.models import SigningRequest

UserModel = get_user_model()


class DocumentUploadForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['title', 'file']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Document title'}),
            'file': forms.FileInput(attrs={'class': 'form-control-file'}),
        }


class ClientAutoSignForm(forms.ModelForm):
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
        required=False,
        label="Signer certificate owner",
    )

    class Meta:
        model = SigningRequest
        fields = ['document', 'signing_type', 'signer']
        widgets = {
            'document': forms.Select(attrs={'class': 'form-control'}),
            'signing_type': forms.Select(attrs={'class': 'form-control'}),
            'signer': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.fields["signing_type"].empty_label = None

        if user is not None:
            self.fields["document"].queryset = Document.objects.filter(
                owner=user,
                status=Document.Status.UPLOADED,
            )

            if user.role == User.Role.CITIZEN:
                self.fields["signing_type"].choices = [
                    (SigningRequest.SigningType.CLIENT, "Citizen client signature"),
                ]
                self.fields["signing_type"].initial = SigningRequest.SigningType.CLIENT
                self.fields["signer"].queryset = User.objects.filter(pk=user.pk)
                self.fields["signer"].initial = user
                self.fields["signer"].widget = forms.HiddenInput()
                self.fields["signer"].help_text = "Citizen signing uses your own certificate."
            else:
                eligible_qs = User.objects.filter(
                    is_verified_identity=True,
                    certificate_profile__status="active",
                ).distinct()
                self.fields["signer"].queryset = eligible_qs
                self.fields["signing_type"].choices = [
                    (SigningRequest.SigningType.REMOTE, "Officer administrative approval signature"),
                    (SigningRequest.SigningType.CLIENT, "Client signature"),
                ]
        else:
            self.fields["signer"].queryset = User.objects.none()

    def clean(self):
        cleaned = super().clean()
        user = getattr(self, "user", None)
        if user is None:
            return cleaned

        if user.role == User.Role.CITIZEN:
            if not user.is_verified_identity or not hasattr(user, "certificate_profile"):
                raise forms.ValidationError(
                    "Your identity must be verified and a certificate must be issued before signing."
                )
            if user.certificate_profile.status != "active":
                raise forms.ValidationError(
                    "Your identity must be verified and a certificate must be issued before signing."
                )
            cleaned["signer"] = user
            cleaned["signing_type"] = SigningRequest.SigningType.CLIENT

        return cleaned


class CitizenRegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={"class": "form-control"}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={"class": "form-control"}))

    class Meta:
        model = UserModel
        fields = ["email", "full_name", "citizen_id"]
        widgets = {
            "email": forms.EmailInput(attrs={"class": "form-control", "placeholder": "you@example.com"}),
            "full_name": forms.TextInput(attrs={"class": "form-control", "placeholder": "Full name"}),
            "citizen_id": forms.TextInput(attrs={"class": "form-control", "placeholder": "Citizen ID"}),
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
