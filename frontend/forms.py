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


class SigningRequestForm(forms.ModelForm):
    signer = forms.ModelChoiceField(
        queryset=User.objects.none(),
        required=True,
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
        eligible_qs = User.objects.filter(
            is_verified_identity=True,
            certificate_profile__status="active",
        ).distinct()

        if user is not None:
            self.fields['document'].queryset = Document.objects.filter(owner=user, status=Document.Status.UPLOADED)
            self.fields['signer'].queryset = eligible_qs
        else:
            self.fields['signer'].queryset = eligible_qs
        self.fields['signing_type'].empty_label = None


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