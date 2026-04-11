from django import forms
from documents.models import Document
from signing.models import SigningRequest


class DocumentUploadForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['title', 'file']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Document title'}),
            'file': forms.FileInput(attrs={'class': 'form-control-file'}),
        }


class SigningRequestForm(forms.ModelForm):
    class Meta:
        model = SigningRequest
        fields = ['document', 'signing_type']
        widgets = {
            'document': forms.Select(attrs={'class': 'form-control'}),
            'signing_type': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user is not None:
            self.fields['document'].queryset = Document.objects.filter(owner=user, status=Document.Status.UPLOADED)
        self.fields['signing_type'].empty_label = None
