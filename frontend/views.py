from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import TemplateView, FormView, ListView, View

from documents.models import Document
from documents.services import calculate_sha256
from signing.models import SigningRequest
from signing.services import remote_sign_signing_request
from .forms import DocumentUploadForm, SigningRequestForm


class HomeView(LoginRequiredMixin, TemplateView):
    template_name = 'frontend/home.html'


class DocumentListView(LoginRequiredMixin, ListView):
    template_name = 'frontend/documents.html'
    model = Document
    context_object_name = 'documents'

    def get_queryset(self):
        return Document.objects.filter(owner=self.request.user).order_by('-uploaded_at')


class DocumentUploadView(LoginRequiredMixin, FormView):
    template_name = 'frontend/upload_document.html'
    form_class = DocumentUploadForm
    success_url = reverse_lazy('document-list')

    def form_valid(self, form):
        document = form.save(commit=False)
        document.owner = self.request.user
        document.sha256_hash = calculate_sha256(form.cleaned_data['file'])
        document.status = Document.Status.UPLOADED
        document.save()
        messages.success(self.request, 'Document uploaded successfully.')
        return super().form_valid(form)


class SigningRequestListView(LoginRequiredMixin, ListView):
    template_name = 'frontend/signing_requests.html'
    model = SigningRequest
    context_object_name = 'signing_requests'

    def get_queryset(self):
        return SigningRequest.objects.filter(requested_by=self.request.user).order_by('-created_at')


class SigningRequestCreateView(LoginRequiredMixin, FormView):
    template_name = 'frontend/signing_request_create.html'
    form_class = SigningRequestForm
    success_url = reverse_lazy('signing-request-list')

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        signing_request = form.save(commit=False)
        signing_request.requested_by = self.request.user
        signing_request.signer = self.request.user
        signing_request.status = SigningRequest.Status.PENDING
        signing_request.save()

        signing_request.document.status = Document.Status.PENDING_SIGN
        signing_request.document.save(update_fields=['status', 'updated_at'])

        messages.success(self.request, 'Signing request created successfully.')
        return super().form_valid(form)


class RemoteSignView(LoginRequiredMixin, View):
    def post(self, request, pk):
        try:
            signing_request = SigningRequest.objects.get(pk=pk, requested_by=request.user)
        except SigningRequest.DoesNotExist:
            messages.error(request, 'Signing request not found.')
            return redirect('signing-request-list')

        if signing_request.signing_type != SigningRequest.SigningType.REMOTE:
            messages.error(request, 'Only remote signing requests can be signed here.')
            return redirect('signing-request-list')

        try:
            signature_record = remote_sign_signing_request(signing_request)
            messages.success(request, f'Remote signing completed. Signature ID: {signature_record.id}.')
        except Exception as exc:
            messages.error(request, f'Remote signing failed: {str(exc)}')

        return redirect('signing-request-list')


class ClientSignInstructionsView(LoginRequiredMixin, TemplateView):
    template_name = 'frontend/client_sign_instructions.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            signing_request = SigningRequest.objects.get(pk=self.kwargs['pk'], requested_by=self.request.user)
        except SigningRequest.DoesNotExist:
            raise Http404('Signing request not found.')

        context['signing_request'] = signing_request
        return context
