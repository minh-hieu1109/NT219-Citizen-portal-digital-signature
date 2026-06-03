from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.db.models import Q
from django.http import Http404, HttpResponseForbidden, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.generic import DetailView, FormView, ListView, TemplateView, View

from audit.models import AuditLog
from audit.utils import log_action
from accounts.services import issue_certificate_from_csr_for_user
from documents.models import Document
from documents.services import calculate_sha256
from signing.models import SignatureRecord, SigningRequest
from signing.services import (
    complete_client_signing_request,
    prepare_client_signing_request,
    remote_sign_signing_request,
)
from verification.models import ValidationEvidence, VerificationResult
from verification.services import verify_signature_record
from .forms import CitizenRegistrationForm, ClientAutoSignForm, DocumentUploadForm, SigningRequestForm, PublicVerifyUploadForm
import base64
import io
import json
import zipfile
from pathlib import Path
import tempfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID
from signing.cms_services import create_cms_detached_signature
from accounts.models import UserCertificate
from django.conf import settings
User = get_user_model()
from verification.public_verify_services import verify_public_cms_detached, verify_public_raw_signature, verify_public_pades 
from signing.pades_services import create_pades_signature

class OfficerAdminRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    raise_exception = True

    def test_func(self):
        user = self.request.user
        return user.role in {User.Role.OFFICER, User.Role.ADMIN}


class HomeView(TemplateView):
    template_name = "frontend/home.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["user_exists"] = User.objects.exists()
        context["is_officer_admin"] = False

        if self.request.user.is_authenticated:
            user = self.request.user
            doc_qs = Document.objects.filter(owner=user)
            signing_qs = SigningRequest.objects.filter(Q(requested_by=user) | Q(signer=user)).distinct()
            signature_qs = SignatureRecord.objects.filter(signing_request__in=signing_qs)
            verification_qs = VerificationResult.objects.filter(signature_record__in=signature_qs)
            evidence_qs = ValidationEvidence.objects.filter(signature_record__in=signature_qs)
            audit_qs = AuditLog.objects.filter(user=user)

            if user.role in {User.Role.OFFICER, User.Role.ADMIN}:
                context["is_officer_admin"] = True
                context["pending_identity_count"] = User.objects.filter(
                    role=User.Role.CITIZEN,
                    is_verified_identity=False,
                ).count()
                context["audit_count"] = AuditLog.objects.count()
            else:
                context["audit_count"] = audit_qs.count()

            context["counts"] = {
                "documents": doc_qs.count(),
                "signing_requests": signing_qs.count(),
                "signatures": signature_qs.count(),
                "verification_results": verification_qs.count(),
                "validation_evidence": evidence_qs.count(),
                "audit_logs": context["audit_count"],
            }

        return context


class DocumentListView(LoginRequiredMixin, ListView):
    template_name = "frontend/documents.html"
    model = Document
    context_object_name = "documents"

    def get_queryset(self):
        user = self.request.user
        qs = Document.objects.select_related("owner").order_by("-uploaded_at")
        if user.role in {User.Role.OFFICER, User.Role.ADMIN}:
            return qs
        return qs.filter(owner=user)


class DocumentDetailView(LoginRequiredMixin, DetailView):
    template_name = "frontend/document_detail.html"
    model = Document
    context_object_name = "document"

    def get_queryset(self):
        user = self.request.user
        qs = Document.objects.select_related("owner")
        if user.role in {User.Role.OFFICER, User.Role.ADMIN}:
            return qs
        return qs.filter(owner=user)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        signatures = SignatureRecord.objects.filter(
            signing_request__document=self.object
        ).select_related("signing_request")
        context["signature_records"] = signatures
        context["verification_results"] = VerificationResult.objects.filter(
            signature_record__in=signatures
        ).select_related("signature_record")
        return context


class DocumentUploadView(LoginRequiredMixin, FormView):
    template_name = "frontend/upload_document.html"
    form_class = DocumentUploadForm
    success_url = reverse_lazy("document-list")

    def form_valid(self, form):
        document = form.save(commit=False)
        document.owner = self.request.user
        document.sha256_hash = calculate_sha256(form.cleaned_data["file"])
        document.status = Document.Status.UPLOADED
        document.save()
        try:
            log_action(
                user=self.request.user,
                action=AuditLog.Action.DOCUMENT_UPLOAD,
                object_type="Document",
                object_id=document.id,
                detail={"title": document.title},
                request=self.request,
            )
        except Exception:
            pass
        messages.success(self.request, "Document uploaded successfully.")
        return super().form_valid(form)


def _portal_demo_key_paths(user):
    key_dir = Path(settings.BASE_DIR) / "keys"
    return {
        "key_dir": key_dir,
        "private_key": key_dir / f"portal_client_user_{user.id}_private_key.pem",
        "csr": key_dir / f"portal_client_user_{user.id}.csr",
        "certificate": key_dir / f"portal_client_user_{user.id}_certificate.pem",
    }


def _load_or_create_portal_demo_private_key(user):
    paths = _portal_demo_key_paths(user)
    paths["key_dir"].mkdir(parents=True, exist_ok=True)
    key_path = paths["private_key"]

    if key_path.exists():
        return serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return private_key


def _certificate_matches_private_key(certificate_pem, private_key):
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    return certificate.public_key().public_numbers() == private_key.public_key().public_numbers()


def _build_portal_demo_csr(user, private_key):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "HCM"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "HCM"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Citizen Portal"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Portal Client Signing Demo"),
                    x509.NameAttribute(NameOID.COMMON_NAME, user.full_name or user.email),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, user.email),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _ensure_portal_demo_client_certificate(user):
    private_key = _load_or_create_portal_demo_private_key(user)
    paths = _portal_demo_key_paths(user)

    existing = UserCertificate.objects.filter(
        user=user,
        status=UserCertificate.Status.ACTIVE,
    ).first()
    if existing and existing.certificate_pem:
        try:
            if _certificate_matches_private_key(existing.certificate_pem, private_key):
                paths["certificate"].write_text(existing.certificate_pem, encoding="utf-8")
                return existing, private_key
        except Exception:
            pass

    csr_pem = _build_portal_demo_csr(user, private_key)
    paths["csr"].write_text(csr_pem, encoding="utf-8")
    issued = issue_certificate_from_csr_for_user(
        user=user,
        csr_pem=csr_pem,
        key_storage_type=UserCertificate.KeyStorageType.FILE,
        private_key_path=str(paths["private_key"]),
    )
    paths["certificate"].write_text(issued["certificate_pem"], encoding="utf-8")
    return issued["user_certificate"], private_key


class ClientAutoSignView(LoginRequiredMixin, FormView):
    template_name = "frontend/client_auto_sign.html"
    form_class = ClientAutoSignForm

    def form_valid(self, form):
        user = self.request.user
        if user.role != User.Role.CITIZEN:
            messages.error(self.request, "Citizen upload & sign is available only for citizen accounts.")
            return self.form_invalid(form)

        if user.role == User.Role.CITIZEN and not user.is_verified_identity:
            messages.error(self.request, "Identity must be verified before client signing.")
            return self.form_invalid(form)

        document = form.save(commit=False)
        document.owner = user
        document.sha256_hash = calculate_sha256(form.cleaned_data["file"])
        document.status = Document.Status.PENDING_SIGN
        document.save()

        try:
            _user_cert, private_key = _ensure_portal_demo_client_certificate(user)
            signing_request = SigningRequest.objects.create(
                document=document,
                requested_by=user,
                signer=user,
                signing_type=SigningRequest.SigningType.CLIENT,
                status=SigningRequest.Status.PENDING,
            )

            prepare_data = prepare_client_signing_request(signing_request)
            digest_bytes = bytes.fromhex(prepare_data["digest_hex"])
            signature_bytes = private_key.sign(
                digest_bytes,
                padding.PKCS1v15(),
                utils.Prehashed(hashes.SHA256()),
            )
            signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

            signature_record = complete_client_signing_request(
                signing_request=signing_request,
                signature_b64=signature_b64,
                algorithm=prepare_data["algorithm"],
            )
            verification_result = verify_signature_record(signature_record)

            try:
                log_action(
                    user=user,
                    action=AuditLog.Action.DOCUMENT_UPLOAD,
                    object_type="Document",
                    object_id=document.id,
                    detail={"title": document.title, "client_auto_signed": True},
                    request=self.request,
                )
                log_action(
                    user=user,
                    action=AuditLog.Action.SIGNING_REQUEST_CREATED,
                    object_type="SigningRequest",
                    object_id=signing_request.id,
                    detail={"document_id": document.id, "signing_type": "client"},
                    request=self.request,
                )
                log_action(
                    user=user,
                    action=AuditLog.Action.CLIENT_SIGNED,
                    object_type="SignatureRecord",
                    object_id=signature_record.id,
                    detail={
                        "signature_purpose": "citizen_signature",
                        "signing_request_id": signing_request.id,
                        "document_id": document.id,
                        "signer_email": user.email,
                        "certificate_serial": signature_record.certificate_serial,
                    },
                    request=self.request,
                )
                log_action(
                    user=user,
                    action=AuditLog.Action.VERIFICATION_RUN,
                    object_type="VerificationResult",
                    object_id=verification_result.id,
                    detail={
                        "signature_record_id": signature_record.id,
                        "status": verification_result.status,
                        "signature_purpose": "citizen_signature",
                    },
                    request=self.request,
                )
            except Exception:
                pass

            messages.success(
                self.request,
                f"Document uploaded, client-signed, and verified: {verification_result.status}.",
            )
            return redirect("document-detail", pk=document.id)
        except Exception as exc:
            document.status = Document.Status.VERIFICATION_FAILED
            document.save(update_fields=["status", "updated_at"])
            messages.error(self.request, f"Client signing failed: {exc}")
            return redirect("document-detail", pk=document.id)


class SigningRequestListView(LoginRequiredMixin, ListView):
    template_name = "frontend/signing_requests.html"
    model = SigningRequest
    context_object_name = "signing_requests"

    def get_queryset(self):
        user = self.request.user
        qs = SigningRequest.objects.select_related(
            "document", "requested_by", "signer"
        ).order_by("-created_at")
        if user.role == User.Role.ADMIN:
            return qs
        if user.role == User.Role.OFFICER:
            return qs.filter(signer=user)
        return qs.filter(requested_by=user)


class SigningRequestDetailView(LoginRequiredMixin, DetailView):
    template_name = "frontend/signing_request_detail.html"
    model = SigningRequest
    context_object_name = "signing_request"

    def get_queryset(self):
        user = self.request.user
        qs = SigningRequest.objects.select_related("document", "requested_by", "signer")
        if user.role in {User.Role.OFFICER, User.Role.ADMIN}:
            return qs
        return qs.filter(Q(requested_by=user) | Q(signer=user)).distinct()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        request_obj = self.object
        signer = request_obj.signer
        signer_verified = bool(signer and signer.is_verified_identity)
        signer_has_active_cert = bool(
            signer
            and hasattr(signer, "certificate_profile")
            and signer.certificate_profile.status == "active"
        )
        is_pending = request_obj.status == SigningRequest.Status.PENDING
        is_expired = bool(request_obj.expires_at and timezone.now() > request_obj.expires_at)
        is_used = request_obj.used_at is not None
        context["can_show_remote_sign"] = (
            request_obj.signing_type == SigningRequest.SigningType.REMOTE
            and is_pending
            and not is_expired
            and not is_used
            and signer_verified
            and signer_has_active_cert
            and self.request.user == signer
        )
        context["signer_verified"] = signer_verified
        context["signer_has_active_cert"] = signer_has_active_cert
        context["is_pending"] = is_pending
        context["is_expired"] = is_expired
        context["is_used"] = is_used
        context["is_officer_admin"] = self.request.user.role in {User.Role.OFFICER, User.Role.ADMIN}
        context["signature_purpose"] = request_obj.signature_purpose
        context["signer_certificate"] = None
        if signer:
            context["signer_certificate"] = UserCertificate.objects.filter(
                user=signer,
                status=UserCertificate.Status.ACTIVE,
            ).first()
        return context


class SigningRequestCreateView(LoginRequiredMixin, FormView):
    template_name = "frontend/signing_request_create.html"
    form_class = SigningRequestForm
    success_url = reverse_lazy("signing-request-list")

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        signing_request = form.save(commit=False)
        signing_request.requested_by = self.request.user
        signing_request.signer = form.cleaned_data["signer"]
        signing_request.status = SigningRequest.Status.PENDING
        signing_request.save()

        signing_request.document.status = Document.Status.PENDING_SIGN
        signing_request.document.save(update_fields=["status", "updated_at"])
        try:
            log_action(
                user=self.request.user,
                action=AuditLog.Action.SIGNING_REQUEST_CREATED,
                object_type="SigningRequest",
                object_id=signing_request.id,
                detail={
                    "document_id": signing_request.document_id,
                    "signer_id": signing_request.signer_id,
                    "signer_email": signing_request.signer.email if signing_request.signer else "",
                    "signing_type": signing_request.signing_type,
                    "signature_purpose": signing_request.signature_purpose,
                },
                request=self.request,
            )
        except Exception:
            pass

        messages.success(self.request, "Signing request created successfully.")
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.user.role == User.Role.CITIZEN:
            has_active_cert = bool(
                self.request.user.is_verified_identity
                and hasattr(self.request.user, "certificate_profile")
                and self.request.user.certificate_profile.status == UserCertificate.Status.ACTIVE
            )
            context["eligible_signer_count"] = 1 if has_active_cert else 0
        else:
            context["eligible_signer_count"] = context["form"].fields["signer"].queryset.count()
        context["is_officer_admin"] = self.request.user.role in {User.Role.OFFICER, User.Role.ADMIN}
        return context


class RemoteSignView(LoginRequiredMixin, View):
    def post(self, request, pk):
        try:
            signing_request = SigningRequest.objects.select_related("signer").get(pk=pk)
        except SigningRequest.DoesNotExist:
            messages.error(request, "Signing request not found.")
            return redirect("signing-request-list")

        if signing_request.signer != request.user and request.user.role not in {User.Role.ADMIN, User.Role.OFFICER}:
            return HttpResponseForbidden("You do not have permission to sign this request.")

        if signing_request.signing_type != SigningRequest.SigningType.REMOTE:
            messages.error(request, "Only remote signing requests can be signed here.")
            return redirect("signing-request-detail", pk=pk)

        try:
            signature_record = remote_sign_signing_request(signing_request)
            try:
                log_action(
                    user=request.user,
                    action=AuditLog.Action.OFFICER_APPROVAL_SIGNED,
                    object_type="SignatureRecord",
                    object_id=signature_record.id,
                    detail={
                        "signing_request_id": signing_request.id,
                        "signature_purpose": signing_request.signature_purpose,
                        "signer_email": signing_request.signer.email if signing_request.signer else "",
                        "certificate_serial": signature_record.certificate_serial,
                    },
                    request=request,
                )
            except Exception:
                pass
            messages.success(request, f"Officer approval signing completed. Signature ID: {signature_record.id}.")
        except Exception as exc:
            try:
                log_action(
                    user=request.user,
                    action=AuditLog.Action.REMOTE_SIGNED,
                    object_type="SigningRequest",
                    object_id=signing_request.id,
                    detail={"status": "failed", "error": str(exc)},
                    request=request,
                )
            except Exception:
                pass
            messages.error(request, f"Remote signing failed: {str(exc)}")

        return redirect("signing-request-detail", pk=pk)


class ClientSignInstructionsView(LoginRequiredMixin, TemplateView):
    template_name = "frontend/client_sign_instructions.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        try:
            signing_request = SigningRequest.objects.get(pk=self.kwargs["pk"])
        except SigningRequest.DoesNotExist:
            raise Http404("Signing request not found.")

        if user.role not in {User.Role.ADMIN, User.Role.OFFICER} and signing_request.signer != user:
            raise Http404("Signing request not found.")

        context["signing_request"] = signing_request
        return context


class VerificationResultListView(LoginRequiredMixin, ListView):
    template_name = "frontend/verification_results.html"
    model = VerificationResult
    context_object_name = "verification_results"

    def get_queryset(self):
        user = self.request.user
        qs = VerificationResult.objects.select_related(
            "signature_record", "signature_record__signing_request", "signature_record__signing_request__document"
        ).order_by("-verified_at")
        if user.role in {User.Role.OFFICER, User.Role.ADMIN}:
            return qs
        return qs.filter(
            Q(signature_record__signing_request__requested_by=user)
            | Q(signature_record__signing_request__signer=user)
        ).distinct()


class VerifySignatureView(LoginRequiredMixin, View):
    def post(self, request, pk):
        signature_qs = SignatureRecord.objects.select_related(
            "signing_request", "signing_request__requested_by", "signing_request__signer"
        )
        signature_record = get_object_or_404(signature_qs, pk=pk)

        user = request.user
        if user.role not in {User.Role.OFFICER, User.Role.ADMIN}:
            if (
                signature_record.signing_request.requested_by != user
                and signature_record.signing_request.signer != user
            ):
                return HttpResponseForbidden("You do not have permission to verify this signature.")

        result = verify_signature_record(signature_record)
        try:
            log_action(
                user=request.user,
                action=AuditLog.Action.VERIFICATION_RUN,
                object_type="VerificationResult",
                object_id=result.id,
                detail={"signature_record_id": signature_record.id, "status": result.status},
                request=request,
            )
        except Exception:
            pass
        messages.success(request, f"Verification completed. Status: {result.status}.")
        return redirect("verification-result-list")


class CitizenRegisterView(FormView):
    template_name = "registration/register.html"
    form_class = CitizenRegistrationForm
    success_url = reverse_lazy("login")

    def form_valid(self, form):
        new_user = User.objects.create_user(
            email=form.cleaned_data["email"],
            password=form.cleaned_data["password"],
            full_name=form.cleaned_data["full_name"],
            citizen_id=form.cleaned_data["citizen_id"],
            role=User.Role.CITIZEN,
            is_verified_identity=False,
            is_active=True,
        )
        try:
            log_action(
                user=new_user,
                action="citizen_registered",
                object_type="User",
                object_id=new_user.id,
                detail={"event": "citizen_registration", "email": new_user.email},
                request=self.request,
            )
        except Exception:
            pass
        messages.success(
            self.request,
            "Registration successful. Please wait for RA/officer identity verification before signing.",
        )
        return super().form_valid(form)


class RAPendingListView(OfficerAdminRequiredMixin, ListView):
    template_name = "frontend/ra_pending.html"
    model = User
    context_object_name = "pending_users"

    def get_queryset(self):
        return User.objects.filter(
            role=User.Role.CITIZEN,
            is_verified_identity=False,
        ).order_by("-created_at")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["verified_without_cert_users"] = (
            User.objects.filter(is_verified_identity=True)
            .exclude(certificate_profile__status="active")
            .order_by("-created_at")
        )
        context["active_cert_users"] = (
            User.objects.filter(certificate_profile__status="active")
            .select_related("certificate_profile")
            .order_by("-created_at")
        )
        return context


class RAActionView(OfficerAdminRequiredMixin, View):
    action_map = {
        "verify": ("is_verified_identity", True, "Identity verified."),
        "reject": ("is_verified_identity", False, "Identity rejected."),
    }

    def post(self, request, user_id, action):
        target_user = get_object_or_404(User, pk=user_id)

        if action == "issue":
            from accounts.services import issue_certificate_for_user

            if target_user.role == User.Role.CITIZEN and not target_user.is_verified_identity:
                messages.error(request, "Citizen identity must be verified before certificate issuance.")
                return redirect("ra-pending")

            try:
                user_cert = issue_certificate_for_user(target_user)
            except Exception:
                user_cert, _private_key = _ensure_portal_demo_client_certificate(target_user)
            AuditLog.objects.create(
                user=request.user,
                action=AuditLog.Action.CERTIFICATE_ISSUED,
                object_type="UserCertificate",
                object_id=user_cert.id,
                detail={"target_user_email": target_user.email},
            )
            messages.success(request, "Certificate issued.")
            return redirect("ra-pending")

        if action not in self.action_map:
            return HttpResponseForbidden("Unsupported action")

        field, value, msg = self.action_map[action]
        setattr(target_user, field, value)
        target_user.save(update_fields=[field])

        audit_action = (
            AuditLog.Action.IDENTITY_VERIFIED
            if action == "verify"
            else AuditLog.Action.IDENTITY_REJECTED
        )
        AuditLog.objects.create(
            user=request.user,
            action=audit_action,
            object_type="User",
            object_id=target_user.id,
            detail={"target_user_email": target_user.email, "is_verified_identity": target_user.is_verified_identity},
        )

        messages.success(request, msg)
        return redirect("ra-pending")


class AuditLogListView(OfficerAdminRequiredMixin, ListView):
    template_name = "frontend/audit_logs.html"
    model = AuditLog
    context_object_name = "audit_logs"

    def get_queryset(self):
        return AuditLog.objects.select_related("user").order_by("-created_at")[:200]

class PublicVerifyUploadView(FormView):
    template_name = "frontend/public_verify_upload.html"
    form_class = PublicVerifyUploadForm

    def form_valid(self, form):
        signature_format = form.cleaned_data["signature_format"]
        document_file = form.cleaned_data["document_file"]
        signature_file = form.cleaned_data.get("signature_file")
        certificate_file = form.cleaned_data.get("certificate_file")

        if signature_format == "cades":
            result = verify_public_cms_detached(
                document_file=document_file,
                cms_signature_file=signature_file,
            )
        elif signature_format == "pades":
            result = verify_public_pades(
                signed_pdf_file=document_file,
            )
        else:
            result = verify_public_raw_signature(
                document_file=document_file,
                signature_file=signature_file,
                certificate_file=certificate_file,
            )

        return render(
            self.request,
            "frontend/public_verify_result.html",
            {"result": result},
        )
    
class DownloadVerificationPackageView(LoginRequiredMixin, View):
    def get(self, request, pk):
        signature_record = get_object_or_404(
            SignatureRecord.objects.select_related(
                "signing_request",
                "signing_request__document",
                "signing_request__requested_by",
                "signing_request__signer",
            ),
            pk=pk,
        )

        signing_request = signature_record.signing_request
        document = signing_request.document
        user = request.user

        allowed = (
            user.role in {User.Role.OFFICER, User.Role.ADMIN}
            or signing_request.requested_by == user
            or signing_request.signer == user
        )

        if not allowed:
            return HttpResponseForbidden(
                "You do not have permission to download this verification package."
            )

        if not document.file:
            raise Http404("Document file not found.")

        buffer = io.BytesIO()

        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            document_name = Path(document.file.name).name

            with document.file.open("rb") as f:
                zf.writestr(f"document/{document_name}", f.read())

            zf.writestr(
                "signature/signature.sig",
                signature_record.signature_value.encode("utf-8"),
            )
                        
            cms_result = {
                "ok": False,
                "message": "CMS signature was not created.",
            }

            try:
                signer_cert_profile = UserCertificate.objects.filter(
                    user=signing_request.signer,
                    status=UserCertificate.Status.ACTIVE,
                ).first()

                if not signer_cert_profile:
                    cms_result["message"] = "Signer certificate profile not found."
                elif signer_cert_profile.key_storage_type != UserCertificate.KeyStorageType.FILE:
                    cms_result["message"] = (
                        "CMS package requires file-based private key in this demo. "
                        f"Current key storage: {signer_cert_profile.key_storage_type}"
                    )
                elif not signer_cert_profile.private_key_path:
                    cms_result["message"] = (
                        "Signer private key path is not available. "
                        "CMS package requires file-based private key in this demo."
                    )
                else:
                    key_path = Path(signer_cert_profile.private_key_path)

                    if not key_path.is_absolute():
                        key_path = Path(settings.BASE_DIR) / key_path

                    if not key_path.exists():
                        cms_result["message"] = f"Signer private key not found: {key_path}"
                    else:
                        with tempfile.TemporaryDirectory() as tmpdir:
                            tmpdir = Path(tmpdir)

                            signer_cert_path = tmpdir / "signer_certificate.pem"
                            signer_cert_path.write_text(
                                signature_record.certificate_pem,
                                encoding="utf-8",
                            )

                            cms_signature_path = tmpdir / "signature.p7s"

                            cms_result = create_cms_detached_signature(
                                input_file=document.file.path,
                                signer_cert_path=str(signer_cert_path),
                                signer_key_path=str(key_path),
                                ca_cert_path=str(settings.PKI_ROOT_CA_CERT),
                                output_path=str(cms_signature_path),
                            )

                            if cms_result.get("ok") and cms_signature_path.exists():
                                zf.writestr(
                                    "signature/signature.p7s",
                                    cms_signature_path.read_bytes(),
                                )

            except Exception as exc:
                cms_result = {
                    "ok": False,
                    "message": f"CMS generation failed: {exc}",
                }

            zf.writestr(
                "signature/cms_status.txt",
                json.dumps(cms_result, indent=2, ensure_ascii=False),
            )
                        
            pades_result = {
                "ok": False,
                "status": "skipped",
                "message": "PAdES was not created.",
            }

            try:
                document_path = Path(document.file.path)

                if document_path.suffix.lower() != ".pdf":
                    pades_result["message"] = "PAdES skipped because document is not a PDF."
                else:
                    signer_cert_profile = UserCertificate.objects.filter(
                        user=signing_request.signer,
                        status=UserCertificate.Status.ACTIVE,
                    ).first()

                    if not signer_cert_profile:
                        pades_result["message"] = "Active signer certificate profile not found."
                    elif signer_cert_profile.key_storage_type != UserCertificate.KeyStorageType.FILE:
                        pades_result["message"] = (
                            "PAdES demo requires file-based private key. "
                            f"Current key storage: {signer_cert_profile.key_storage_type}"
                        )
                    elif not signer_cert_profile.private_key_path:
                        pades_result["message"] = "Signer private key path is not available."
                    else:
                        key_path = Path(signer_cert_profile.private_key_path)

                        if not key_path.is_absolute():
                            key_path = Path(settings.BASE_DIR) / key_path

                        if not key_path.exists():
                            pades_result["message"] = f"Signer private key not found: {key_path}"
                        else:
                            with tempfile.TemporaryDirectory() as tmpdir:
                                tmpdir = Path(tmpdir)

                                signer_cert_path = tmpdir / "signer_certificate.pem"
                                signer_cert_path.write_text(
                                    signature_record.certificate_pem,
                                    encoding="utf-8",
                                )

                                signed_pdf_path = tmpdir / "signed_document.pdf"

                                pades_result = create_pades_signature(
                                    input_pdf_path=str(document_path),
                                    signer_cert_path=str(signer_cert_path),
                                    signer_key_path=str(key_path),
                                    output_pdf_path=str(signed_pdf_path),
                                    ca_cert_path=str(settings.PKI_ROOT_CA_CERT),
                                )

                                if pades_result.get("ok") and signed_pdf_path.exists():
                                    zf.writestr(
                                        "pades/signed_document.pdf",
                                        signed_pdf_path.read_bytes(),
                                    )

            except Exception as exc:
                pades_result = {
                    "ok": False,
                    "status": "error",
                    "message": f"PAdES generation failed: {exc}",
                }

            zf.writestr(
                "pades/pades_status.txt",
                json.dumps(pades_result, indent=2, ensure_ascii=False),
            )
            zf.writestr(
                "certs/signer_certificate.pem",
                signature_record.certificate_pem or "",
            )

            try:
                ca_cert_path = Path(settings.PKI_ROOT_CA_CERT)
                if ca_cert_path.exists():
                    zf.writestr("certs/ca_certificate.pem", ca_cert_path.read_bytes())
            except Exception:
                pass

            if signature_record.timestamp_token:
                try:
                    timestamp_bytes = base64.b64decode(signature_record.timestamp_token)
                    zf.writestr("timestamp/timestamp.tsr", timestamp_bytes)
                except Exception:
                    zf.writestr(
                        "timestamp/timestamp_token_base64.txt",
                        signature_record.timestamp_token,
                    )

            metadata = {
                "signature_record_id": signature_record.id,
                "signing_request_id": signing_request.id,
                "document_title": document.title,
                "document_sha256": document.sha256_hash,
                "signed_hash": signature_record.signed_hash,
                "signature_purpose": signing_request.signature_purpose,
                "signature_format": "RAW + CAdES/CMS detached + PAdES PDF",
                "signature_encoding": "base64",
                "signing_type": signing_request.signing_type,
                "algorithm": signature_record.algorithm,
                "signer_email": signing_request.signer.email if signing_request.signer else "",
                "signer_role": signing_request.signer.role if signing_request.signer else "",
                "requester_email": signing_request.requested_by.email,
                "requested_by_email": signing_request.requested_by.email,
                "document_owner_email": document.owner.email if document.owner else "",
                "certificate_subject": signature_record.certificate_subject,
                "certificate_serial": signature_record.certificate_serial,
                "signer_certificate_subject": signature_record.certificate_subject,
                "signer_certificate_serial": signature_record.certificate_serial,
                "signed_at": signature_record.signed_at.isoformat(),
                "timestamp_status": signature_record.timestamp_status,
                "timestamp_message": signature_record.timestamp_message,
                "raw_signature_file": "signature/signature.sig",
                "cms_signature_file": "signature/signature.p7s",
                "cms_signature_created": bool(cms_result.get("ok")),
                "cms_signature_message": cms_result.get("message", ""),
                "pades_signed_pdf_file": "pades/signed_document.pdf",
                "pades_signature_created": bool(pades_result.get("ok")),
                "pades_signature_message": pades_result.get("message", ""),
            }

            zf.writestr(
                "metadata.json",
                json.dumps(metadata, indent=2, ensure_ascii=False),
            )

        buffer.seek(0)

        response = HttpResponse(buffer.getvalue(), content_type="application/zip")
        response["Content-Disposition"] = (
            f'attachment; filename="verification_package_signature_{signature_record.id}.zip"'
        )
        return response
