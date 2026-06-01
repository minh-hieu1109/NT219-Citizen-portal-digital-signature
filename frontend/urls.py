from django.urls import path

from .views import (
    AuditLogListView,
    ClientSignInstructionsView,
    DocumentDetailView,
    DocumentListView,
    DocumentUploadView,
    HomeView,
    RAActionView,
    RAPendingListView,
    RemoteSignView,
    SigningRequestCreateView,
    SigningRequestDetailView,
    SigningRequestListView,
    VerificationResultListView,
    VerifySignatureView,
)

urlpatterns = [
    path("", HomeView.as_view(), name="home"),
    path("documents/", DocumentListView.as_view(), name="document-list"),
    path("documents/upload/", DocumentUploadView.as_view(), name="document-upload"),
    path("documents/<int:pk>/", DocumentDetailView.as_view(), name="document-detail"),
    path("signing/requests/", SigningRequestListView.as_view(), name="signing-request-list"),
    path("signing/requests/create/", SigningRequestCreateView.as_view(), name="signing-request-create"),
    path("signing/requests/<int:pk>/", SigningRequestDetailView.as_view(), name="signing-request-detail"),
    path("signing/requests/<int:pk>/remote-sign/", RemoteSignView.as_view(), name="remote-sign"),
    path("signing/requests/<int:pk>/client-sign/", ClientSignInstructionsView.as_view(), name="client-sign-instructions"),
    path("verification/results/", VerificationResultListView.as_view(), name="verification-result-list"),
    path("verification/signature/<int:pk>/verify/", VerifySignatureView.as_view(), name="verify-signature"),
    path("ra/pending/", RAPendingListView.as_view(), name="ra-pending"),
    path("ra/<int:user_id>/<str:action>/", RAActionView.as_view(), name="ra-action"),
    path("audit/", AuditLogListView.as_view(), name="audit-log-list"),
]
