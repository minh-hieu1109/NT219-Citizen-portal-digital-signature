from django.urls import path
from .views import (
    EnrollFileClientCertificateView,
    IssueCertificateView,
    PendingIdentityListView,
    RejectIdentityView,
    VerifyIdentityView,
)

urlpatterns = [
    path("pending-identity/", PendingIdentityListView.as_view(), name="pending-identity"),
    path("<int:user_id>/verify-identity/", VerifyIdentityView.as_view(), name="verify-identity"),
    path("<int:user_id>/reject-identity/", RejectIdentityView.as_view(), name="reject-identity"),
    path("<int:user_id>/issue-certificate/", IssueCertificateView.as_view(), name="issue-certificate"),
    path(
        "certificates/enroll-file-client/",
        EnrollFileClientCertificateView.as_view(),
        name="enroll-file-client-certificate",
    ),
]
