from django.urls import path
from .views import EnrollFileClientCertificateView

urlpatterns = [
    path(
        "certificates/enroll-file-client/",
        EnrollFileClientCertificateView.as_view(),
        name="enroll-file-client-certificate",
    ),
]