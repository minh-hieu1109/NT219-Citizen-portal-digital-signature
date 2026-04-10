from django.urls import path
from .views import (
    SigningRequestListCreateView,
    SigningRequestDetailView,
    SignatureRecordDetailView,
    RemoteSignView,
    PrepareClientSignView,
    CompleteClientSignView,
)

urlpatterns = [
    path("requests/", SigningRequestListCreateView.as_view(), name="signing-request-list-create"),
    path("requests/<int:pk>/", SigningRequestDetailView.as_view(), name="signing-request-detail"),
    path("requests/<int:pk>/remote-sign/", RemoteSignView.as_view(), name="remote-sign"),
    path("requests/<int:pk>/prepare-client-sign/", PrepareClientSignView.as_view(), name="prepare-client-sign"),
    path("requests/<int:pk>/complete-client-sign/", CompleteClientSignView.as_view(), name="complete-client-sign"),
    path("signatures/<int:pk>/", SignatureRecordDetailView.as_view(), name="signature-record-detail"),
]