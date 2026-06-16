from django.urls import path
from .views import (
    SigningRequestListCreateView,
    SigningRequestDetailView,
    SignatureRecordDetailView,
    RemoteSignView,
    PrepareClientSignView,
    CompleteClientSignView,
)
from . import client_api_views

urlpatterns = [
    path("requests/", SigningRequestListCreateView.as_view(), name="signing-request-list-create"),
    path("requests/<int:pk>/", SigningRequestDetailView.as_view(), name="signing-request-detail"),
    path("requests/<int:pk>/remote-sign/", RemoteSignView.as_view(), name="remote-sign"),
    path("requests/<int:pk>/prepare-client-sign/", PrepareClientSignView.as_view(), name="prepare-client-sign"),
    path("requests/<int:pk>/complete-client-sign/", CompleteClientSignView.as_view(), name="complete-client-sign"),
    path("signatures/<int:pk>/", SignatureRecordDetailView.as_view(), name="signature-record-detail"),
    path("api/client/pending/", client_api_views.pending_client_requests, name="client_pending_requests"),
    path("api/client/requests/<int:request_id>/file/", client_api_views.client_request_file, name="client_request_file"),
    path(
        "api/client/<int:request_id>/submit/",
        client_api_views.submit_client_signature,
        name="client-submit-signature",
    ),
    path(
        "api/client/pair/",
        client_api_views.pair_client_device,
        name="client-pair-device",
    ),
]