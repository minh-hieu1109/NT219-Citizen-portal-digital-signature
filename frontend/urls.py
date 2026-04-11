from django.urls import path
from .views import (
    HomeView,
    DocumentListView,
    DocumentUploadView,
    SigningRequestListView,
    SigningRequestCreateView,
    RemoteSignView,
    ClientSignInstructionsView,
)

urlpatterns = [
    path('', HomeView.as_view(), name='home'),
    path('documents/', DocumentListView.as_view(), name='document-list'),
    path('documents/upload/', DocumentUploadView.as_view(), name='document-upload'),
    path('signing/requests/', SigningRequestListView.as_view(), name='signing-request-list'),
    path('signing/requests/create/', SigningRequestCreateView.as_view(), name='signing-request-create'),
    path('signing/requests/<int:pk>/remote-sign/', RemoteSignView.as_view(), name='remote-sign'),
    path('signing/requests/<int:pk>/client-sign/', ClientSignInstructionsView.as_view(), name='client-sign-instructions'),
]
