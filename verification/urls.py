from django.urls import path
from .views import RunVerificationView, VerificationResultDetailView

urlpatterns = [
    path("signatures/<int:pk>/verify/", RunVerificationView.as_view(), name="run-verification"),
    path("results/<int:pk>/", VerificationResultDetailView.as_view(), name="verification-result-detail"),
]