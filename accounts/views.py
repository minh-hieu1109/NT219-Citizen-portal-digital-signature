from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from rest_framework.generics import ListAPIView
from django.shortcuts import get_object_or_404

from audit.models import AuditLog
from audit.utils import log_action
from .models import User, UserCertificate
from .serializers import (
    EnrollFileClientCertificateSerializer,
    PendingIdentityUserSerializer,
)
from .services import issue_certificate_for_user, issue_certificate_from_csr_for_user


class IsOfficerOrAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and user.role in {User.Role.OFFICER, User.Role.ADMIN}
        )


class PendingIdentityListView(ListAPIView):
    serializer_class = PendingIdentityUserSerializer
    permission_classes = [permissions.IsAuthenticated, IsOfficerOrAdmin]

    def get_queryset(self):
        return (
            User.objects.filter(
                role=User.Role.CITIZEN,
                is_verified_identity=False,
            )
            .order_by("-created_at")
        )


class VerifyIdentityView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsOfficerOrAdmin]

    def post(self, request, user_id):
        target_user = get_object_or_404(User, pk=user_id)
        target_user.is_verified_identity = True
        target_user.save(update_fields=["is_verified_identity"])

        log_action(
            user=request.user,
            action=AuditLog.Action.IDENTITY_VERIFIED,
            object_type="User",
            object_id=target_user.id,
            detail={
                "target_user_email": target_user.email,
                "target_user_role": target_user.role,
                "is_verified_identity": target_user.is_verified_identity,
            },
            request=request,
        )

        return Response(
            {
                "message": "Identity verified successfully.",
                "user_id": target_user.id,
                "is_verified_identity": target_user.is_verified_identity,
            },
            status=status.HTTP_200_OK,
        )


class RejectIdentityView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsOfficerOrAdmin]

    def post(self, request, user_id):
        target_user = get_object_or_404(User, pk=user_id)
        target_user.is_verified_identity = False
        target_user.save(update_fields=["is_verified_identity"])

        log_action(
            user=request.user,
            action=AuditLog.Action.IDENTITY_REJECTED,
            object_type="User",
            object_id=target_user.id,
            detail={
                "target_user_email": target_user.email,
                "target_user_role": target_user.role,
                "is_verified_identity": target_user.is_verified_identity,
            },
            request=request,
        )

        return Response(
            {
                "message": "Identity rejected.",
                "user_id": target_user.id,
                "is_verified_identity": target_user.is_verified_identity,
            },
            status=status.HTTP_200_OK,
        )


class IssueCertificateView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsOfficerOrAdmin]

    def post(self, request, user_id):
        target_user = get_object_or_404(User, pk=user_id)

        if target_user.role == User.Role.CITIZEN and not target_user.is_verified_identity:
            return Response(
                {"detail": "Citizen identity must be verified before certificate issuance."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        had_certificate = UserCertificate.objects.filter(user=target_user).exists()
        user_cert = issue_certificate_for_user(target_user)

        log_action(
            user=request.user,
            action=AuditLog.Action.CERTIFICATE_ISSUED,
            object_type="UserCertificate",
            object_id=user_cert.id,
            detail={
                "target_user_id": target_user.id,
                "target_user_email": target_user.email,
                "certificate_serial": user_cert.certificate_serial,
                "is_verified_identity": target_user.is_verified_identity,
                "already_had_certificate": had_certificate,
            },
            request=request,
        )

        return Response(
            {
                "message": "Certificate issued successfully.",
                "user_id": target_user.id,
                "certificate_serial": user_cert.certificate_serial,
            },
            status=status.HTTP_200_OK,
        )

class EnrollFileClientCertificateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if request.user.role == User.Role.CITIZEN and not request.user.is_verified_identity:
            return Response(
                {"detail": "Citizen identity must be verified before certificate enrollment."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = EnrollFileClientCertificateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            result = issue_certificate_from_csr_for_user(
                user=request.user,
                csr_pem=serializer.validated_data["csr_pem"],
                key_storage_type=serializer.validated_data.get("key_storage_type", "file"),
                private_key_path=serializer.validated_data.get("private_key_path"),
                pkcs11_token_label=serializer.validated_data.get("pkcs11_token_label"),
                pkcs11_key_label=serializer.validated_data.get("pkcs11_key_label"),
                pkcs11_key_id=serializer.validated_data.get("pkcs11_key_id"),
                pkcs11_slot=serializer.validated_data.get("pkcs11_slot"),
            )
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(
                {"detail": f"Certificate enrollment failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                "message": "Certificate issued successfully.",
                "certificate_pem": result["certificate_pem"],
                "certificate_subject": result["certificate_subject"],
                "certificate_serial": result["certificate_serial"],
            },
            status=status.HTTP_200_OK,
        )
