from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response

from .models import SigningRequest, SignatureRecord
from .serializers import (
    SigningRequestSerializer,
    SignatureRecordSerializer,
    RemoteSignSerializer,
    ClientSignPrepareSerializer,
    ClientSignCompleteSerializer,
)


class SigningRequestListCreateView(generics.ListCreateAPIView):
    serializer_class = SigningRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Hiển thị các request mà user tạo
        return (
            SigningRequest.objects.filter(requested_by=self.request.user)
            .select_related("document", "requested_by", "signer")
            .order_by("-created_at")
        )

    def perform_create(self, serializer):
        serializer.save()


class SigningRequestDetailView(generics.RetrieveAPIView):
    serializer_class = SigningRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Cho phép xem request nếu user là người tạo hoặc là signer
        return (
            SigningRequest.objects.filter()
            .select_related("document", "requested_by", "signer")
            .filter(
                requested_by=self.request.user
            ) | SigningRequest.objects.filter(
                signer=self.request.user
            ).select_related("document", "requested_by", "signer")
        )


class SignatureRecordDetailView(generics.RetrieveAPIView):
    serializer_class = SignatureRecordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Cho phép xem signature record nếu user là requested_by hoặc signer
        return (
            SignatureRecord.objects.filter(
                signing_request__requested_by=self.request.user
            )
            .select_related("signing_request", "signing_request__document", "signing_request__requested_by", "signing_request__signer")
            |
            SignatureRecord.objects.filter(
                signing_request__signer=self.request.user
            ).select_related("signing_request", "signing_request__document", "signing_request__requested_by", "signing_request__signer")
        )


class RemoteSignView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            signing_request = (
                SigningRequest.objects.select_related("document", "requested_by", "signer")
                .get(pk=pk)
            )
        except SigningRequest.DoesNotExist:
            return Response(
                {"detail": "Signing request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = RemoteSignSerializer(
            data={},
            context={
                "request": request,
                "signing_request": signing_request,
            },
        )
        serializer.is_valid(raise_exception=True)
        result = serializer.save()

        return Response(
            {
                "message": result["message"],
                "signature_record": SignatureRecordSerializer(
                    result["signature_record"]
                ).data,
            },
            status=status.HTTP_200_OK,
        )
    
class PrepareClientSignView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            signing_request = (
                SigningRequest.objects.select_related("document", "requested_by", "signer")
                .get(pk=pk)
            )
        except SigningRequest.DoesNotExist:
            return Response(
                {"detail": "Signing request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = ClientSignPrepareSerializer(
            data={},
            context={
                "request": request,
                "signing_request": signing_request,
            },
        )
        serializer.is_valid(raise_exception=True)
        result = serializer.save()

        return Response(result, status=status.HTTP_200_OK)


class CompleteClientSignView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            signing_request = (
                SigningRequest.objects.select_related("document", "requested_by", "signer")
                .get(pk=pk)
            )
        except SigningRequest.DoesNotExist:
            return Response(
                {"detail": "Signing request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = ClientSignCompleteSerializer(
            data=request.data,
            context={
                "request": request,
                "signing_request": signing_request,
            },
        )
        serializer.is_valid(raise_exception=True)
        result = serializer.save()

        return Response(
            {
                "message": result["message"],
                "signature_record": SignatureRecordSerializer(
                    result["signature_record"]
                ).data,
            },
            status=status.HTTP_200_OK,
        )