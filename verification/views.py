from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from signing.models import SignatureRecord
from .models import VerificationResult
from .serializers import VerificationResultSerializer, RunVerificationSerializer


class VerificationResultDetailView(generics.RetrieveAPIView):
    serializer_class = VerificationResultSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return VerificationResult.objects.filter(
            signature_record__signing_request__requested_by=self.request.user
        ).select_related(
            "signature_record",
            "signature_record__signing_request",
            "signature_record__signing_request__document",
        )


class RunVerificationView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            signature_record = SignatureRecord.objects.select_related(
                "signing_request",
                "signing_request__document",
                "signing_request__requested_by",
            ).get(
                pk=pk,
                signing_request__requested_by=request.user,
            )
        except SignatureRecord.DoesNotExist:
            return Response(
                {"detail": "Signature record not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = RunVerificationSerializer(
            data={},
            context={
                "request": request,
                "signature_record": signature_record,
            }
        )
        serializer.is_valid(raise_exception=True)
        result = serializer.save()

        output = VerificationResultSerializer(result["verification_result"])
        return Response(
            {
                "message": result["message"],
                "verification_result": output.data,
            },
            status=status.HTTP_200_OK,
        )