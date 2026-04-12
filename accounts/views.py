from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status

from .serializers import EnrollFileClientCertificateSerializer
from .services import issue_certificate_from_csr_for_user

class EnrollFileClientCertificateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
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