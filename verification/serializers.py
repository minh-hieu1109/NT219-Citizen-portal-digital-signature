from rest_framework import serializers

from .models import VerificationResult
from .services import verify_signature_record
from audit.utils import log_action
from audit.models import AuditLog


class VerificationResultSerializer(serializers.ModelSerializer):
    document_title = serializers.CharField(
        source="signature_record.signing_request.document.title",
        read_only=True
    )

    class Meta:
        model = VerificationResult
        fields = [
            "id",
            "signature_record",
            "document_title",
            "status",
            "is_signature_valid",
            "is_hash_match",
            "signer_subject",
            "signer_serial",
            "detail",
            "verified_at",
        ]
        read_only_fields = fields


class RunVerificationSerializer(serializers.Serializer):
    message = serializers.CharField(read_only=True)

    def save(self, **kwargs):
        signature_record = self.context["signature_record"]
        request = self.context["request"]

        if hasattr(signature_record, "verification_result"):
            raise serializers.ValidationError(
                "This signature has already been verified."
            )

        try:
            verification_result = verify_signature_record(signature_record)
        except Exception as e:
            raise serializers.ValidationError(str(e))

        log_action(
            user=request.user,
            action=AuditLog.Action.VERIFICATION_RUN,
            object_type="VerificationResult",
            object_id=verification_result.id,
            detail={
                "signature_record_id": signature_record.id,
                "document_id": signature_record.signing_request.document.id,
                "status": verification_result.status,
                "is_signature_valid": verification_result.is_signature_valid,
                "is_hash_match": verification_result.is_hash_match,
                "signer_subject": verification_result.signer_subject,
                "signer_serial": verification_result.signer_serial,
                "detail": verification_result.detail,
            },
            request=request,
        )

        return {
            "message": "Verification completed successfully.",
            "verification_result": verification_result,
        }