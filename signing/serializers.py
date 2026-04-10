from rest_framework import serializers

from documents.models import Document
from .models import SigningRequest, SignatureRecord
from .services import (
    remote_sign_signing_request,
    prepare_client_signing_request,
    complete_client_signing_request,
)
from audit.utils import log_action
from audit.models import AuditLog


class SigningRequestSerializer(serializers.ModelSerializer):
    requested_by_email = serializers.EmailField(source="requested_by.email", read_only=True)
    signer_email = serializers.EmailField(source="signer.email", read_only=True)
    document_title = serializers.CharField(source="document.title", read_only=True)

    class Meta:
        model = SigningRequest
        fields = [
            "id",
            "document",
            "document_title",
            "requested_by",
            "requested_by_email",
            "signer",
            "signer_email",
            "signing_type",
            "status",
            "created_at",
            "completed_at",
        ]
        read_only_fields = [
            "id",
            "requested_by",
            "requested_by_email",
            "signer_email",
            "document_title",
            "status",
            "created_at",
            "completed_at",
        ]

    def validate_document(self, value):
        request = self.context["request"]

        if value.owner != request.user:
            raise serializers.ValidationError(
                "You can only create a signing request for your own document."
            )

        if value.status != Document.Status.UPLOADED:
            raise serializers.ValidationError(
                "Only uploaded documents can be submitted for signing."
            )

        return value

    def validate(self, attrs):
        request = self.context["request"]
        if attrs.get("signer") is None:
            attrs["signer"] = request.user
        return attrs

    def create(self, validated_data):
        request = self.context["request"]
        document = validated_data["document"]

        signing_request = SigningRequest.objects.create(
            document=document,
            requested_by=request.user,
            signer=validated_data["signer"],
            signing_type=validated_data.get(
                "signing_type",
                SigningRequest.SigningType.REMOTE,
            ),
            status=SigningRequest.Status.PENDING,
        )

        document.status = Document.Status.PENDING_SIGN
        document.save(update_fields=["status", "updated_at"])

        log_action(
            user=request.user,
            action=AuditLog.Action.SIGNING_REQUEST_CREATED,
            object_type="SigningRequest",
            object_id=signing_request.id,
            detail={
                "document_id": signing_request.document.id,
                "document_title": signing_request.document.title,
                "signing_type": signing_request.signing_type,
                "status": signing_request.status,
                "requested_by_id": signing_request.requested_by.id,
                "requested_by_email": signing_request.requested_by.email,
                "signer_id": signing_request.signer.id if signing_request.signer else None,
                "signer_email": signing_request.signer.email if signing_request.signer else None,
            },
            request=request,
        )

        return signing_request


class SignatureRecordSerializer(serializers.ModelSerializer):
    document_title = serializers.CharField(source="signing_request.document.title", read_only=True)
    requested_by_email = serializers.EmailField(source="signing_request.requested_by.email", read_only=True)
    signer_email = serializers.EmailField(source="signing_request.signer.email", read_only=True)

    class Meta:
        model = SignatureRecord
        fields = [
            "id",
            "signing_request",
            "document_title",
            "requested_by_email",
            "signer_email",
            "signature_value",
            "certificate_pem",
            "certificate_subject",
            "certificate_serial",
            "algorithm",
            "signed_hash",
            "signed_at",
            "timestamp_token",
            "timestamp_status",
            "timestamp_message",
        ]
        read_only_fields = fields


class RemoteSignSerializer(serializers.Serializer):
    signing_request_id = serializers.IntegerField(read_only=True)
    message = serializers.CharField(read_only=True)
    signature_record = SignatureRecordSerializer(read_only=True)

    def validate(self, attrs):
        signing_request = self.context["signing_request"]
        request = self.context["request"]

        if signing_request.status != SigningRequest.Status.PENDING:
            raise serializers.ValidationError(
                {"detail": "Only pending signing requests can be signed."}
            )

        if hasattr(signing_request, "signature_record"):
            raise serializers.ValidationError(
                {"detail": "This signing request has already been signed."}
            )

        if not signing_request.signer:
            raise serializers.ValidationError(
                {"detail": "This signing request does not have a signer assigned."}
            )

        if signing_request.signer != request.user:
            raise serializers.ValidationError(
                {"detail": "Only the assigned signer can perform remote signing."}
            )

        if signing_request.signing_type != SigningRequest.SigningType.REMOTE:
            raise serializers.ValidationError(
                {"detail": "This signing request is not configured for remote signing."}
            )

        return attrs

    def save(self, **kwargs):
        signing_request = self.context["signing_request"]
        request = self.context["request"]

        try:
            signature_record = remote_sign_signing_request(signing_request)
        except ValueError as e:
            raise serializers.ValidationError({"detail": str(e)})
        except Exception as e:
            raise serializers.ValidationError(
                {"detail": f"Remote signing failed: {str(e)}"}
            )

        log_action(
            user=request.user,
            action=AuditLog.Action.REMOTE_SIGNED,
            object_type="SigningRequest",
            object_id=signing_request.id,
            detail={
                "document_id": signing_request.document.id,
                "document_title": signing_request.document.title,
                "signature_record_id": signature_record.id,
                "signed_hash": signature_record.signed_hash,
                "algorithm": signature_record.algorithm,
                "certificate_subject": signature_record.certificate_subject,
                "certificate_serial": signature_record.certificate_serial,
                "timestamp_status": signature_record.timestamp_status,
                "signer_id": signing_request.signer.id,
                "signer_email": signing_request.signer.email,
            },
            request=request,
        )

        return {
            "signing_request_id": signing_request.id,
            "message": "Remote signing completed successfully.",
            "signature_record": signature_record,
        }
    

class ClientSignPrepareSerializer(serializers.Serializer):
    signing_request_id = serializers.IntegerField(read_only=True)
    document_id = serializers.IntegerField(read_only=True)
    document_title = serializers.CharField(read_only=True)
    digest_hex = serializers.CharField(read_only=True)
    algorithm = serializers.CharField(read_only=True)
    certificate_serial = serializers.CharField(read_only=True)

    def validate(self, attrs):
        signing_request = self.context["signing_request"]
        request = self.context["request"]

        if signing_request.status != SigningRequest.Status.PENDING:
            raise serializers.ValidationError(
                {"detail": "Only pending signing requests can be prepared for client signing."}
            )

        if hasattr(signing_request, "signature_record"):
            raise serializers.ValidationError(
                {"detail": "This signing request has already been signed."}
            )

        if not signing_request.signer:
            raise serializers.ValidationError(
                {"detail": "This signing request does not have a signer assigned."}
            )

        if signing_request.signer != request.user:
            raise serializers.ValidationError(
                {"detail": "Only the assigned signer can prepare client signing."}
            )

        if signing_request.signing_type != SigningRequest.SigningType.CLIENT:
            raise serializers.ValidationError(
                {"detail": "This signing request is not configured for client signing."}
            )

        return attrs

    def save(self, **kwargs):
        signing_request = self.context["signing_request"]
        request = self.context["request"]

        try:
            result = prepare_client_signing_request(signing_request)
        except ValueError as e:
            raise serializers.ValidationError({"detail": str(e)})
        except Exception as e:
            raise serializers.ValidationError(
                {"detail": f"Prepare client signing failed: {str(e)}"}
            )

        log_action(
            user=request.user,
            action=AuditLog.Action.SIGNING_REQUEST_CREATED,
            object_type="SigningRequest",
            object_id=signing_request.id,
            detail={
                "step": "prepare_client_signing",
                "document_id": signing_request.document.id,
                "document_title": signing_request.document.title,
                "signing_type": signing_request.signing_type,
                "signer_id": signing_request.signer.id,
                "signer_email": signing_request.signer.email,
            },
            request=request,
        )

        return result


class ClientSignCompleteSerializer(serializers.Serializer):
    signature_value = serializers.CharField()
    algorithm = serializers.CharField(default="RSA-SHA256-PREHASHED")

    def validate(self, attrs):
        signing_request = self.context["signing_request"]
        request = self.context["request"]

        if signing_request.status != SigningRequest.Status.PENDING:
            raise serializers.ValidationError(
                {"detail": "Only pending signing requests can be completed for client signing."}
            )

        if hasattr(signing_request, "signature_record"):
            raise serializers.ValidationError(
                {"detail": "This signing request has already been signed."}
            )

        if not signing_request.signer:
            raise serializers.ValidationError(
                {"detail": "This signing request does not have a signer assigned."}
            )

        if signing_request.signer != request.user:
            raise serializers.ValidationError(
                {"detail": "Only the assigned signer can complete client signing."}
            )

        if signing_request.signing_type != SigningRequest.SigningType.CLIENT:
            raise serializers.ValidationError(
                {"detail": "This signing request is not configured for client signing."}
            )

        return attrs

    def save(self, **kwargs):
        signing_request = self.context["signing_request"]
        request = self.context["request"]

        try:
            signature_record = complete_client_signing_request(
                signing_request=signing_request,
                signature_b64=self.validated_data["signature_value"],
                algorithm=self.validated_data.get("algorithm", "RSA-SHA256-PREHASHED"),
            )
        except ValueError as e:
            raise serializers.ValidationError({"detail": str(e)})
        except Exception as e:
            raise serializers.ValidationError(
                {"detail": f"Client signing failed: {str(e)}"}
            )

        log_action(
            user=request.user,
            action=AuditLog.Action.REMOTE_SIGNED,
            object_type="SigningRequest",
            object_id=signing_request.id,
            detail={
                "step": "complete_client_signing",
                "document_id": signing_request.document.id,
                "document_title": signing_request.document.title,
                "signature_record_id": signature_record.id,
                "signed_hash": signature_record.signed_hash,
                "algorithm": signature_record.algorithm,
                "certificate_subject": signature_record.certificate_subject,
                "certificate_serial": signature_record.certificate_serial,
                "timestamp_status": signature_record.timestamp_status,
                "signer_id": signing_request.signer.id,
                "signer_email": signing_request.signer.email,
            },
            request=request,
        )

        return {
            "message": "Client signing completed successfully.",
            "signature_record": signature_record,
        }