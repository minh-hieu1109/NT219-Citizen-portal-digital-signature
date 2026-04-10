from rest_framework import serializers
from .models import Document
from .services import calculate_sha256
from audit.utils import log_action
from audit.models import AuditLog

class DocumentSerializer(serializers.ModelSerializer):
    owner_email = serializers.EmailField(source="owner.email", read_only=True)

    class Meta:
        model = Document
        fields = [
            "id",
            "owner",
            "owner_email",
            "title",
            "file",
            "sha256_hash",
            "status",
            "uploaded_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "owner",
            "owner_email",
            "sha256_hash",
            "status",
            "uploaded_at",
            "updated_at",
        ]

    def create(self, validated_data):
        request = self.context["request"]
        uploaded_file = validated_data["file"]

        file_hash = calculate_sha256(uploaded_file)
        uploaded_file.seek(0)

        document = Document.objects.create(
            owner=request.user,
            title=validated_data["title"],
            file=uploaded_file,
            sha256_hash=file_hash,
            status=Document.Status.UPLOADED,
        )
        log_action(
            user=request.user,
            action=AuditLog.Action.DOCUMENT_UPLOAD,
            object_type="Document",
            object_id=document.id,
            detail={
                "title": document.title,
                "filename": document.file.name if document.file else None,
                "sha256_hash": document.sha256_hash,
                "status": document.status,
            },
            request=request,
        )
        return document