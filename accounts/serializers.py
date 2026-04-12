from rest_framework import serializers
from .models import UserCertificate

class EnrollFileClientCertificateSerializer(serializers.Serializer):
    csr_pem = serializers.CharField()
    key_storage_type = serializers.ChoiceField(
        choices=UserCertificate.KeyStorageType.choices,
        default=UserCertificate.KeyStorageType.FILE,
    )
    private_key_path = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    pkcs11_token_label = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    pkcs11_key_label = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    pkcs11_key_id = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    pkcs11_slot = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    def validate(self, attrs):
        key_storage_type = attrs.get("key_storage_type")

        if key_storage_type == UserCertificate.KeyStorageType.FILE:
            return attrs

        if key_storage_type == UserCertificate.KeyStorageType.SOFTHSM:
            if not attrs.get("pkcs11_token_label"):
                raise serializers.ValidationError("pkcs11_token_label is required for SoftHSM PKCS#11.")
            if not attrs.get("pkcs11_key_label"):
                raise serializers.ValidationError("pkcs11_key_label is required for SoftHSM PKCS#11.")
            return attrs

        return attrs