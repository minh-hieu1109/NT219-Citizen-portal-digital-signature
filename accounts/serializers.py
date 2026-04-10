from rest_framework import serializers


class EnrollFileClientCertificateSerializer(serializers.Serializer):
    csr_pem = serializers.CharField()
    key_storage_type = serializers.CharField(default="file")

    def validate_csr_pem(self, value):
        if "BEGIN CERTIFICATE REQUEST" not in value:
            raise serializers.ValidationError("Invalid CSR PEM format.")
        return value

    def validate_key_storage_type(self, value):
        if value != "file":
            raise serializers.ValidationError("Only file key storage type is supported in this endpoint.")
        return value