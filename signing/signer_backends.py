from signing.mldsa_openssl import mldsa_sign_bytes


class FilePemMLDSASignerBackend:
    def sign(self, user_cert, data: bytes) -> bytes:
        if not user_cert.private_key_path:
            raise ValueError("private_key_path is empty for ML-DSA signer.")

        return mldsa_sign_bytes(
            private_key_path=user_cert.private_key_path,
            data=data,
        )


def get_signer_backend(user_cert):
    if user_cert.key_storage_type == "file":
        return FilePemMLDSASignerBackend()

    raise ValueError(
        f"Unsupported key storage type for ML-DSA stage: {user_cert.key_storage_type}"
    )