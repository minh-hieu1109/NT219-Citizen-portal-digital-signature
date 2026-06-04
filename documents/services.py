import hashlib
import os


def calculate_sha256(file_obj):
    if isinstance(file_obj, (str, bytes, os.PathLike)):
        return calculate_sha256_path(file_obj)

    sha256 = hashlib.sha256()

    try:
        file_obj.seek(0)
    except Exception:
        pass

    if hasattr(file_obj, "chunks"):
        for chunk in file_obj.chunks():
            sha256.update(chunk)
    else:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            sha256.update(chunk)

    try:
        file_obj.seek(0)
    except Exception:
        pass

    return sha256.hexdigest()


def calculate_uploaded_file_sha256(uploaded_file):

    return calculate_sha256(uploaded_file)


def calculate_sha256_path(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def short_fingerprint(hash_hex, length=12):
    value = (hash_hex or "").upper()[:length]
    return "-".join(value[i:i + 4] for i in range(0, len(value), 4))