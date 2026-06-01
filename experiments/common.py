import os
import subprocess
import sys
import uuid
from pathlib import Path
from time import perf_counter


BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django  # noqa: E402

django.setup()

from django.core.files.base import ContentFile  # noqa: E402
from django.utils import timezone  # noqa: E402

from accounts.models import User, UserCertificate  # noqa: E402
from accounts.services import issue_certificate_from_csr_for_user  # noqa: E402
from documents.models import Document  # noqa: E402
from django.conf import settings  # noqa: E402
from signing.models import SigningRequest  # noqa: E402
from signing.services import remote_sign_signing_request  # noqa: E402
from verification.ltv_services import verify_ltv  # noqa: E402
from verification.services import verify_signature_record  # noqa: E402


KEYS_DIR = BASE_DIR / "experiments" / "results" / "keys"


def log(level: str, msg: str):
    print(f"[{level}] {msg}")


def ensure_demo_citizen(email: str = "demo_exp_citizen@example.com") -> User:
    user, _ = User.objects.get_or_create(
        email=email,
        defaults={
            "username": email,
            "full_name": "Demo Experiment Citizen",
            "citizen_id": f"exp-{uuid.uuid4().hex[:12]}",
            "role": User.Role.CITIZEN,
            "is_verified_identity": True,
        },
    )
    if not user.is_verified_identity:
        user.is_verified_identity = True
        user.save(update_fields=["is_verified_identity"])
    if not user.has_usable_password():
        user.set_password("exp12345")
        user.save(update_fields=["password"])
    return user


def ensure_demo_certificate(user: User) -> UserCertificate:
    existing = UserCertificate.objects.filter(user=user).first()
    if existing and existing.private_key_path and Path(existing.private_key_path).exists():
        return existing

    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    key_path = KEYS_DIR / f"user_{user.id}_key.pem"
    csr_path = KEYS_DIR / f"user_{user.id}.csr"

    if not key_path.exists():
        subprocess.run(
            [str(settings.PKI_OPENSSL_BIN), "genrsa", "-out", str(key_path), "2048"],
            check=True,
            capture_output=True,
            text=True,
        )

    subj = f"/C=VN/ST=HCM/L=HCM/O=Citizen Portal/OU=Citizen/CN={user.full_name}/emailAddress={user.email}"
    subprocess.run(
        [
            str(settings.PKI_OPENSSL_BIN),
            "req",
            "-new",
            "-key",
            str(key_path),
            "-out",
            str(csr_path),
            "-subj",
            subj,
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    csr_pem = csr_path.read_text(encoding="utf-8")
    issue_certificate_from_csr_for_user(
        user=user,
        csr_pem=csr_pem,
        key_storage_type=UserCertificate.KeyStorageType.FILE,
        private_key_path=str(key_path),
    )

    return UserCertificate.objects.get(user=user)


def create_demo_document(user: User, title_prefix: str = "exp_doc", content: bytes = b"demo content") -> Document:
    doc = Document.objects.create(
        owner=user,
        title=f"{title_prefix}_{int(timezone.now().timestamp())}",
        status=Document.Status.UPLOADED,
        sha256_hash="",
    )
    doc.file.save(f"{doc.title}.txt", ContentFile(content), save=True)
    return doc


def create_remote_request(user: User, doc: Document) -> SigningRequest:
    doc.status = Document.Status.UPLOADED
    doc.save(update_fields=["status", "updated_at"])
    return SigningRequest.objects.create(
        document=doc,
        requested_by=user,
        signer=user,
        signing_type=SigningRequest.SigningType.REMOTE,
        status=SigningRequest.Status.PENDING,
    )


def run_remote_sign_and_verify(user: User, content: bytes = b"demo content"):
    ensure_demo_certificate(user)
    doc = create_demo_document(user, content=content)
    req = create_remote_request(user, doc)

    t0 = perf_counter()
    sig = remote_sign_signing_request(req)
    t1 = perf_counter()
    ver = verify_signature_record(sig)
    t2 = perf_counter()
    ltv = verify_ltv(sig)
    t3 = perf_counter()

    return {
        "document": doc,
        "signing_request": req,
        "signature_record": sig,
        "verification_result": ver,
        "ltv_result": ltv,
        "timings_ms": {
            "remote_sign": (t1 - t0) * 1000,
            "verify": (t2 - t1) * 1000,
            "ltv_verify": (t3 - t2) * 1000,
        },
    }
