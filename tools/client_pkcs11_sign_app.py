import argparse
import base64
import json
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def _load_pkcs11_module():
    try:
        import pkcs11  # type: ignore

        return pkcs11
    except Exception as exc:
        return None, exc


def _load_django():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()


def _is_pkcs11_available(lib_path: str):
    mod = _load_pkcs11_module()
    if isinstance(mod, tuple):
        return False, f"python-pkcs11 unavailable: {mod[1]}"

    try:
        mod.lib(lib_path)
    except Exception as exc:
        return False, f"Cannot load PKCS#11 library at '{lib_path}': {exc}"

    return True, "ok"


def _sign_digest_with_pkcs11(digest_hex: str, lib_path: str, token_label: str, pin: str, key_label: str | None, key_id: str | None):
    pkcs11 = _load_pkcs11_module()
    if isinstance(pkcs11, tuple):
        raise RuntimeError(f"python-pkcs11 unavailable: {pkcs11[1]}")

    KeyType = pkcs11.KeyType
    ObjectClass = pkcs11.ObjectClass
    Mechanism = pkcs11.Mechanism
    Attribute = pkcs11.Attribute

    digest_bytes = bytes.fromhex(digest_hex)
    digest_info_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    digest_info = digest_info_prefix + digest_bytes

    p11 = pkcs11.lib(lib_path)
    token = p11.get_token(token_label=token_label)

    with token.open(user_pin=pin) as session:
        query = {
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: KeyType.RSA,
        }
        if key_label:
            query[Attribute.LABEL] = key_label
        if key_id:
            query[Attribute.ID] = bytes.fromhex(key_id) if all(c in "0123456789abcdefABCDEF" for c in key_id) and len(key_id) % 2 == 0 else key_id.encode("utf-8")

        private_keys = list(session.get_objects(query))
        if not private_keys:
            raise RuntimeError("No RSA private key found in token for given label/id.")

        signature = private_keys[0].sign(digest_info, mechanism=Mechanism.RSA_PKCS)
        return base64.b64encode(signature).decode("utf-8")


def _prepare_via_api(base_url: str, signing_request_id: int, email: str, password: str):
    import requests

    url = f"{base_url.rstrip('/')}/api/signing/requests/{signing_request_id}/prepare-client-sign/"
    resp = requests.post(url, auth=(email, password), timeout=60)
    if not resp.ok:
        raise RuntimeError(f"Prepare failed: {resp.status_code} {resp.text}")
    return resp.json()


def _complete_via_api(base_url: str, signing_request_id: int, signature_b64: str, email: str, password: str):
    import requests

    url = f"{base_url.rstrip('/')}/api/signing/requests/{signing_request_id}/complete-client-sign/"
    payload = {
        "signature_value": signature_b64,
        "algorithm": "RSA-SHA256-PREHASHED",
    }
    resp = requests.post(url, json=payload, auth=(email, password), timeout=60)
    if not resp.ok:
        raise RuntimeError(f"Complete failed: {resp.status_code} {resp.text}")
    return resp.json()


def _prepare_via_orm(signing_request_id: int):
    _load_django()
    from signing.models import SigningRequest
    from signing.services import prepare_client_signing_request

    signing_request = SigningRequest.objects.select_related("signer", "document").get(id=signing_request_id)
    return prepare_client_signing_request(signing_request)


def _complete_via_orm(signing_request_id: int, signature_b64: str):
    _load_django()
    from signing.models import SigningRequest
    from signing.services import complete_client_signing_request
    from verification.services import verify_signature_record

    signing_request = SigningRequest.objects.select_related("signer", "document").get(id=signing_request_id)
    signature_record = complete_client_signing_request(
        signing_request=signing_request,
        signature_b64=signature_b64,
        algorithm="RSA-SHA256-PREHASHED",
    )
    verification = verify_signature_record(signature_record)
    return {
        "message": "Client signing completed successfully.",
        "signature_record_id": signature_record.id,
        "verification_status": verification.status,
    }


def _print_setup_guidance():
    print("[WARNING] SoftHSM/PKCS#11 environment not ready.")
    print("Setup guidance:")
    print("- Linux: run scripts/setup_client_softhsm_token.sh")
    print("- Windows: run scripts/setup_client_softhsm_token.ps1")
    print("- Typical PKCS#11 lib path (Linux): /usr/lib/softhsm/libsofthsm2.so")
    print("- Typical PKCS#11 lib path (Windows): C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll")


def main():
    parser = argparse.ArgumentParser(description="Client-side PKCS#11 signing app")
    parser.add_argument("signing_request_id", type=int)
    parser.add_argument("--base-url", default=os.getenv("PORTAL_BASE_URL", "http://web:8000"))
    parser.add_argument("--use-orm", action="store_true", help="Use local Django ORM flow instead of HTTP API")
    parser.add_argument("--email", default=os.getenv("TOOL_EMAIL", ""))
    parser.add_argument("--password", default=os.getenv("TOOL_PASSWORD", ""))
    parser.add_argument("--pkcs11-lib", default=os.getenv("PKCS11_LIB_PATH", "/usr/lib/softhsm/libsofthsm2.so"))
    parser.add_argument("--token-label", default=os.getenv("PKCS11_TOKEN_LABEL", "citizen-client-token"))
    parser.add_argument("--key-label", default=os.getenv("PKCS11_KEY_LABEL", "CitizenClientKey"))
    parser.add_argument("--key-id", default=os.getenv("PKCS11_KEY_ID", ""))
    parser.add_argument("--pin", default=os.getenv("PKCS11_USER_PIN", ""))
    parser.add_argument("--allow-warning-exit", action="store_true", help="Return exit code 0 when PKCS#11 unavailable")
    args = parser.parse_args()

    ok, message = _is_pkcs11_available(args.pkcs11_lib)
    if not ok:
        print(f"[WARNING] {message}")
        _print_setup_guidance()
        return 0 if args.allow_warning_exit else 2

    if not args.pin:
        print("[WARNING] PKCS11 PIN is missing.")
        _print_setup_guidance()
        return 0 if args.allow_warning_exit else 2

    try:
        if args.use_orm:
            prepare_data = _prepare_via_orm(args.signing_request_id)
        else:
            if not args.email or not args.password:
                raise RuntimeError("email/password required for API mode")
            prepare_data = _prepare_via_api(args.base_url, args.signing_request_id, args.email, args.password)

        digest_hex = prepare_data["digest_hex"]
        print("[OK] Digest prepared")

        signature_b64 = _sign_digest_with_pkcs11(
            digest_hex=digest_hex,
            lib_path=args.pkcs11_lib,
            token_label=args.token_label,
            pin=args.pin,
            key_label=args.key_label or None,
            key_id=args.key_id or None,
        )
        print("[OK] Signature created by PKCS#11 token")

        if args.use_orm:
            complete_data = _complete_via_orm(args.signing_request_id, signature_b64)
            verification_status = complete_data.get("verification_status", "unknown")
        else:
            complete_data = _complete_via_api(
                args.base_url,
                args.signing_request_id,
                signature_b64,
                args.email,
                args.password,
            )
            print("[OK] Server accepted signature")
            signature_record = complete_data.get("signature_record", {})
            verification_status = "unknown"
            if signature_record.get("id"):
                try:
                    _load_django()
                    from signing.models import SignatureRecord
                    from verification.services import verify_signature_record

                    sr = SignatureRecord.objects.get(id=signature_record["id"])
                    vr = verify_signature_record(sr)
                    verification_status = vr.status
                except Exception:
                    verification_status = "unknown"

        if args.use_orm:
            print("[OK] Server accepted signature")

        print(f"[OK] Verification result: {verification_status}")
        print(json.dumps({"prepare": prepare_data, "complete": complete_data}, indent=2, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"[FATAL] {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
