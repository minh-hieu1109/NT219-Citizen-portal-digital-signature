# README_DEMO

## 1) Run with Docker

```bash
docker compose up -d --build
docker compose ps
docker compose logs web --tail=100
```

## 2) Apply migrations

```bash
docker compose exec web python manage.py migrate
```

## 3) Create superuser (optional)

```bash
docker compose exec web python manage.py createsuperuser
```

## 4) Run checks and tests

```bash
docker compose exec web python manage.py check
docker compose exec web python manage.py makemigrations --check --dry-run
docker compose exec web python manage.py test
```

## 5) Run experiments

```bash
docker compose exec web python experiments/01_end_to_end_remote_sign.py
docker compose exec web python experiments/02_end_to_end_client_pkcs11_sign.py
docker compose exec web python experiments/03_tamper_document_after_sign.py
docker compose exec web python experiments/04_revoke_certificate_and_verify.py
docker compose exec web python experiments/05_replay_remote_signing_request.py
docker compose exec web python experiments/06_tsa_unavailable.py
docker compose exec web python experiments/07_ocsp_unavailable.py
docker compose exec web python experiments/08_benchmark_sign_verify.py
docker compose exec web python experiments/09_cms_pkcs7_detached_signature.py
```

## 6) Expected warning/fail-safe cases

- `experiments/02_end_to_end_client_pkcs11_sign.py` can print `[WARNING]` and exit safely when PKCS#11/SoftHSM environment is not ready.
- `experiments/06_tsa_unavailable.py` intentionally simulates TSA failure; signing should still complete with timestamp status error/missing.
- `experiments/07_ocsp_unavailable.py` intentionally simulates OCSP endpoint outage; app should not crash.
- `experiments/04_revoke_certificate_and_verify.py` can depend on PKI/CRL state in environment; invalid/revoked verification is expected behavior in this scenario.
- `experiments/09_cms_pkcs7_detached_signature.py` can print `[WARNING]` when suitable cert/key/OpenSSL is missing in environment.

## 7) PKCS#11 client-signing demo setup

Run setup scripts first:

- Linux/macOS shell:
```bash
bash scripts/setup_client_softhsm_token.sh
```

- Windows PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/setup_client_softhsm_token.ps1
```

Then set environment variables (example):

```bash
export TOOL_EMAIL="your_user_email@example.com"
export TOOL_PASSWORD="your_password"
export PKCS11_USER_PIN="123456"
export PKCS11_TOKEN_LABEL="citizen-client-token"
export PKCS11_KEY_LABEL="CitizenClientKey"
export PKCS11_LIB_PATH="/usr/lib/softhsm/libsofthsm2.so"
```

Run client PKCS#11 experiment:

```bash
docker compose exec web python experiments/02_end_to_end_client_pkcs11_sign.py
```

## 8) CMS/PKCS#7 detached signature demo

Run CMS experiment:

```bash
docker compose exec web python experiments/09_cms_pkcs7_detached_signature.py
```

Optional direct commands:

```bash
docker compose exec web python manage.py create_cms_signature --input /app/experiments/results/cms/cms_demo_input.txt --cert /app/pki-lab/certs/users/user_4.crt --key /app/pki-lab/users/private/user_4_key.pem --out /app/experiments/results/cms/cms_demo_signature.p7s --ca /app/pki-lab/certs/rootCA.crt

docker compose exec web python manage.py verify_cms_signature --input /app/experiments/results/cms/cms_demo_input.txt --signature /app/experiments/results/cms/cms_demo_signature.p7s --ca /app/pki-lab/certs/rootCA.crt
```

Limitation:
- CMS signing in Phase 7 is implemented with file-based private key via OpenSSL CLI.
- SoftHSM-backed CMS signing is not integrated yet in this phase.

## 9) Required PKCS#11 environment variables

- `TOOL_EMAIL`
- `PKCS11_USER_PIN`
- `PKCS11_TOKEN_LABEL`
- `PKCS11_KEY_LABEL`
- `PKCS11_LIB_PATH`

Optional but usually needed in API mode:
- `TOOL_PASSWORD`
- `PORTAL_BASE_URL`
