# README_DEMO

## 1. Prerequisites
- Docker Desktop
- Git
- Browser
- Optional for advanced demos: SoftHSM/OpenSC/OpenSSL

## 2. Clone and Start
```bash
git clone <repo-url>
cd NT219-Citizen-portal-digital-signature
docker compose up -d --build
docker compose ps
```

## 3. Apply Migrations
```bash
docker compose exec web python manage.py migrate
```

## 4. Create Deterministic Demo Data
```bash
docker compose exec web python manage.py create_web_demo_data
```
Expected:
- `admin/officer/citizen` accounts created/updated.
- officer has an active certificate.
- citizen has demo document.
- one pending remote signing request exists.

## 5. Web URL and Credentials
- URL: `http://localhost:8000`
- `admin@example.com / Admin@123456`
- `officer@example.com / Officer@123456`
- `citizen@example.com / Citizen@123456`

## 6. Main Web Demo Script
1. Admin dashboard
- Login admin and open `/`.
- Expected: dashboard and counters visible.

2. RA panel
- Open `/ra/pending/`.
- Expected sections:
  - Pending identity verification
  - Verified users without certificate
  - Users with active certificate
- Officer should already have cert for signing.

3. Citizen registration demo (optional)
- Open `/accounts/register/`.
- Register a new citizen.
- Login admin/officer and verify identity in RA panel.
- Proves RA onboarding workflow.

4. Citizen upload document
- Login citizen and open `/documents/upload/`.
- Upload file.
- Expected: document stored with SHA-256 hash.

5. Citizen creates signing request
- Open `/signing/requests/create/`.
- Select document.
- Select signer `officer@example.com`.
- Select `signing_type=remote`.
- Expected: request pending and `expires_at` shown.
- Default TTL is `REMOTE_SIGNING_REQUEST_TTL_MINUTES=10`.

6. Officer remote signs
- Login officer.
- Open `/signing/requests/` and assigned request detail.
- Click Remote Sign.
- Expected: request `signed`, `used_at` set, `SignatureRecord` created.

7. Verify
- Click Verify or open `/verification/results/`.
- Expected:
  - status valid
  - hash match true
  - signature valid true
  - timestamp processed
  - LTV evidence present

8. Audit log
- Login admin/officer and open `/audit/`.
- Expected: recent upload/request/sign/verify/RA actions listed first.

9. Logout
- Click Logout in navbar.
- Expected: redirected to `/accounts/login/`.

## 7. Terminal Experiments
```bash
docker compose exec web python manage.py check
docker compose exec web python manage.py test
docker compose exec web python manage.py web_smoke_check

docker compose exec web python experiments/01_end_to_end_remote_sign.py
docker compose exec web python experiments/03_tamper_document_after_sign.py
docker compose exec web python experiments/05_replay_remote_signing_request.py
docker compose exec web python experiments/07_ocsp_unavailable.py
docker compose exec web python experiments/08_benchmark_sign_verify.py
docker compose exec web python experiments/09_cms_pkcs7_detached_signature.py
```

## 8. What Each Demo Proves
- Web flow: citizen portal + RA + remote signing lifecycle.
- Tamper test: integrity protection.
- Replay test: `nonce/expires_at/used_at` protection.
- OCSP unavailable: fail-safe revocation handling.
- Benchmark: performance/evaluation output.
- CMS: standards-oriented detached signature support.

## 9. Troubleshooting
- No eligible signer found:
  - Run `create_web_demo_data` or issue cert to officer in RA panel.
- Signer has no certificate:
  - Issue cert in RA panel or rerun `create_web_demo_data`.
- Logout 405:
  - Should be fixed; use navbar Logout button (POST).
- OCSP unavailable:
  - Non-fatal in lab; status stored as unavailable/error.
- PKCS#11 warning:
  - Set env vars: `TOOL_EMAIL`, `PKCS11_USER_PIN`, `PKCS11_TOKEN_LABEL`, `PKCS11_KEY_LABEL`, `PKCS11_LIB_PATH`.
- Docker permission/container conflict:
  - Restart Docker Desktop, rerun compose up/down as needed.
  - Do not delete volumes unless intentionally resetting demo data.

## 10. Final Presentation Checklist
- Containers are up.
- `create_web_demo_data` completed.
- `web_smoke_check` pass.
- Officer has active certificate.
- Citizen can create request for officer.
- Officer can remote sign.
- Verification is valid.
- Audit page shows new actions.
- Key experiments pass.
