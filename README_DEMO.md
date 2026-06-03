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
- `citizen@example.com` is verified and has an active certificate.
- `citizen@example.com` has a demo document.
- One pending `client` signing request exists where requester, document owner, and signer are the citizen.
- `officer@example.com` is available for RA/reviewer or optional officer approval demos.

## 5. Web URL and Credentials
- URL: `http://localhost:8010`
- `admin@example.com / Admin@123456`
- `officer@example.com / Officer@123456`
- `citizen@example.com / Citizen@123456`

## 6. Main Web Demo Script: Citizen Signs Document
1. Admin dashboard
- Login admin and open `/`.
- Expected: dashboard and counters visible.

2. RA panel
- Open `/ra/pending/`.
- Verify citizen identity and issue certificate when demonstrating onboarding.
- Officer/Admin acts as RA/reviewer, not as the signer of the citizen document.

3. Citizen login
- Login `citizen@example.com`.
- Confirm the citizen has an active certificate in RA/admin views if needed.

4. Citizen upload and sign
- Open `Citizen Upload & Sign` from Dashboard or Documents.
- Upload a file and submit.
- Expected:
  - document is created
  - signing request is `client`
  - requester, document owner, and signer are `citizen@example.com`
  - signature is created with the citizen demo local client private key
  - verification runs against the citizen certificate

5. Verify
- On the document detail page, click `Verify`.
- Expected:
  - status valid
  - hash match true
  - signature valid true
  - signer certificate subject/serial belongs to the citizen

6. Download verification package
- Click `Download package` or open the signing request detail and download package.
- Expected package includes:
  - original document
  - raw signature
  - signer certificate for `citizen@example.com`
  - CA certificate
  - `metadata.json` with `signature_purpose=citizen_signature`

7. Public verifier
- Open `/verify/upload/`.
- Upload document + signature + certificate for RAW verification, or use the package files.

8. Tamper demo
- Modify the signed document and verify again.
- Expected: INVALID due to hash mismatch.

9. Audit log
- Login admin/officer and open `/audit/`.
- Expected: identity/certificate, upload, citizen client sign, verify, and package-related actions are visible.

## 7. Optional: Officer Administrative Approval Signing
The old remote-sign flow is retained only as an officer approval signature demo.
It proves that an officer signed an administrative decision/approval, not that
the citizen signed the citizen document.

Rules:
- If signer is `officer@example.com`, the signature belongs to the officer.
- UI labels this as `Officer Approval Sign`.
- Verification package metadata uses `signature_purpose=officer_approval_signature`.

## 8. Terminal Experiments
```bash
docker compose exec web python manage.py check
docker compose exec web python manage.py makemigrations --check --dry-run
docker compose exec web python manage.py test
docker compose exec web python manage.py web_smoke_check

docker compose exec web python experiments/01_end_to_end_citizen_client_sign.py
docker compose exec web python experiments/01_end_to_end_remote_sign.py
docker compose exec web python experiments/02_end_to_end_client_pkcs11_sign.py
docker compose exec web python experiments/03_tamper_document_after_sign.py
docker compose exec web python experiments/05_replay_remote_signing_request.py
docker compose exec web python experiments/09_cms_pkcs7_detached_signature.py
```

Use `01_end_to_end_citizen_client_sign.py` as the main citizen signing proof.
Treat `01_end_to_end_remote_sign.py` as a remote/officer-approval style lab
experiment, not as the main citizen client-signature proof.

## 9. Client File Signing Helper
The web-only flow is the main presentation path. This helper remains useful for
showing prepare/sign/complete from a local file-key client.

```bash
docker compose exec web python manage.py create_client_file_sign_demo_data
```

Copy the printed request id, then run the command printed by the helper. The
helper creates `client@example.com` and a file-based client certificate owned by
that user.

## 10. What Each Demo Proves
- Citizen client signing: citizen owns the certificate and signs the document.
- Officer approval signing: officer signs an approval, not the citizen document.
- Tamper test: integrity protection.
- Replay test: `nonce/expires_at/used_at` protection.
- OCSP/CRL: certificate status handling in lab mode.
- CMS/PAdES/LTV: standards-oriented packaging and validation support.

## 11. Troubleshooting
- Citizen cannot create signing request:
  - Verify identity and issue certificate in RA panel, or rerun `create_web_demo_data`.
- No eligible citizen certificate:
  - Use `Citizen Upload & Sign`; it creates/reuses a demo local client key bound to the logged-in citizen.
- Officer signature appears as signer:
  - That is an officer approval signature, not a citizen signature.
- OCSP unavailable:
  - Non-fatal in lab; status stored as unavailable/error.
- PKCS#11 warning:
  - Set env vars: `TOOL_EMAIL`, `PKCS11_USER_PIN`, `PKCS11_TOKEN_LABEL`, `PKCS11_KEY_LABEL`, `PKCS11_LIB_PATH`.
- Docker permission/container conflict:
  - Restart Docker Desktop, rerun compose up/down as needed.
  - Do not delete volumes unless intentionally resetting demo data.

## 12. Final Presentation Checklist
- Containers are up.
- `create_web_demo_data` completed.
- `web_smoke_check` pass.
- Citizen has active certificate.
- Citizen can use `Citizen Upload & Sign`.
- SignatureRecord signer is the citizen via `signing_request.signer`.
- Verification is valid using citizen certificate.
- Verification package contains citizen signer certificate and metadata.
- Officer/Admin is RA/reviewer or optional approval signer only.
- Audit page shows citizen sign and verification actions.
