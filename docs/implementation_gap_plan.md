# Implementation Gap Plan

## 1. Existing Features

- Django monolith with apps: `accounts`, `documents`, `signing`, `verification`, `audit`, `frontend`.
- User management with custom `User` model (`role`, `citizen_id`, `is_verified_identity`).
- Certificate profile per user via `UserCertificate`.
- Document upload, SHA-256 hashing, status tracking.
- Signing request flow with two modes:
  - `remote` signing (server-side key use).
  - `client` signing (prepare digest + complete signature).
- Signer backends:
  - File PEM private key.
  - SoftHSM PKCS#11 key.
- Timestamp integration using OpenSSL RFC3161 commands.
- Signature verification flow:
  - Integrity/hash check.
  - Cryptographic signature validation.
  - CA issuer check.
  - Certificate validity period check.
  - Local DB certificate status check.
  - CRL check.
  - Timestamp token verification.
- Audit logging for core events (upload, request create, sign, verify).
- Demo frontend pages for login, documents, signing requests.
- Dockerized stack (`web`, `db`, `client-signer`) with SoftHSM token volumes.

## 2. Gaps vs Required Scope

### 2.1 Missing or Partial

- RA workflow is only partial:
  - `is_verified_identity` field exists, but no complete officer/admin approval API workflow yet.
  - Certificate issuance is still triggered by user-create signal for non-admin users.
- Replay protection for remote signing is incomplete:
  - Depends mostly on status/one-to-one signature existence, no explicit nonce + expiry + used timestamp model.
- OCSP checking is missing:
  - Verification currently uses CRL only.
- LTV archive evidence model/process is missing:
  - No dedicated archival evidence entity (cert chain/OCSP/CRL/timestamp bundle hash).
- Experiment automation scripts are incomplete for full assignment coverage.
- Benchmark scripts/results are not yet implemented.
- Automated tests are mostly placeholders in app-level `tests.py`.

### 2.2 Optional/Deferred by assignment guidance

- Full OIDC/WebAuthn/Keycloak integration.
- Full PAdES/XAdES/CAdES production-grade implementation.
- Mobile signing real SDK flow.
- Threshold signing and production HSM integration.

## 3. Planned Implementation Phases

1. Phase 0: Baseline survey and environment checks.
2. Phase 1: RA workflow APIs and policy enforcement.
3. Phase 2: Replay protection model + enforcement for remote signing.
4. Phase 3: SoftHSM/PKCS#11 client-side demo script hardening.
5. Phase 4: OCSP simulation and verification integration.
6. Phase 5: LTV archive evidence model and verification mode.
7. Phase 6: Experiments and benchmark scripts + result outputs.
8. Phase 7 (optional): CMS/PKCS#7 detached signature support.
9. Phase 8: Hardening, cleanup, demo docs.

## 4. Current Run Commands

### 4.1 Local Python

```bash
python manage.py check
python manage.py makemigrations --check --dry-run
```

### 4.2 Docker

```bash
docker compose config
docker compose up -d --build
docker compose logs web --tail=100
```

## 5. Current Test/Check Commands

```bash
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test
```

## 6. Environment Risks and Known Issues

- Local Python environment currently missing Django dependency (`ModuleNotFoundError: No module named 'django'`).
- Docker daemon currently unavailable on this machine (`dockerDesktopLinuxEngine` pipe not found), so `docker compose up/logs` cannot run.
- PowerShell profile/terminal theme plugins emit permission warnings; noisy but not the primary blocker.

## 7. Baseline Status Summary

- Source baseline successfully reviewed.
- Docker compose file is syntactically valid (`docker compose config` works).
- Runtime verification is currently blocked by environment setup (Python dependencies + Docker daemon state).
