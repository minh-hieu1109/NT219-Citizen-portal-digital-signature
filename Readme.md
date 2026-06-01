# Digital Signature for Public Administrative Services via Citizen Services Portal

## Project Overview
- Django Citizen Portal for public administrative service workflows.
- Citizens upload documents and create signing requests.
- Officer/Admin handles RA identity verification and remote signing.
- System verifies signature/hash/certificate/timestamp/OCSP/CRL/LTV.
- Audit logs provide traceability and support non-repudiation.

## Problem and Motivation
- Public-service digitization needs integrity, authenticity, and non-repudiation.
- Digital signatures reduce paper processing and improve legal assurance.

## Main Features
- Citizen Portal web UI
- Citizen registration
- RA identity verification
- Certificate issuing
- Document upload + SHA-256 hash
- Signing request workflow
- Remote signing
- Replay protection (`nonce`, `expires_at`, `used_at`)
- Signature verification
- RFC3161 timestamping
- OCSP/CRL checking with fail-safe handling
- LTV evidence archive
- Audit logs
- CMS/PKCS#7 detached signature demo
- PKCS#11/SoftHSM client-signing tool and setup scripts
- Experiment scripts and benchmark

## Roles
- Citizen: register, upload document, create signing request, view own result.
- Officer: process assigned requests, remote sign when active certificate exists.
- Admin/RA: identity verification, certificate issuing, audit/admin visibility.

## Final Web Workflow
1. Citizen registers.
2. Admin/Officer verifies identity in RA panel.
3. Citizen uploads document.
4. Citizen creates signing request for officer.
5. Officer remote signs.
6. System verifies signature.
7. LTV evidence and audit logs are stored.

## Architecture Overview
- Django + Django templates
- PostgreSQL
- Docker Compose
- PKI lab files
- OpenSSL helpers for CMS/TSA/OCSP
- SoftHSM/PKCS#11 support
- Main apps: `accounts`, `documents`, `signing`, `verification`, `audit`, `frontend`

## Security Features Mapping
| Requirement/Concern | Implemented Feature |
|---|---|
| Identity proofing | RA workflow (verify/reject/issue certificate) |
| Non-repudiation | Certificate-backed signature + audit log |
| Integrity | SHA-256 hashing + signature verification |
| Replay attack | `nonce` + `expires_at` + `used_at` |
| Revocation | OCSP/CRL status handling |
| Long-term validation | `ValidationEvidence` archive |
| Standard signature format | CMS/PKCS#7 detached signature demo |
| Client-side token signing | PKCS#11 tool with safe-warning mode |

## Experiments
- `01_end_to_end_remote_sign.py`: remote-sign E2E baseline.
- `02_end_to_end_client_pkcs11_sign.py`: client PKCS#11 signing (or warning if env missing).
- `03_tamper_document_after_sign.py`: tamper/integrity failure detection.
- `04_revoke_certificate_and_verify.py`: revoked-certificate scenario.
- `05_replay_remote_signing_request.py`: replay rejection.
- `06_tsa_unavailable.py`: timestamp service unavailable handling.
- `07_ocsp_unavailable.py`: OCSP unavailable fail-safe behavior.
- `08_benchmark_sign_verify.py`: benchmark + CSV/JSON outputs.
- `09_cms_pkcs7_detached_signature.py`: CMS detached create/verify.

## Quick Start
```bash
docker compose up -d --build
docker compose exec web python manage.py migrate
docker compose exec web python manage.py create_web_demo_data
```
Open: `http://localhost:8000`

## Demo Credentials
- `admin@example.com / Admin@123456`
- `officer@example.com / Officer@123456`
- `citizen@example.com / Citizen@123456`

## Tests
```bash
docker compose exec web python manage.py check
docker compose exec web python manage.py makemigrations --check --dry-run
docker compose exec web python manage.py test
docker compose exec web python manage.py web_smoke_check
```

## Limitations
- Lab/demo implementation, not production-ready.
- OCSP responder may be unavailable unless started separately; system records unavailable safely.
- CMS demo currently uses file-based key, not SoftHSM-backed CMS signing.
- Live PKCS#11 client signing depends on local SoftHSM/token/env setup.
- Legal/QES compliance is discussed at design level, not certified production compliance.

## Repository Structure
```text
accounts/      user, roles, RA, certificate profile, demo data commands
documents/     document model/upload/hash logic
signing/       signing request, remote/client signing, replay protection, CMS service
verification/  signature verification, OCSP/CRL/TSA/LTV services
audit/         audit log model/API/helpers
frontend/      web UI views/forms/tests/management commands
experiments/   end-to-end experiments and benchmark scripts
tools/         client-side helper tools (PKCS#11/file signing)
scripts/       setup/start helper scripts (SoftHSM, OCSP)
pki-lab/       lab CA, cert, key, CRL, TSA materials
task/          implementation progress tracking
```
