# Experiments (Phase 6)

This folder contains lab/demo scripts for end-to-end digital-signature scenarios.

## Prerequisites

- Docker services are up: `docker compose up -d --build`
- Run all scripts from project root.
- Recommended execution (inside web container):
  - `docker compose exec web python experiments/<script>.py`

## Scripts

1. `01_end_to_end_remote_sign.py`
- Create/find demo citizen and certificate.
- Create document and remote signing request.
- Remote-sign, verify signature, verify LTV evidence.
- Print structured summary.

2. `02_end_to_end_client_pkcs11_sign.py`
- Placeholder for SoftHSM/PKCS#11 flow.
- Intentionally not implemented in this phase.

3. `03_tamper_document_after_sign.py`
- Sign document successfully.
- Modify document content after signing.
- Re-verify and show expected invalid hash/signature status.

4. `04_revoke_certificate_and_verify.py`
- Sign document successfully.
- Revoke signer certificate using local revocation service.
- Re-verify and show revoked/invalid behavior.

5. `05_replay_remote_signing_request.py`
- Sign once successfully.
- Attempt signing same request again and expect replay rejection.

6. `06_tsa_unavailable.py`
- Temporarily set invalid TSA config for this process.
- Sign document and show that signing still succeeds while timestamp is missing/error.

7. `07_ocsp_unavailable.py`
- Temporarily set unreachable OCSP responder URL.
- Verify signature and show OCSP status `unavailable`/`error` without app crash.

8. `08_benchmark_sign_verify.py`
- Run `N` iterations (default 20) of remote sign + verify + LTV verify.
- Write CSV and JSON summary to `experiments/results/`.

## Output folder

- Benchmark files are written to:
  - `experiments/results/benchmark_sign_verify.csv`
  - `experiments/results/benchmark_sign_verify_summary.json`

## Notes

- These scripts are lab/demo utilities, not production orchestration.
- Script 02 is intentionally skipped until Phase 3 (PKCS#11).
