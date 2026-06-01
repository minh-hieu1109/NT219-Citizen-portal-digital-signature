# Demo Checklist

## Web Demo Setup
1. Run: `docker compose exec web python manage.py create_web_demo_data`
2. Open: `http://localhost:8000`
3. Login as admin and check `/ra/pending/` has 3 sections.
4. Login as citizen and create/upload flow works.
5. Login as officer and remote sign assigned request.
6. Verify result in `/verification/results/`.
7. Confirm `/audit/` has newest actions.
8. Confirm Logout redirects to `/accounts/login/`.

## Demo 1 - Remote signing valid
- Run: `docker compose exec web python experiments/01_end_to_end_remote_sign.py`
- Expect: `verification_status=valid`, LTV evidence exists.

## Demo 2 - Replay rejected
- Run: `docker compose exec web python experiments/05_replay_remote_signing_request.py`
- Expect: first sign success, second sign rejected (used/replay).

## Demo 3 - Tamper detected
- Run: `docker compose exec web python experiments/03_tamper_document_after_sign.py`
- Expect: verification invalid with hash/signature mismatch.

## Demo 4 - Revoked certificate scenario
- Run: `docker compose exec web python experiments/04_revoke_certificate_and_verify.py`
- Expect: revoked/invalid outcome or environment warning.

## Demo 5 - OCSP unavailable safe handling
- Run: `docker compose exec web python experiments/07_ocsp_unavailable.py`
- Expect: no crash, OCSP detail marks unavailable/error/disabled.

## Demo 6 - LTV evidence
- Included in remote-sign flow.
- Expect: `evidence_exists=True`, `ltv_valid=True`.

## Demo 7 - Benchmark generated
- Run: `docker compose exec web python experiments/08_benchmark_sign_verify.py`
- Expect:
  - `experiments/results/benchmark_sign_verify.csv`
  - `experiments/results/benchmark_sign_verify_summary.json`

## Demo 8 - PKCS#11 client signing
- Run: `docker compose exec web python experiments/02_end_to_end_client_pkcs11_sign.py`
- Expect:
  - warning + setup guidance if env missing, or
  - successful PKCS#11 sign when env is ready.

## Demo 9 - CMS/PKCS#7 detached signature
- Run: `docker compose exec web python experiments/09_cms_pkcs7_detached_signature.py`
- Expect:
  - `[OK] CMS detached signature created`
  - `[OK] CMS detached signature verified`
