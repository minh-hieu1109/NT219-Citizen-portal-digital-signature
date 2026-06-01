# Demo Checklist

## Demo 1 - Remote signing valid
- Run: `docker compose exec web python experiments/01_end_to_end_remote_sign.py`
- Expect: `verification_status=valid`

## Demo 2 - Replay rejected
- Run: `docker compose exec web python experiments/05_replay_remote_signing_request.py`
- Expect: first sign success, second attempt rejected with replay/used message.

## Demo 3 - Tamper detected
- Run: `docker compose exec web python experiments/03_tamper_document_after_sign.py`
- Expect: verification invalid with hash/signature mismatch detail.

## Demo 4 - Revoked certificate detected
- Run: `docker compose exec web python experiments/04_revoke_certificate_and_verify.py`
- Expect: cert status revoked and verification invalid.
- Note: if local PKI/CRL setup is incomplete, treat as environment warning and review script output.

## Demo 5 - OCSP unavailable safe handling
- Run: `docker compose exec web python experiments/07_ocsp_unavailable.py`
- Expect: no crash; detail contains `ocsp_status` unavailable/error/disabled depending on flow.

## Demo 6 - LTV evidence exists
- Included in remote signing flow.
- Expect from demo output: `evidence_exists=True` and `ltv_valid=True`.

## Demo 7 - Benchmark output generated
- Run: `docker compose exec web python experiments/08_benchmark_sign_verify.py`
- Expect files:
  - `experiments/results/benchmark_sign_verify.csv`
  - `experiments/results/benchmark_sign_verify_summary.json`

## Demo 8 - PKCS#11 client signing (warning/live)
- Run: `docker compose exec web python experiments/02_end_to_end_client_pkcs11_sign.py`
- If env not ready: expect `[WARNING]` and setup guidance (safe behavior).
- If env ready: expect digest prepared, PKCS#11 signature created, server accepted signature.

## Demo 9 - CMS/PKCS#7 detached signature
- Run: `docker compose exec web python experiments/09_cms_pkcs7_detached_signature.py`
- Expect (when cert/key available):
  - `[OK] CMS detached signature created`
  - `[OK] CMS detached signature verified`
- If cert/key/OpenSSL not available: expect `[WARNING]` and setup guidance; script should not crash.
