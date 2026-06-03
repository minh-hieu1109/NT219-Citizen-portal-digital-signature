# Demo Checklist

## Web Demo Setup
1. Run: `docker compose exec web python manage.py create_web_demo_data`
2. Open: `http://localhost:8010`
3. Login as admin and check `/ra/pending/` has RA sections.
4. Confirm `citizen@example.com` is verified and has an active certificate.
5. Login as citizen and open `Citizen Upload & Sign`.
6. Upload a document and confirm redirect to document detail.
7. Confirm related signature shows:
   - signer: `citizen@example.com`
   - purpose: `citizen_signature`
   - type: `Client`
8. Click `Verify` and expect valid status.
9. Download verification package and confirm `metadata.json` names the citizen certificate.
10. Confirm `/audit/` has upload, citizen client sign, and verification actions.
11. Confirm Logout redirects to `/accounts/login/`.

## Demo 1 - Citizen client signing valid
- Web: `Citizen Upload & Sign`
- Terminal: `docker compose exec web python experiments/01_end_to_end_citizen_client_sign.py`
- Expect: `verification_status=valid`, signer is citizen, signer certificate is citizen certificate.

## Demo 2 - Replay rejected
- Run: `docker compose exec web python experiments/05_replay_remote_signing_request.py`
- Expect: first sign success, second sign rejected (used/replay).

## Demo 3 - Tamper detected
- Run: `docker compose exec web python experiments/03_tamper_document_after_sign.py`
- Expect: verification invalid with hash/signature mismatch.

## Demo 4 - Optional officer approval signing
- Run: `docker compose exec web python experiments/01_end_to_end_remote_sign.py`
- Expect: valid officer approval signature when environment is ready.
- Note: this proves officer approval, not citizen document signing.

## Demo 5 - Revoked certificate scenario
- Run: `docker compose exec web python experiments/04_revoke_certificate_and_verify.py`
- Expect: revoked/invalid outcome or environment warning.

## Demo 6 - OCSP unavailable safe handling
- Run: `docker compose exec web python experiments/07_ocsp_unavailable.py`
- Expect: no crash, OCSP detail marks unavailable/error/disabled.

## Demo 7 - LTV evidence
- Included in signing flows.
- Expect: `evidence_exists=True`, `ltv_valid=True` when environment supports it.

## Demo 8 - Benchmark generated
- Run: `docker compose exec web python experiments/08_benchmark_sign_verify.py`
- Expect:
  - `experiments/results/benchmark_sign_verify.csv`
  - `experiments/results/benchmark_sign_verify_summary.json`

## Demo 9 - PKCS#11 client signing
- Run: `docker compose exec web python experiments/02_end_to_end_client_pkcs11_sign.py`
- Expect:
  - warning + setup guidance if env missing, or
  - successful PKCS#11 sign when env is ready.

## Demo 10 - CMS/PKCS#7 detached signature
- Run: `docker compose exec web python experiments/09_cms_pkcs7_detached_signature.py`
- Expect:
  - `[OK] CMS detached signature created`
  - `[OK] CMS detached signature verified`
