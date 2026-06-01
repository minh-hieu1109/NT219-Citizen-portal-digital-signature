# Codex Implementation Plan — NT219 Citizen Portal Digital Signature

Repo mục tiêu:

```text
https://github.com/minh-hieu1109/NT219-Citizen-portal-digital-signature
```

Đồ án: **Digital Signature for Public Administrative Services via Citizen Services Portal**  
Môn: **NT219 - Cryptography**

Mục tiêu của file này là dùng làm **task plan chính cho Codex**. Codex phải đọc file này trước khi làm. Mỗi lần chỉ làm **một giai đoạn**, làm xong phải cập nhật file tiến độ duy nhất:

```text
FINAL_TASK_PROGRESS.md tạo tại thư mục task
```

thêm thư mục task này vào gitignore

---

## 0. Phạm vi cần đạt

Repo hiện tại đã có nền tảng Django cho Citizen Portal, gồm các phần như:

```text
accounts/
documents/
signing/
verification/
audit/
frontend/
pki-lab/
tools/
docker-compose.yml
requirements.txt
```

Cần bổ sung để đáp ứng cơ bản yêu cầu đề tài:

1. RA workflow cơ bản.
2. Remote signing có replay protection.
3. Client-side signing mô phỏng smartcard/USB token bằng SoftHSM/PKCS#11.
4. OCSP checking cơ bản hoặc mô phỏng bằng OpenSSL.
5. LTV archive cơ bản.
6. Experiment scripts chứng minh các tình huống chính.
7. Benchmark ký/xác minh.
8. Cleanup Docker/config/demo scripts.

Các phần có thể bỏ qua hoặc chỉ ghi TODO/design note:

1. Mobile signing thật.
2. WebAuthn/OIDC/Keycloak đầy đủ.
3. PAdES/XAdES/CAdES đầy đủ.
4. eIDAS/QES pháp lý đầy đủ.
5. Threshold signing.
6. Production HSM như AWS CloudHSM/Thales/Utimaco.

---

## 1. Nguyên tắc bắt buộc cho Codex

Codex phải tuân thủ các quy tắc sau:

1. Không làm lại repo từ đầu.
2. Không xóa chức năng hiện có nếu chưa chắc chắn.
3. Không đổi tên app Django hiện có nếu không cần.
4. Không đổi database schema tùy tiện mà không tạo migration.
5. Không xóa migration, reset database, xóa Docker volume hoặc xóa dữ liệu demo nếu chưa hỏi lại user.
6. Mỗi lần chỉ làm một giai đoạn.
7. Sau mỗi giai đoạn phải chạy lệnh kiểm tra phù hợp.
8. Nếu test lỗi, phải sửa nguyên nhân thật, không comment test, không xóa assertion để né lỗi.
9. Không hardcode secret production thật vào repo.
10. Với password/PIN demo, đặt trong `.env.example` hoặc biến môi trường, không giấu trong code.
11. Nếu gặp lỗi môi trường không tự xử lý được, phải dừng và ghi rõ trong `FINAL_TASK_PROGRESS.md`.
12. Ưu tiên demo end-to-end chạy được hơn là thêm quá nhiều tính năng nhưng không chạy được.

---

## 2. File tiến độ bắt buộc

Codex phải tạo và duy trì file:

```text
FINAL_TASK_PROGRESS.md
```

Sau mỗi giai đoạn, Codex phải thêm một mục mới vào cuối file, không ghi đè mất nội dung cũ.

Mẫu nội dung:

```markdown
# FINAL TASK PROGRESS

## Phase 0 — Baseline survey

### Status
DONE / PARTIAL / BLOCKED

### What was implemented
- ...

### Files changed
- ...

### Migrations created
- ...

### Commands run
```bash
...
```

### Test/check result
- ...

### Demo command, if any
```bash
...
```

### Known issues
- ...

### Next recommended phase
- ...
```

Nếu bị lỗi không xử lý được, ghi:

```markdown
## BLOCKED DETAILS

### Command
```bash
...
```

### Error
```text
...
```

### Suspected cause
- ...

### Suggested fix
- ...

### What I need from user
- ...
```

---

## 3. Phase 0 — Khảo sát repo và tạo baseline

### Mục tiêu

Đọc toàn bộ source code hiện tại, không chỉ README. Xác định repo đã có gì, thiếu gì, lệnh chạy hiện tại là gì.

### File cần đọc kỹ

```text
accounts/models.py
accounts/serializers.py
accounts/views.py
accounts/signals.py
accounts/urls.py
documents/models.py
documents/serializers.py
documents/views.py
documents/urls.py
signing/models.py
signing/serializers.py
signing/services.py
signing/signer_backends.py
signing/views.py
signing/urls.py
verification/models.py
verification/services.py
verification/views.py
verification/urls.py
audit/models.py
audit/views.py
frontend/views.py
config/settings.py
docker-compose.yml
requirements.txt
```

### Việc cần làm

1. Tạo thư mục nếu chưa có:

```text
docs/
```

2. Tạo file:

```text
docs/implementation_gap_plan.md
```

3. Nội dung file phải có:

- Chức năng hiện có.
- Chức năng còn thiếu so với phạm vi code cần làm.
- Danh sách giai đoạn triển khai.
- Lệnh chạy project hiện tại.
- Lệnh test/check hiện tại.
- Rủi ro môi trường có thể gặp.

### Lệnh kiểm tra cần chạy

Tối thiểu:

```bash
python manage.py check
python manage.py makemigrations --check --dry-run
```

Nếu repo chạy bằng Docker:

```bash
docker compose config
docker compose up -d --build
docker compose logs web --tail=100
```

### Kết quả mong muốn

- Có `docs/implementation_gap_plan.md`.
- Có `FINAL_TASK_PROGRESS.md` với mục Phase 0.
- Biết rõ repo đang chạy được hay đang lỗi ở đâu.

---

## 4. Phase 1 — RA workflow cơ bản

### Mục tiêu

Bổ sung quy trình Registration Authority cơ bản:

```text
Citizen đăng ký tài khoản
→ Officer/Admin xác minh danh tính
→ Certificate chỉ được cấp sau khi user được xác minh
→ Ghi audit log
```

### Yêu cầu chức năng

1. Tận dụng model user hiện có nếu đã có:

```python
role
citizen_id
is_verified_identity
```

2. Nếu thiếu field cần thiết, bổ sung bằng migration.

3. Thêm hoặc hoàn thiện API:

```text
GET    /api/accounts/pending-identity/
POST   /api/accounts/{user_id}/verify-identity/
POST   /api/accounts/{user_id}/reject-identity/
POST   /api/accounts/{user_id}/issue-certificate/
```

4. Chỉ `officer` hoặc `admin` được verify/reject identity.
5. Chỉ user đã `is_verified_identity=True` mới được cấp certificate.
6. Citizen chưa verify không được remote sign.
7. Citizen chưa verify không được cấp certificate.
8. Mọi thao tác verify/reject/issue certificate phải ghi audit log.
9. Nếu repo đang tự cấp certificate ngay khi tạo citizen bằng signal, cần sửa lại:
   - Không tự cấp certificate ngay cho citizen chưa verify.
   - Có thể giữ auto certificate cho superuser/admin nếu cần.
   - Citizen chỉ được cấp certificate sau khi officer/admin approve.

### File có thể cần sửa

```text
accounts/models.py
accounts/views.py
accounts/serializers.py
accounts/urls.py
accounts/signals.py
audit/models.py
audit/services.py
signing/services.py
```

### Test cần tạo

Tạo test hoặc bổ sung test:

```text
tests/test_ra_workflow.py
```

Case tối thiểu:

1. Citizen mới tạo chưa được verify.
2. Citizen chưa verify không được cấp cert.
3. Officer verify citizen thành công.
4. Citizen đã verify được cấp cert.
5. Citizen chưa verify không được remote sign.
6. Audit log được tạo khi verify và issue certificate.

### Lệnh kiểm tra

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py check
python manage.py test
```

### Cập nhật tiến độ

Sau khi xong, append vào `FINAL_TASK_PROGRESS.md`:

- API đã thêm.
- Model/migration đã thêm.
- Test đã tạo.
- Lệnh đã chạy.
- Lỗi còn lại nếu có.

---

## 5. Phase 2 — Replay protection cho remote signing

### Mục tiêu

Bổ sung chống replay cho remote signing. Không chỉ dựa vào trạng thái signed, cần có nonce/expires/used rõ ràng.

### Việc cần làm

Trong `SigningRequest`, bổ sung nếu chưa có:

```python
nonce
expires_at
used_at
auth_challenge
auth_method
strong_auth_verified
```

Có thể tối giản:

```python
nonce = random UUID/token
expires_at = now + 10 minutes
used_at = null until signed
strong_auth_verified = BooleanField(default=False)
```

Thêm setting:

```python
REQUIRE_STRONG_AUTH_FOR_REMOTE_SIGNING = False
REMOTE_SIGNING_REQUEST_TTL_MINUTES = 10
```

Khi tạo signing request:

1. Sinh nonce.
2. Sinh expires_at.
3. Trạng thái pending.

Khi remote sign:

1. Kiểm tra request chưa expired.
2. Kiểm tra `used_at is None`.
3. Kiểm tra chưa có `SignatureRecord`.
4. Nếu `REQUIRE_STRONG_AUTH_FOR_REMOTE_SIGNING=True`, yêu cầu `strong_auth_verified=True`.
5. Sau khi ký thành công, set `used_at = timezone.now()`.
6. Nếu gọi lại cùng request, phải fail với thông báo replay/used request.

### File có thể cần sửa

```text
signing/models.py
signing/serializers.py
signing/services.py
signing/views.py
signing/urls.py
config/settings.py
```

### Test cần tạo

```text
tests/test_remote_signing_replay.py
```

Case tối thiểu:

1. Remote signing lần đầu thành công.
2. Gọi lại remote signing cùng request bị từ chối.
3. Request hết hạn bị từ chối.
4. Request đã có `used_at` bị từ chối.

### Lệnh kiểm tra

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py check
python manage.py test
```

---

## 6. Phase 3 — Client-side signing qua SoftHSM/PKCS#11

### Mục tiêu

Bổ sung demo client-side signing mô phỏng smartcard/USB token bằng SoftHSM/PKCS#11. Không cần USB token thật.

### Tool cần tạo

```text
tools/client_pkcs11_sign_app.py
```

### Chức năng tool

Tool nhận input:

- server URL,
- username/password hoặc token auth repo đang dùng,
- signing_request_id,
- PKCS#11 library path,
- token label,
- key label hoặc key id,
- PIN.

Luồng:

1. Login/authenticate.
2. Gọi API prepare client signing để lấy digest.
3. Ký digest bằng private key trong SoftHSM qua PKCS#11.
4. Gửi chữ ký base64 về API complete client signing.
5. In kết quả rõ ràng.

Ví dụ lệnh:

```bash
python tools/client_pkcs11_sign_app.py \
  --base-url http://localhost:8000 \
  --username citizen1 \
  --password citizenpass \
  --request-id 1 \
  --pkcs11-lib /usr/lib/softhsm/libsofthsm2.so \
  --token-label citizen-token \
  --key-label citizen-signing-key \
  --pin 1234
```

Windows path có thể là:

```text
C:\SoftHSM2\lib\softhsm2-x64.dll
```

### Setup script cần tạo

```text
scripts/setup_client_softhsm_token.sh
scripts/setup_client_softhsm_token.ps1
```

Script nên hỗ trợ:

1. Init token.
2. Generate RSA keypair.
3. Export public key hoặc tạo CSR nếu khả thi.
4. Ghi hướng dẫn ngắn trong terminal.

Nếu repo đã có API enroll certificate từ CSR, tận dụng luồng:

```text
client SoftHSM tạo keypair
→ tạo CSR
→ gửi CSR lên server
→ server cấp certificate
→ client ký bằng private key trong SoftHSM
```

Nếu quá khó, bước đầu có thể dùng certificate có sẵn, nhưng phải ghi rõ TODO trong `FINAL_TASK_PROGRESS.md`.

### Demo script cần tạo

```text
experiments/run_client_pkcs11_demo.py
```

Hoặc:

```text
experiments/run_client_pkcs11_demo.sh
```

Demo cần chứng minh:

1. Tạo signing request kiểu client.
2. Prepare digest.
3. Client ký bằng SoftHSM/PKCS#11.
4. Server verify chữ ký thành công.
5. SignatureRecord được tạo.
6. Verification trả về valid.

### Lỗi môi trường cần xử lý rõ

Nếu không tìm thấy PKCS#11 library, không crash mơ hồ. In gợi ý path:

Linux:

```text
/usr/lib/softhsm/libsofthsm2.so
/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

Windows:

```text
C:\SoftHSM2\lib\softhsm2-x64.dll
```

---

## 7. Phase 4 — OCSP responder mô phỏng bằng OpenSSL

### Mục tiêu

Bổ sung OCSP checking cơ bản. Repo có thể đã có CRL, nhưng đề yêu cầu OCSP/CRL, nên cần thêm OCSP ở mức lab/demo.

### Service cần tạo

```text
verification/ocsp_services.py
```

Hoặc vị trí hợp lý tương đương.

### Chức năng

1. Tạo hoặc gửi OCSP request cho certificate.
2. Gọi OpenSSL OCSP responder hoặc verify qua endpoint configured.
3. Parse kết quả cơ bản:
   - good,
   - revoked,
   - unknown,
   - unavailable,
   - error.

### Script chạy OCSP responder

Tạo:

```text
scripts/start_ocsp_responder.sh
scripts/start_ocsp_responder.ps1
```

Ví dụ tham khảo:

```bash
openssl ocsp \
  -index pki-lab/demoCA/index.txt \
  -port 8888 \
  -rsigner pki-lab/ocsp/ocsp.crt \
  -rkey pki-lab/ocsp/ocsp.key \
  -CA pki-lab/ca/ca.crt \
  -text
```

Tên path thực tế phải dựa trên repo hiện tại.

### Setting cần thêm

```python
ENABLE_OCSP_CHECK = True
OCSP_RESPONDER_URL = "http://localhost:8888"
OPENSSL_BIN = os.getenv("OPENSSL_BIN", "openssl")
```

### Tích hợp verification

Khi verify signature:

1. Nếu OCSP enabled, gọi OCSP check.
2. Nếu OCSP không chạy, không được crash.
3. Lưu trạng thái vào `VerificationResult.detail` hoặc field riêng:

```text
ocsp_status = good/revoked/unknown/unavailable/error
ocsp_checked_at = ...
ocsp_response_base64 = ... nếu có
```

### Test cần tạo

```text
tests/test_ocsp_verification.py
```

Case tối thiểu:

1. Certificate good → OCSP good.
2. Certificate revoked → OCSP revoked.
3. OCSP unavailable → hệ thống không crash, ghi rõ unavailable.

---

## 8. Phase 5 — LTV archive cơ bản

### Mục tiêu

Bổ sung Long-Term Validation evidence ở mức cơ bản. Không cần production-grade, nhưng phải lưu được bằng chứng xác minh.

### Model đề xuất

Tạo model mới nếu phù hợp:

```python
class ValidationEvidence(models.Model):
    signature_record = models.OneToOneField(SignatureRecord, on_delete=models.CASCADE)
    signer_certificate_pem = models.TextField()
    certificate_chain_pem = models.TextField(blank=True)
    crl_pem = models.TextField(blank=True)
    ocsp_response_base64 = models.TextField(blank=True)
    timestamp_token_base64 = models.TextField(blank=True)
    archived_at = models.DateTimeField(auto_now_add=True)
    evidence_hash = models.CharField(max_length=64)
```

Nếu không muốn tạo model mới, có thể lưu trong `SignatureRecord` hoặc `VerificationResult.detail`, nhưng model riêng được ưu tiên.

### Khi ký thành công

Cần lưu:

1. Signer certificate.
2. CA certificate chain nếu có.
3. CRL hiện tại nếu có.
4. OCSP response nếu có.
5. Timestamp token nếu có.
6. Evidence hash = SHA-256 của toàn bộ evidence.

### Khi verify

Thêm chế độ hoặc service:

```text
live validation
archived/LTV validation
```

Có thể tạo management command:

```bash
python manage.py verify_ltv --signature-id 1
```

Hoặc API:

```text
POST /api/verification/signatures/{id}/verify-ltv/
```

### Test cần tạo

```text
tests/test_ltv_archive.py
```

Case tối thiểu:

1. Sau khi ký, có `ValidationEvidence`.
2. Evidence có signer certificate.
3. Evidence có timestamp token nếu timestamp tạo được.
4. Evidence hash không rỗng.
5. Verify LTV đọc được evidence và trả kết quả rõ ràng.

---

## 9. Phase 6 — Experiment scripts

### Mục tiêu

Tạo script demo để chứng minh hệ thống đáp ứng yêu cầu đề tài. Đây là phần rất quan trọng để sau này viết báo cáo/slide.

### Thư mục cần tạo

```text
experiments/
experiments/results/
```

### File cần tạo

```text
experiments/README.md
experiments/common.py
experiments/01_end_to_end_remote_sign.py
experiments/02_end_to_end_client_pkcs11_sign.py
experiments/03_tamper_document_after_sign.py
experiments/04_revoke_certificate_and_verify.py
experiments/05_replay_remote_signing_request.py
experiments/06_tsa_unavailable.py
experiments/07_ocsp_unavailable.py
experiments/08_benchmark_sign_verify.py
```

### Script 01 — End-to-end remote sign

Luồng:

```text
login
create/upload document
create remote signing request
remote sign
verify signature
print result
```

Output mong muốn:

```text
[OK] Uploaded document
[OK] Created remote signing request
[OK] Remote signing completed
[OK] Verification result: valid
```

### Script 02 — End-to-end client PKCS#11 sign

Luồng:

```text
login
upload document
create client signing request
prepare digest
client signs digest via SoftHSM/PKCS#11
complete signing
verify signature
```

Output mong muốn:

```text
[OK] Digest prepared
[OK] Signature created by PKCS#11 token
[OK] Server accepted signature
[OK] Verification result: valid
```

Nếu Phase 3 chưa hoàn tất, script này có thể ghi rõ `SKIPPED` với lý do.

### Script 03 — Tamper document after sign

Luồng:

```text
ký document thành công
sửa nội dung file trong media hoặc upload replacement nếu app hỗ trợ
verify lại
expect invalid/hash mismatch
```

Output mong muốn:

```text
[EXPECTED FAIL] Verification rejected tampered document
Reason: hash mismatch
```

### Script 04 — Revoke certificate and verify

Luồng:

```text
ký document thành công
revoke certificate
generate/update CRL
verify lại
expect invalid/revoked
```

Output mong muốn:

```text
[EXPECTED FAIL] Verification rejected revoked certificate
Reason: certificate revoked
```

### Script 05 — Replay remote signing request

Luồng:

```text
tạo remote signing request
remote sign lần 1 thành công
remote sign lần 2 cùng request
expect fail/replay detected
```

Output mong muốn:

```text
[OK] First remote signing accepted
[EXPECTED FAIL] Replay signing request rejected
```

### Script 06 — TSA unavailable

Luồng:

```text
cấu hình sai TSA hoặc tắt TSA
remote sign
kiểm tra hệ thống không crash
signature vẫn có thể tạo hoặc request fail có kiểm soát
timestamp_status = failed/unavailable
```

Output mong muốn:

```text
[EXPECTED WARNING] Timestamp service unavailable
[OK] System handled TSA failure safely
```

### Script 07 — OCSP unavailable

Luồng:

```text
cấu hình OCSP URL sai hoặc tắt OCSP responder
verify signature
expect ocsp_status = unavailable
system không crash
```

Output mong muốn:

```text
[EXPECTED WARNING] OCSP unavailable
[OK] Verification handled OCSP outage safely
```

### Script 08 — Benchmark sign verify

Đo:

1. Remote signing time.
2. Client signing time nếu có.
3. Verification time.
4. Timestamp time nếu đo được.

Xuất file:

```text
experiments/results/benchmark_results.csv
experiments/results/benchmark_summary.md
```

CSV format:

```csv
operation,iterations,avg_ms,min_ms,max_ms,p95_ms
remote_sign,10,...
verify,10,...
client_pkcs11_sign,10,...
timestamp,10,...
```

---

## 10. Phase 7 — CMS/PKCS#7 detached signature nếu đủ thời gian

### Mục tiêu

Không cần làm PAdES/XAdES đầy đủ. Chỉ cần thêm CMS/PKCS#7 detached signature để repo không chỉ có raw RSA signature.

### Service cần tạo

```text
signing/cms_services.py
```

### Lệnh OpenSSL tham khảo

Sign:

```bash
openssl cms -sign \
  -binary \
  -in input.pdf \
  -signer signer.crt \
  -inkey signer.key \
  -outform DER \
  -out signature.p7s \
  -nosmimecap
```

Verify:

```bash
openssl cms -verify \
  -binary \
  -inform DER \
  -in signature.p7s \
  -content input.pdf \
  -CAfile ca.crt \
  -out /tmp/verified.out
```

Nếu private key nằm trong SoftHSM thì CMS bằng OpenSSL sẽ phức tạp hơn. Bước đầu chỉ cần hỗ trợ file-key CMS. SoftHSM vẫn có thể dùng raw RSA signing.

### Gợi ý model

Có thể thêm:

```python
signature_format = choices: RAW_RSA, CMS_PKCS7
```

Hoặc lưu trong field algorithm nếu repo đã có.

### Management command gợi ý

```bash
python manage.py create_cms_signature --document-id 1 --certificate-id 1
python manage.py verify_cms_signature --signature-id 1
```

Nếu quá mất thời gian, bỏ qua phase này và ghi TODO trong `FINAL_TASK_PROGRESS.md`.

---

## 11. Phase 8 — Hardening và cleanup

### Mục tiêu

Đảm bảo project sạch, chạy được, dễ demo.

### Việc cần làm

1. Kiểm tra secret/config không hardcode quá nguy hiểm.
2. Tạo hoặc cập nhật `.env.example`.
3. Đảm bảo Docker Compose chạy được.
4. Đảm bảo migration đầy đủ.
5. Đảm bảo `python manage.py check` pass.
6. Đảm bảo test chính pass hoặc ghi rõ test nào phụ thuộc môi trường.
7. Đảm bảo experiment scripts có hướng dẫn chạy.
8. Tạo Makefile hoặc script tổng hợp nếu phù hợp.

### Makefile gợi ý

```makefile
check:
	python manage.py check

migrate:
	python manage.py migrate

test:
	python manage.py test

demo-remote:
	python experiments/01_end_to_end_remote_sign.py

demo-client-pkcs11:
	python experiments/02_end_to_end_client_pkcs11_sign.py

demo-tamper:
	python experiments/03_tamper_document_after_sign.py

demo-revoke:
	python experiments/04_revoke_certificate_and_verify.py

demo-replay:
	python experiments/05_replay_remote_signing_request.py

benchmark:
	python experiments/08_benchmark_sign_verify.py
```

### File demo cần tạo hoặc cập nhật

```text
README_DEMO.md
```

Nội dung cần có:

1. Cách chạy Docker.
2. Cách migrate database.
3. Cách tạo user demo.
4. Cách chạy remote signing demo.
5. Cách chạy client PKCS#11 demo.
6. Cách chạy tamper/revoke/replay experiments.
7. Cách chạy benchmark.
8. Các lỗi thường gặp.

---

## 12. Thứ tự ưu tiên nếu không đủ thời gian

### Bắt buộc nên làm

1. Phase 0 — Baseline survey.
2. Phase 1 — RA workflow.
3. Phase 2 — Replay protection.
4. Phase 4 — OCSP cơ bản.
5. Phase 5 — LTV archive cơ bản.
6. Phase 6 — Experiment scripts: remote sign, tamper, revoke, replay, benchmark.

### Nên làm

1. Phase 3 — Client PKCS#11 signing bằng SoftHSM.
2. Phase 6 — TSA unavailable, OCSP unavailable.
3. Phase 8 — Cleanup Docker/config/demo.

### Có thời gian thì làm

1. Phase 7 — CMS/PKCS#7 detached signature.

### Có thể bỏ qua

1. Mobile signing thật.
2. Keycloak/OIDC/WebAuthn thật.
3. PAdES/XAdES/CAdES đầy đủ.
4. Threshold signing.
5. Production HSM.

---

## 13. Lỗi có thể gặp và cách xử lý

### 13.1. Migration conflict

Không xóa migration cũ bừa bãi. Chạy:

```bash
python manage.py makemigrations
python manage.py migrate
```

Nếu database dev bị hỏng và cần reset, phải hỏi user trước.

### 13.2. SoftHSM không tìm thấy library

Gợi ý path:

Linux:

```text
/usr/lib/softhsm/libsofthsm2.so
/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

Windows:

```text
C:\SoftHSM2\lib\softhsm2-x64.dll
```

### 13.3. Token chưa init hoặc PIN sai

Lỗi thường gặp:

```text
CKR_PIN_INCORRECT
CKR_TOKEN_NOT_PRESENT
```

Cần kiểm tra script setup token và biến môi trường PIN.

### 13.4. OpenSSL path khác nhau giữa Windows/Linux

Dùng setting:

```python
OPENSSL_BIN = os.getenv("OPENSSL_BIN", "openssl")
```

Không hardcode path OpenSSL trong nhiều file.

### 13.5. OCSP responder chưa chạy

Không để app crash. Trả về:

```text
ocsp_status = unavailable
```

và ghi chi tiết lỗi vào JSON detail.

### 13.6. TSA lỗi

Nếu timestamp fail, lưu:

```text
timestamp_status = failed/unavailable
timestamp_error = ...
```

Không được làm crash toàn bộ hệ thống nếu chữ ký đã tạo được.

### 13.7. Test phụ thuộc thời gian

Dùng `timezone.now()`. Với request expired, tạo dữ liệu expired trực tiếp thay vì sleep lâu.

---

## 14. Tiêu chí hoàn thành cơ bản

Sau khi hoàn thành các phase chính, các lệnh sau phải chạy được hoặc nếu không chạy được thì phải ghi rõ lý do môi trường:

```bash
python manage.py check
python manage.py migrate
python manage.py test
python experiments/01_end_to_end_remote_sign.py
python experiments/03_tamper_document_after_sign.py
python experiments/04_revoke_certificate_and_verify.py
python experiments/05_replay_remote_signing_request.py
python experiments/08_benchmark_sign_verify.py
```

Nếu Phase 3 hoàn thành:

```bash
python experiments/02_end_to_end_client_pkcs11_sign.py
```

Nếu Phase 6 đầy đủ:

```bash
python experiments/06_tsa_unavailable.py
python experiments/07_ocsp_unavailable.py
```

Nếu dùng Docker:

```bash
docker compose up -d --build
docker compose exec web python manage.py check
docker compose exec web python manage.py migrate
docker compose exec web python manage.py test
docker compose exec web python experiments/01_end_to_end_remote_sign.py
```

---

## 15. Cách báo cáo lại cho user sau mỗi phase

Sau khi xong mỗi phase, Codex phải trả lời ngắn gọn:

```text
Phase X completed.
I updated FINAL_TASK_PROGRESS.md.
Main changes:
- ...
Checks run:
- ...
Result:
- ...
Next phase recommended:
- Phase Y
```

Nếu bị lỗi:

```text
Phase X blocked.
I updated FINAL_TASK_PROGRESS.md with error details.
Please send this file/content to ChatGPT for review.
```
