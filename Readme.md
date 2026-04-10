# Citizen Services Portal - Digital Signature Capstone

Đồ án môn NT219 - Cryptography

## Mô tả
Hệ thống Citizen Services Portal tích hợp chữ ký số, gồm:

- Upload document
- Tạo signing request
- Remote signing
- Client-side signing
- Verification
- CRL checking
- RFC 3161 timestamping
- SoftHSM lab qua Docker

## Công nghệ chính
- Django + Django REST Framework
- PostgreSQL
- Docker / Docker Compose
- OpenSSL
- SoftHSM2
- OpenSC (chưa dùng)

## Cấu trúc thư mục chính

- `accounts/`: quản lý user và certificate profile
- `documents/`: upload và quản lý document
- `signing/`: signing request, remote sign, client sign
- `verification/`: verify signature, CRL, timestamp
- `audit/`: audit log
- `tools/`: script client-side signing
- `pki-lab/`: PKI lab files
- `keys/`: key/certificate local phục vụ demo

## Yêu cầu trước khi chạy
Cần cài:

- Docker
- Docker Compose

## Cách chạy project

### 1. Clone repo
```bash
git clone <YOUR_GITHUB_REPO_URL>
cd citizen-portal
2. Tạo file .env

Tạo file .env ở thư mục gốc.

Ví dụ:

DEBUG=True
SECRET_KEY=django-insecure-change-this-key

DB_NAME=citizen_db
DB_USER=citizen_user
DB_PASSWORD=12345678
DB_HOST=db
DB_PORT=5432

PKCS11_LIB_PATH=/usr/lib/softhsm/libsofthsm2.so
PKCS11_TOKEN_PIN=1234

PKI_OPENSSL_BIN=/usr/bin/openssl
PKI_ROOT_CA_CERT=/app/pki-lab/root-ca/rootCA.crt
PKI_ROOT_CA_KEY=/app/pki-lab/root-ca/rootCA.key
PKI_TSA_CONF=/app/pki-lab/tsa/tsa.conf
PKI_TSA_SECTION=tsa_config
PKI_TSA_CERT=/app/pki-lab/tsa/certs/tsa.crt
PKI_USER_CERT_DIR=/app/pki-lab/user-certs
3. Build và chạy Docker
docker compose up --build
4. Chạy migrate

Mở terminal mới:

docker compose exec web python manage.py migrate
5. Tạo superuser
docker compose exec web python manage.py createsuperuser
6. Truy cập hệ thống
App/API: http://127.0.0.1:8000
Admin: http://127.0.0.1:8000/admin
Luồng demo cơ bản
A. Client-side signing
Upload document
Tạo SigningRequest với signing_type = client
Chạy script client:
python .\tools\client_file_sign_app.py
Script sẽ:
lấy hash document từ server
ký bằng private key local
gửi chữ ký lại cho server
Server verify và tạo SignatureRecord
B. Remote signing
Upload document
Tạo SigningRequest với signing_type = remote
Gọi API remote sign
Server dùng key file/SoftHSM để ký
Server tạo SignatureRecord
Ghi chú
Project dùng Docker để chạy SoftHSM và môi trường lab PKI
Repo này phục vụ mục đích học tập / lab / capstone
Không dùng khóa / certificate trong repo cho môi trường production