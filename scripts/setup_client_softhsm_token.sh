#!/usr/bin/env bash
set -euo pipefail

TOKEN_LABEL="${PKCS11_TOKEN_LABEL:-citizen-client-token}"
SO_PIN="${PKCS11_SO_PIN:-12345678}"
USER_PIN="${PKCS11_USER_PIN:-123456}"
KEY_LABEL="${PKCS11_KEY_LABEL:-CitizenClientKey}"
KEY_ID="${PKCS11_KEY_ID:-10}"
PKCS11_LIB_PATH="${PKCS11_LIB_PATH:-/usr/lib/softhsm/libsofthsm2.so}"

echo "[INFO] Checking SoftHSM tools..."
if ! command -v softhsm2-util >/dev/null 2>&1; then
  echo "[WARNING] softhsm2-util not found. Install SoftHSM2 first."
  echo "Ubuntu/Debian: sudo apt-get install -y softhsm2 opensc"
  exit 0
fi

if ! command -v pkcs11-tool >/dev/null 2>&1; then
  echo "[WARNING] pkcs11-tool not found. Install opensc package."
  echo "Ubuntu/Debian: sudo apt-get install -y opensc"
  exit 0
fi

echo "[INFO] Existing tokens:"
softhsm2-util --show-slots || true

if softhsm2-util --show-slots 2>/dev/null | grep -q "Token label *: *${TOKEN_LABEL}"; then
  echo "[OK] Token '${TOKEN_LABEL}' already exists."
else
  echo "[INFO] Initializing token '${TOKEN_LABEL}'..."
  softhsm2-util --init-token --free --label "${TOKEN_LABEL}" --so-pin "${SO_PIN}" --pin "${USER_PIN}"
  echo "[OK] Token initialized."
fi

echo "[INFO] Generating RSA keypair (if missing)..."
if pkcs11-tool --module "${PKCS11_LIB_PATH}" --login --pin "${USER_PIN}" --token-label "${TOKEN_LABEL}" -O | grep -q "label: *${KEY_LABEL}"; then
  echo "[OK] Key label '${KEY_LABEL}' already exists."
else
  pkcs11-tool --module "${PKCS11_LIB_PATH}" --login --pin "${USER_PIN}" \
    --token-label "${TOKEN_LABEL}" --keypairgen --key-type rsa:2048 \
    --id "${KEY_ID}" --label "${KEY_LABEL}"
  echo "[OK] RSA keypair generated in token."
fi

echo "[OK] SoftHSM setup done."
echo "[INFO] PKCS11 library path (Linux): ${PKCS11_LIB_PATH}"
echo "[INFO] For Windows typical path: C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll"
