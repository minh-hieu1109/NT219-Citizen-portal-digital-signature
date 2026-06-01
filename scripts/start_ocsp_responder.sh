#!/usr/bin/env bash
set -euo pipefail

# Lab OCSP responder helper (OpenSSL-based).
# Uses root CA cert/key as responder signer for demo/lab only.

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INDEX_FILE="${INDEX_FILE:-$BASE_DIR/pki-lab/index.txt}"
CA_CERT="${CA_CERT:-$BASE_DIR/pki-lab/certs/rootCA.crt}"
RESPONDER_CERT="${RESPONDER_CERT:-$BASE_DIR/pki-lab/certs/rootCA.crt}"
RESPONDER_KEY="${RESPONDER_KEY:-$BASE_DIR/pki-lab/private/rootCA.key}"
PORT="${OCSP_PORT:-8888}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

if [[ ! -f "$INDEX_FILE" ]]; then
  echo "[ERROR] Missing index file: $INDEX_FILE"
  exit 1
fi

if [[ ! -f "$RESPONDER_CERT" || ! -f "$RESPONDER_KEY" ]]; then
  echo "[ERROR] Missing responder cert/key."
  echo "RESPONDER_CERT=$RESPONDER_CERT"
  echo "RESPONDER_KEY=$RESPONDER_KEY"
  exit 1
fi

echo "[INFO] Starting OCSP responder on port $PORT"
echo "[INFO] INDEX_FILE=$INDEX_FILE"
echo "[INFO] CA_CERT=$CA_CERT"
echo "[INFO] RESPONDER_CERT=$RESPONDER_CERT"

exec "$OPENSSL_BIN" ocsp \
  -index "$INDEX_FILE" \
  -port "$PORT" \
  -rsigner "$RESPONDER_CERT" \
  -rkey "$RESPONDER_KEY" \
  -CA "$CA_CERT" \
  -text
