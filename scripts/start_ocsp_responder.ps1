$ErrorActionPreference = "Stop"

# Lab OCSP responder helper (OpenSSL-based).
# Uses root CA cert/key as responder signer for demo/lab only.

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$IndexFile = if ($env:INDEX_FILE) { $env:INDEX_FILE } else { Join-Path $RepoRoot "pki-lab\index.txt" }
$CaCert = if ($env:CA_CERT) { $env:CA_CERT } else { Join-Path $RepoRoot "pki-lab\certs\rootCA.crt" }
$ResponderCert = if ($env:RESPONDER_CERT) { $env:RESPONDER_CERT } else { Join-Path $RepoRoot "pki-lab\certs\rootCA.crt" }
$ResponderKey = if ($env:RESPONDER_KEY) { $env:RESPONDER_KEY } else { Join-Path $RepoRoot "pki-lab\private\rootCA.key" }
$Port = if ($env:OCSP_PORT) { $env:OCSP_PORT } else { "8888" }
$OpenSSL = if ($env:OPENSSL_BIN) { $env:OPENSSL_BIN } else { "openssl" }

if (-not (Test-Path $IndexFile)) {
  Write-Error "Missing index file: $IndexFile"
}

if (-not (Test-Path $ResponderCert) -or -not (Test-Path $ResponderKey)) {
  Write-Error "Missing responder cert/key. RESPONDER_CERT=$ResponderCert RESPONDER_KEY=$ResponderKey"
}

Write-Host "[INFO] Starting OCSP responder on port $Port"
Write-Host "[INFO] INDEX_FILE=$IndexFile"
Write-Host "[INFO] CA_CERT=$CaCert"
Write-Host "[INFO] RESPONDER_CERT=$ResponderCert"

& $OpenSSL ocsp `
  -index $IndexFile `
  -port $Port `
  -rsigner $ResponderCert `
  -rkey $ResponderKey `
  -CA $CaCert `
  -text
