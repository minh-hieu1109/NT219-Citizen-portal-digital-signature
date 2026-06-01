$ErrorActionPreference = "Stop"

$TokenLabel = if ($env:PKCS11_TOKEN_LABEL) { $env:PKCS11_TOKEN_LABEL } else { "citizen-client-token" }
$SoPin = if ($env:PKCS11_SO_PIN) { $env:PKCS11_SO_PIN } else { "12345678" }
$UserPin = if ($env:PKCS11_USER_PIN) { $env:PKCS11_USER_PIN } else { "123456" }
$KeyLabel = if ($env:PKCS11_KEY_LABEL) { $env:PKCS11_KEY_LABEL } else { "CitizenClientKey" }
$KeyId = if ($env:PKCS11_KEY_ID) { $env:PKCS11_KEY_ID } else { "10" }
$Pkcs11Lib = if ($env:PKCS11_LIB_PATH) { $env:PKCS11_LIB_PATH } else { "C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll" }

Write-Host "[INFO] Checking SoftHSM tools..."
$softhsm = Get-Command softhsm2-util -ErrorAction SilentlyContinue
$pkcs11Tool = Get-Command pkcs11-tool -ErrorAction SilentlyContinue

if (-not $softhsm) {
  Write-Host "[WARNING] softhsm2-util not found. Install SoftHSM2 first."
  Write-Host "[INFO] Typical PKCS#11 library path (Windows): C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll"
  exit 0
}

if (-not $pkcs11Tool) {
  Write-Host "[WARNING] pkcs11-tool not found. Install OpenSC."
  Write-Host "[INFO] Download OpenSC: https://github.com/OpenSC/OpenSC/releases"
  exit 0
}

Write-Host "[INFO] Existing slots:"
& softhsm2-util --show-slots

$slots = & softhsm2-util --show-slots 2>$null
if ($slots -match "Token label\s*:\s*$TokenLabel") {
  Write-Host "[OK] Token '$TokenLabel' already exists."
} else {
  Write-Host "[INFO] Initializing token '$TokenLabel'..."
  & softhsm2-util --init-token --free --label $TokenLabel --so-pin $SoPin --pin $UserPin
  Write-Host "[OK] Token initialized."
}

$keyList = & pkcs11-tool --module $Pkcs11Lib --login --pin $UserPin --token-label $TokenLabel -O 2>$null
if ($keyList -match "label:\s*$KeyLabel") {
  Write-Host "[OK] Key label '$KeyLabel' already exists."
} else {
  Write-Host "[INFO] Generating RSA keypair..."
  & pkcs11-tool --module $Pkcs11Lib --login --pin $UserPin --token-label $TokenLabel --keypairgen --key-type rsa:2048 --id $KeyId --label $KeyLabel
  Write-Host "[OK] RSA keypair generated."
}

Write-Host "[OK] SoftHSM setup done."
Write-Host "[INFO] PKCS11 library path (Windows): $Pkcs11Lib"
Write-Host "[INFO] Typical Linux path: /usr/lib/softhsm/libsofthsm2.so"
