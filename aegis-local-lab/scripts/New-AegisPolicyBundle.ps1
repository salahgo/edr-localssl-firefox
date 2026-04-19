param(
  [string]$RootCertificatePath = "",
  [string]$BundlePath = "",
  [string]$PayloadPath = "",
  [string]$TelemetryPath = "",
  [string[]]$EnterpriseDomains = @("localhost"),
  [string]$Version = "1.0.0-local",
  [switch]$OmitRootApproval,
  [string]$SignerCertificatePath = "",
  [string]$SignerKeyPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-Sha256FingerprintHex {
  param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

  $hashBytes = [System.Security.Cryptography.SHA256]::HashData($Certificate.RawData)
  return ([Convert]::ToHexString($hashBytes)).ToUpperInvariant()
}

function Read-Certificate {
  param([string]$Path)

  $raw = [System.IO.File]::ReadAllText($Path)
  if ($raw.Contains("BEGIN CERTIFICATE")) {
    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($raw)
  }
  return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.IO.File]::ReadAllBytes($Path))
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$generatedDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\generated"))

if ([string]::IsNullOrWhiteSpace($RootCertificatePath)) {
  $RootCertificatePath = Join-Path $generatedDir "ManagementCA.pem"
}
if ([string]::IsNullOrWhiteSpace($BundlePath)) {
  $BundlePath = Join-Path $generatedDir "aegis-enterprise-policy.bundle.json"
}
if ([string]::IsNullOrWhiteSpace($PayloadPath)) {
  $PayloadPath = Join-Path $generatedDir "aegis-enterprise-policy.payload.json"
}
if ([string]::IsNullOrWhiteSpace($TelemetryPath)) {
  $TelemetryPath = Join-Path $generatedDir "aegis-telemetry.jsonl"
}
if ([string]::IsNullOrWhiteSpace($SignerCertificatePath)) {
  $SignerCertificatePath = Join-Path $repoRoot "security\manager\ssl\tests\unit\bad_certs\default-ee.pem"
}
if ([string]::IsNullOrWhiteSpace($SignerKeyPath)) {
  $SignerKeyPath = Join-Path $repoRoot "security\manager\ssl\tests\unit\bad_certs\default-ee.key"
}

$RootCertificatePath = [System.IO.Path]::GetFullPath($RootCertificatePath)
$BundlePath = [System.IO.Path]::GetFullPath($BundlePath)
$PayloadPath = [System.IO.Path]::GetFullPath($PayloadPath)
$TelemetryPath = [System.IO.Path]::GetFullPath($TelemetryPath)
$SignerCertificatePath = [System.IO.Path]::GetFullPath($SignerCertificatePath)
$SignerKeyPath = [System.IO.Path]::GetFullPath($SignerKeyPath)

[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($BundlePath)) | Out-Null

$rootCertificate = Read-Certificate -Path $RootCertificatePath
$signerCertificate = Read-Certificate -Path $SignerCertificatePath
$signerCertificatePem = [System.IO.File]::ReadAllText($SignerCertificatePath)

$rootFingerprint = Get-Sha256FingerprintHex -Certificate $rootCertificate
$signerFingerprint = Get-Sha256FingerprintHex -Certificate $signerCertificate

$approvedRoots = @()
if (-not $OmitRootApproval) {
  $approvedRoots = @($rootFingerprint)
}

$payloadObject = [ordered]@{
  version = $Version
  enterprise_domains = $EnterpriseDomains
  approved_root_fingerprints_sha256 = $approvedRoots
  approved_intermediate_fingerprints_sha256 = @()
  required_eku = @("serverAuth")
  require_san = $true
  revocation_mode = "soft_fail"
  max_leaf_validity_days = 825
  required_policy_oids = @()
  pinsets = @()
  enforcement = [ordered]@{
    internal_hostname_public_ca = "block"
    public_hostname_private_ca = "block"
  }
}

$payloadJson = $payloadObject | ConvertTo-Json -Depth 10 -Compress

$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.ImportFromPem([System.IO.File]::ReadAllText($SignerKeyPath))
$signatureBytes = $rsa.SignData(
  [System.Text.Encoding]::UTF8.GetBytes($payloadJson),
  [System.Security.Cryptography.HashAlgorithmName]::SHA256,
  [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)

$bundleObject = [ordered]@{
  format = "aegis-enterprise-policy-bundle/v1"
  payload = $payloadJson
  signature = [ordered]@{
    algorithm = "rsa_pkcs1_sha256"
    signature_base64 = [Convert]::ToBase64String($signatureBytes)
    signer_cert_pem = $signerCertificatePem
  }
}

$bundleJson = $bundleObject | ConvertTo-Json -Depth 10 -Compress

Set-Content -LiteralPath $PayloadPath -Value $payloadJson -Encoding utf8 -NoNewline
Set-Content -LiteralPath $BundlePath -Value $bundleJson -Encoding utf8 -NoNewline
if (-not (Test-Path -LiteralPath $TelemetryPath)) {
  Set-Content -LiteralPath $TelemetryPath -Value "" -Encoding utf8 -NoNewline
}

Write-Output "Created:"
Write-Output "  payload: $PayloadPath"
Write-Output "  bundle: $BundlePath"
Write-Output "  telemetry log: $TelemetryPath"
Write-Output "Fingerprints:"
Write-Output "  approved root: $rootFingerprint"
Write-Output "  allowed signer: $signerFingerprint"
if ($OmitRootApproval) {
  Write-Output "Mode:"
  Write-Output "  root approval omitted to trigger the internal-hostname block path"
}
