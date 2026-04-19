param(
  [string]$ProfileDir = "",
  [string]$BundlePath = "",
  [string]$TelemetryPath = "",
  [string]$SignerCertificatePath = "",
  [string]$RootCertificatePath = "",
  [string]$CertutilPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sharedScript = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\aegis-local-lab\scripts\Write-AegisFirefoxPrefs.ps1"))
$generatedDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\generated"))

if ([string]::IsNullOrWhiteSpace($ProfileDir)) {
  $ProfileDir = Join-Path $generatedDir "firefox-profile"
}
if ([string]::IsNullOrWhiteSpace($BundlePath)) {
  $BundlePath = Join-Path $generatedDir "aegis-enterprise-policy.bundle.json"
}
if ([string]::IsNullOrWhiteSpace($TelemetryPath)) {
  $TelemetryPath = Join-Path $generatedDir "aegis-telemetry.jsonl"
}
if ([string]::IsNullOrWhiteSpace($RootCertificatePath)) {
  $RootCertificatePath = Join-Path $generatedDir "certs\rootCA.pem"
}

$params = @{
  ProfileDir = $ProfileDir
  BundlePath = $BundlePath
  TelemetryPath = $TelemetryPath
  RootCertificatePath = $RootCertificatePath
  RootNickname = "Aegis Nginx Lab Root CA"
}

if (-not [string]::IsNullOrWhiteSpace($SignerCertificatePath)) {
  $params.SignerCertificatePath = $SignerCertificatePath
}
if (-not [string]::IsNullOrWhiteSpace($CertutilPath)) {
  $params.CertutilPath = $CertutilPath
}

& $sharedScript @params
