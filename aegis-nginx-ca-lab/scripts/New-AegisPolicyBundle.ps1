param(
  [string]$RootCertificatePath = "",
  [string]$BundlePath = "",
  [string]$PayloadPath = "",
  [string]$TelemetryPath = "",
  [string[]]$EnterpriseDomains = @("localhost"),
  [string]$Version = "1.0.0-nginx-local-ca",
  [switch]$OmitRootApproval,
  [string]$SignerCertificatePath = "",
  [string]$SignerKeyPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sharedScript = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\aegis-local-lab\scripts\New-AegisPolicyBundle.ps1"))
$generatedDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\generated"))

if ([string]::IsNullOrWhiteSpace($RootCertificatePath)) {
  $RootCertificatePath = Join-Path $generatedDir "certs\rootCA.pem"
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

$params = @{
  RootCertificatePath = $RootCertificatePath
  BundlePath = $BundlePath
  PayloadPath = $PayloadPath
  TelemetryPath = $TelemetryPath
  EnterpriseDomains = $EnterpriseDomains
  Version = $Version
}

if ($OmitRootApproval) {
  $params.OmitRootApproval = $true
}
if (-not [string]::IsNullOrWhiteSpace($SignerCertificatePath)) {
  $params.SignerCertificatePath = $SignerCertificatePath
}
if (-not [string]::IsNullOrWhiteSpace($SignerKeyPath)) {
  $params.SignerKeyPath = $SignerKeyPath
}

& $sharedScript @params
