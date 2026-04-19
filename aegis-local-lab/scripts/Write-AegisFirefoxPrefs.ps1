param(
  [string]$ProfileDir = "",
  [string]$BundlePath = "",
  [string]$TelemetryPath = "",
  [string]$SignerCertificatePath = "",
  [string]$RootCertificatePath = "",
  [string]$RootNickname = "Aegis Imported Root CA",
  [string]$CertutilPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-Sha256FingerprintHex {
  param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

  $hashBytes = [System.Security.Cryptography.SHA256]::HashData($Certificate.RawData)
  return ([Convert]::ToHexString($hashBytes)).ToUpperInvariant()
}

function ConvertTo-JsString {
  param([string]$Value)

  return $Value.Replace("\", "\\").Replace('"', '\"')
}

function Read-Certificate {
  param([string]$Path)

  $raw = [System.IO.File]::ReadAllText($Path)
  if ($raw.Contains("BEGIN CERTIFICATE")) {
    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($raw)
  }
  return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.IO.File]::ReadAllBytes($Path))
}

function Resolve-NssCertutilPath {
  param(
    [string]$PreferredPath,
    [string]$RepoRoot
  )

  if (-not [string]::IsNullOrWhiteSpace($PreferredPath)) {
    $resolvedPreferredPath = [System.IO.Path]::GetFullPath($PreferredPath)
    if (Test-Path -LiteralPath $resolvedPreferredPath) {
      return $resolvedPreferredPath
    }
    throw "NSS certutil.exe not found at: $resolvedPreferredPath"
  }

  $defaultPath = Join-Path $RepoRoot "obj-x86_64-pc-windows-msvc\dist\bin\certutil.exe"
  if (Test-Path -LiteralPath $defaultPath) {
    return $defaultPath
  }

  foreach ($objDir in Get-ChildItem -LiteralPath $RepoRoot -Directory -Filter "obj-*") {
    $candidate = Join-Path $objDir.FullName "dist\bin\certutil.exe"
    if (Test-Path -LiteralPath $candidate) {
      return $candidate
    }
  }

  throw "Unable to find NSS certutil.exe under $RepoRoot. Build Firefox first or pass -CertutilPath."
}

function Import-TrustedRootCertificate {
  param(
    [string]$ProfileDir,
    [string]$RootCertificatePath,
    [string]$RootNickname,
    [string]$CertutilPath
  )

  if ([string]::IsNullOrWhiteSpace($RootCertificatePath)) {
    return
  }

  $resolvedRootCertificatePath = [System.IO.Path]::GetFullPath($RootCertificatePath)
  if (-not (Test-Path -LiteralPath $resolvedRootCertificatePath)) {
    throw "Root certificate not found at: $resolvedRootCertificatePath"
  }

  $dbPath = "sql:{0}" -f $ProfileDir
  $certDbPath = Join-Path $ProfileDir "cert9.db"
  $keyDbPath = Join-Path $ProfileDir "key4.db"

  if (-not (Test-Path -LiteralPath $certDbPath) -or -not (Test-Path -LiteralPath $keyDbPath)) {
    & $CertutilPath -N -d $dbPath --empty-password | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "Failed to initialize NSS certificate database in $ProfileDir"
    }
  }

  & $CertutilPath -D -d $dbPath -n $RootNickname 2>$null | Out-Null
  & $CertutilPath -A -d $dbPath -n $RootNickname -t "C,," -i $resolvedRootCertificatePath | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to import trusted root certificate into $ProfileDir"
  }
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
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
if ([string]::IsNullOrWhiteSpace($SignerCertificatePath)) {
  $SignerCertificatePath = Join-Path $repoRoot "security\manager\ssl\tests\unit\bad_certs\default-ee.pem"
}

$ProfileDir = [System.IO.Path]::GetFullPath($ProfileDir)
$BundlePath = [System.IO.Path]::GetFullPath($BundlePath)
$TelemetryPath = [System.IO.Path]::GetFullPath($TelemetryPath)
$SignerCertificatePath = [System.IO.Path]::GetFullPath($SignerCertificatePath)

[System.IO.Directory]::CreateDirectory($ProfileDir) | Out-Null

$signerFingerprint = Get-Sha256FingerprintHex -Certificate (Read-Certificate -Path $SignerCertificatePath)
$jsBundlePath = ConvertTo-JsString -Value $BundlePath
$jsTelemetryPath = ConvertTo-JsString -Value $TelemetryPath
$jsSignerFingerprint = ConvertTo-JsString -Value $signerFingerprint

$userJsPath = Join-Path $ProfileDir "user.js"
$prefs = @(
  'user_pref("security.aegis.enterprise_policy.bundle_path", "' + $jsBundlePath + '");',
  'user_pref("security.aegis.enterprise_policy.allowed_signer_fingerprints_sha256", "' + $jsSignerFingerprint + '");',
  'user_pref("security.aegis.telemetry.log_path", "' + $jsTelemetryPath + '");'
)

Set-Content -LiteralPath $userJsPath -Value ($prefs -join [Environment]::NewLine) -Encoding ascii
Set-Content -LiteralPath $TelemetryPath -Value "" -Encoding utf8 -NoNewline

$resolvedCertutilPath = Resolve-NssCertutilPath -PreferredPath $CertutilPath -RepoRoot $repoRoot
Import-TrustedRootCertificate `
  -ProfileDir $ProfileDir `
  -RootCertificatePath $RootCertificatePath `
  -RootNickname $RootNickname `
  -CertutilPath $resolvedCertutilPath

Write-Output "Created:"
Write-Output "  profile: $ProfileDir"
Write-Output "  user.js: $userJsPath"
Write-Output "Configured:"
Write-Output "  bundle: $BundlePath"
Write-Output "  signer fingerprint: $signerFingerprint"
Write-Output "  telemetry log: $TelemetryPath"
if (-not [string]::IsNullOrWhiteSpace($RootCertificatePath)) {
  Write-Output "  trusted root: $([System.IO.Path]::GetFullPath($RootCertificatePath))"
  Write-Output "  NSS certutil: $resolvedCertutilPath"
}
