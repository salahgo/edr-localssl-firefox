param(
  [string[]]$DnsNames = @("localhost"),
  [string]$CommonName = "localhost",
  [string]$OutputDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-Pem {
  param(
    [string]$Label,
    [byte[]]$Bytes
  )

  $base64 = [Convert]::ToBase64String($Bytes)
  $lines = for ($i = 0; $i -lt $base64.Length; $i += 64) {
    $count = [Math]::Min(64, $base64.Length - $i)
    $base64.Substring($i, $count)
  }
  $body = $lines -join [Environment]::NewLine
  return "-----BEGIN $Label-----$([Environment]::NewLine)$body$([Environment]::NewLine)-----END $Label-----$([Environment]::NewLine)"
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
  $OutputDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\generated\web"))
} else {
  $OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
}

[System.IO.Directory]::CreateDirectory($OutputDir) | Out-Null

$keyPath = Join-Path $OutputDir "site.key"
$csrPath = Join-Path $OutputDir "site.csr"

$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$dn = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=$CommonName")
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
  $dn,
  $rsa,
  [System.Security.Cryptography.HashAlgorithmName]::SHA256,
  [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)

$keyUsage =
  [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature `
  -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
$request.CertificateExtensions.Add(
  [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($keyUsage, $true)
)

$ekuOids = [System.Security.Cryptography.OidCollection]::new()
$null = $ekuOids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1", "Server Authentication"))
$request.CertificateExtensions.Add(
  [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $false)
)

$request.CertificateExtensions.Add(
  [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
)

$sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
foreach ($dnsName in $DnsNames) {
  $sanBuilder.AddDnsName($dnsName)
}
$request.CertificateExtensions.Add($sanBuilder.Build($false))

$privateKeyPem = $rsa.ExportPkcs8PrivateKeyPem()
$csrPem = ConvertTo-Pem -Label "CERTIFICATE REQUEST" -Bytes $request.CreateSigningRequest()

Set-Content -LiteralPath $keyPath -Value $privateKeyPem -Encoding ascii -NoNewline
Set-Content -LiteralPath $csrPath -Value $csrPem -Encoding ascii -NoNewline

Write-Output "Created:"
Write-Output "  key: $keyPath"
Write-Output "  csr: $csrPath"
