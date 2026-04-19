# Aegis Nginx Local CA Lab

This is the simpler second lab for Aegis. It gives you a browser-visible HTTPS success case using Docker Compose, Nginx, and a lab-local root CA issued entirely on your machine.

Use this lab when you want the page at `https://localhost:4445/` to look secure in Firefox even though the certificate was created locally.

Important: Aegis does not replace normal NSS trust building. The local root CA still has to be trusted by the Firefox profile first. In this lab, `scripts\Write-AegisFirefoxPrefs.ps1` does that automatically for the generated profile. Aegis then decides whether that trusted private CA is allowed for the hostname you are visiting.

## What "working" looks like

With the same local CA trusted in the Firefox profile:

- with the default bundle, `https://localhost:4445/` loads normally and `generated\aegis-telemetry.jsonl` records `tls_validation_success_enterprise`
- with `-OmitRootApproval`, the same site is blocked for the internal hostname and the telemetry log records `tls_internal_hostname_public_ca` and `tls_validation_failure_enterprise`

This lab is meant to make that difference visible in the browser chrome as well as in telemetry.

## Files

- `docker-compose.yml`: one-shot certificate bootstrap plus the Nginx HTTPS site
- `scripts/generate-certs.sh`: creates a local root CA and a `localhost` server certificate inside `generated\certs`
- `scripts/New-AegisPolicyBundle.ps1`: wrapper that builds an Aegis bundle approving this lab's root CA
- `scripts/Write-AegisFirefoxPrefs.ps1`: wrapper that writes the Aegis prefs into this lab's disposable Firefox profile

## Step 1

Generate the local CA and site certificate:

```powershell
cd E:\Projects\edr-localssl-firefox\aegis-nginx-ca-lab
docker compose run --rm cert-init
```

This creates:

- `generated\certs\rootCA.pem`
- `generated\certs\rootCA.key`
- `generated\certs\site.crt`
- `generated\certs\site.key`
- `generated\certs\site.fullchain.crt`

## Step 2

Build the Aegis bundle that approves this local CA for `localhost`:

```powershell
.\scripts\New-AegisPolicyBundle.ps1
```

To prove the block path, rebuild the bundle without approving the root:

```powershell
.\scripts\New-AegisPolicyBundle.ps1 -OmitRootApproval
```

## Step 3

Write a clean Firefox profile for this lab:

```powershell
.\scripts\Write-AegisFirefoxPrefs.ps1
```

That script also imports `generated\certs\rootCA.pem` into the profile's NSS certificate database, so Firefox already trusts the lab CA on first launch.

Launch your local Firefox build with that profile:

```powershell
& 'E:\Projects\edr-localssl-firefox\obj-x86_64-pc-windows-msvc\dist\bin\firefox.exe' `
  -no-remote `
  -profile 'E:\Projects\edr-localssl-firefox\aegis-nginx-ca-lab\generated\firefox-profile'
```

## Step 4

Start the HTTPS site:

```powershell
docker compose up -d local-web
```

Visit:

```text
https://localhost:4445/
```

Expected results:

- with the default bundle, the page should load normally and show a secure connection
- `aegis-nginx-ca-lab\generated\aegis-telemetry.jsonl` should show `tls_validation_success_enterprise`
- with `-OmitRootApproval`, the same visit should be blocked by enterprise policy and log the failure events

## Notes

- This lab reuses the repo's local xpcshell signer key and certificate from `security/manager/ssl/tests/unit/bad_certs/`. That is only for this private lab.
- If you want the heavier EJBCA workflow as well, keep using [aegis-local-lab](../aegis-local-lab/README.md).
