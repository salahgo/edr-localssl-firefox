# Aegis Local SSL Lab

This lab keeps everything local and gives you a repeatable way to check the behavior your Aegis patch adds.

If you want a lighter browser-visible HTTPS success case without EJBCA, use the separate [Aegis Nginx Local CA Lab](../aegis-nginx-ca-lab/README.md).

The fastest way to bootstrap the CA uses EJBCA itself. For a clean browser-visible HTTPS success case, prefer the optional `local-web` service on `https://localhost:4443/`.

Important: this patch does not replace normal NSS trust building. The CA still has to be trusted by the Firefox profile first. Aegis then decides whether that trusted private CA is allowed for the hostname you are visiting.

## What "working" looks like

With the same CA trusted in the Firefox profile:

- if the bundle approves that CA fingerprint for `localhost`, `aegis-telemetry.jsonl` records `tls_validation_success_enterprise`
- if the bundle omits that CA fingerprint, the same site is blocked for the internal hostname and the telemetry log records `tls_internal_hostname_public_ca` and `tls_validation_failure_enterprise`

That A/B check is the point of this lab.

Note: EJBCA's HTTPS/admin endpoint is not a reliable browser-visible success page for this check. In local quickstart mode it can still fail at a later handshake or admin-auth step even when Aegis has already accepted the server certificate. The telemetry log is the authoritative signal for the EJBCA endpoint. If you want a visible success page in the browser, issue a cert for the optional `local-web` service instead.

## Files

- `docker-compose.yml`: local EJBCA plus an optional Nginx HTTPS site
- `scripts/New-AegisLabCsr.ps1`: creates `site.key` and `site.csr` for the optional site
- `scripts/New-AegisPolicyBundle.ps1`: builds a signed Aegis bundle using the repo's existing xpcshell test signer key
- `scripts/Write-AegisFirefoxPrefs.ps1`: writes the prefs needed by your local Firefox build into a disposable profile

## Step 1

Start EJBCA:

```powershell
cd E:\Projects\edr-localssl-firefox\aegis-local-lab
docker compose up -d ejbca
docker compose logs -f ejbca
```

This compose file uses `TLS_SETUP_ENABLED="simple"` for a local-only lab. Per the official EJBCA container docs, that mode gives anyone with HTTPS access admin access, so do not expose it outside your machine.

Open:

```text
http://localhost:8080/ejbca/adminweb/
```

## Step 2

Download the EJBCA Management CA certificate and trust it in the test profile:

1. In EJBCA, open `RA Web`.
2. Open `CA Certificates and CRLs`.
3. For `Management CA`, download the PEM certificate.
4. Save it as `aegis-local-lab\generated\ManagementCA.pem`.

Then create the Aegis bundle:

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

Launch your local Firefox build with that profile:

```powershell
& 'E:\Projects\edr-localssl-firefox\obj-x86_64-pc-windows-msvc\dist\bin\firefox.exe' `
  -no-remote `
  -profile 'E:\Projects\edr-localssl-firefox\aegis-local-lab\generated\firefox-profile'
```

In that Firefox profile:

1. Open `Settings -> Privacy & Security -> Certificates -> View Certificates`.
2. On `Authorities`, import `aegis-local-lab\generated\ManagementCA.pem`.
3. Trust it to identify websites.

Now test the EJBCA certificate path by visiting:

```text
https://localhost:8443/ejbca/adminweb/
```

Expected results:

- with the default bundle, `aegis-local-lab\generated\aegis-telemetry.jsonl` should show `tls_validation_success_enterprise`
- with `-OmitRootApproval`, the same visit should log the enterprise-policy failure events
- the browser may still show a secure-connection failure on this EJBCA endpoint due to non-Aegis TLS/admin requirements

## Optional separate HTTPS site

If you want a clean browser-visible HTTPS success page instead of EJBCA's own server cert:

1. Generate a CSR and private key:

```powershell
.\scripts\New-AegisLabCsr.ps1
```

2. In EJBCA, create a TLS server profile and issue a server certificate for the CSR.
   Use the official EJBCA server-certificate tutorial as the guide for the profile and RA request flow.
3. Save the downloaded full chain PEM as `aegis-local-lab\generated\web\site.crt`.
   The private key is already in `aegis-local-lab\generated\web\site.key`.
4. Start the site:

```powershell
docker compose --profile web up -d local-web
```

5. Visit:

```text
https://localhost:4443/
```

If the certificate chains to the same Management CA, the same Aegis bundle should control whether it is allowed on the internal hostname `localhost`.

## Notes

- `New-AegisPolicyBundle.ps1` intentionally reuses the repo's local xpcshell signer key and certificate from `security/manager/ssl/tests/unit/bad_certs/`. That is only for this private lab.
- If you prefer trusting the CA through Windows instead of Firefox Authorities, import the root into the Windows trust store and use a Firefox profile where enterprise roots are enabled.

## References

- EJBCA Community container on Docker Hub: https://hub.docker.com/r/keyfactor/ejbca-ce
- EJBCA quick start with client-certificate setup: https://docs.keyfactor.com/ejbca/9.1.1/quick-start-guide-start-ejbca-container-with-clien
- EJBCA client certificate quick start, including downloading `ManagementCA.pem`: https://docs.keyfactor.com/how-to/latest/quick-start-issue-client-authentication-certificat
- EJBCA tutorial for issuing TLS server certificates from a CSR: https://docs.keyfactor.com/ejbca/9.2/tutorial-issue-tls-server-certificates-with-ejbca
