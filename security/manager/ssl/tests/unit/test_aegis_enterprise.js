/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

do_get_profile();

const certdb = Cc["@mozilla.org/security/x509certdb;1"].getService(
  Ci.nsIX509CertDB
);

const VALIDATION_TIME = 1767225600;
const BUNDLE_PATH_PREF = "security.aegis.enterprise_policy.bundle_path";
const SIGNERS_PREF =
  "security.aegis.enterprise_policy.allowed_signer_fingerprints_sha256";
const TELEMETRY_PATH_PREF = "security.aegis.telemetry.log_path";
const SIGNER_CERT_FILE = "bad_certs/default-ee.pem";
const SIGNER_KEY_FILE = "bad_certs/default-ee.key";
const SERVERAUTH_CERT_FILE = "bad_certs/nsCertTypeCriticalWithExtKeyUsage.pem";

let gSignerCertPem;
let gSignerFingerprint;
let gBadCertRootFingerprint;
let gOcspRootFingerprint;
let gOcspIntermediateFingerprint;

function normalizedFingerprint(cert) {
  return cert.sha256Fingerprint.replace(/:/g, "");
}

function pemFileToArrayBuffer(filename) {
  return new Uint8Array(
    stringToArray(atob(pemToBase64(readFile(do_get_file(filename, false)))))
  ).buffer;
}

async function signPayload(payloadString) {
  let key = await crypto.subtle.importKey(
    "pkcs8",
    pemFileToArrayBuffer(SIGNER_KEY_FILE),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  let signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    new TextEncoder().encode(payloadString)
  );
  return btoa(arrayToString(Array.from(new Uint8Array(signature))));
}

function makePolicy(overrides = {}) {
  let enforcement = Object.assign(
    {
      internal_hostname_public_ca: "block",
      public_hostname_private_ca: "block",
    },
    overrides.enforcement || {}
  );
  let policy = {
    version: "1.0.0-test",
    enterprise_domains: ["localhost"],
    approved_root_fingerprints_sha256: [],
    approved_intermediate_fingerprints_sha256: [],
    required_eku: ["serverAuth"],
    require_san: true,
    revocation_mode: "soft_fail",
    max_leaf_validity_days: 825,
    required_policy_oids: [],
    pinsets: [],
    enforcement,
  };
  return Object.assign(policy, overrides, { enforcement });
}

function profileFile(name) {
  let file = do_get_profile().clone();
  file.append(name);
  return file;
}

function writeStringToFile(file, contents) {
  let outputStream = FileUtils.openFileOutputStream(file);
  outputStream.write(contents, contents.length);
  outputStream.close();
}

async function writeBundle(
  name,
  payloadObject,
  { tamperPayload = false } = {}
) {
  let payloadString = JSON.stringify(payloadObject);
  let signature = await signPayload(payloadString);
  let envelopePayload = payloadString;
  if (tamperPayload) {
    let tamperedPayload = JSON.parse(payloadString);
    tamperedPayload.version += "-tampered";
    envelopePayload = JSON.stringify(tamperedPayload);
  }
  let bundleFile = profileFile(`${name}.bundle.json`);
  writeStringToFile(
    bundleFile,
    JSON.stringify({
      format: "aegis-enterprise-policy-bundle/v1",
      payload: envelopePayload,
      signature: {
        algorithm: "rsa_pkcs1_sha256",
        signature_base64: signature,
        signer_cert_pem: gSignerCertPem,
      },
    })
  );
  return bundleFile.path;
}

async function removeIfExists(path) {
  let file = new FileUtils.File(path);
  if (file.exists()) {
    file.remove(false);
  }
}

async function configureEnterprisePolicy(
  testName,
  payloadObject,
  { tamperPayload = false, allowedSignerFingerprint = gSignerFingerprint } = {}
) {
  let logPath = profileFile(`${testName}.log.jsonl`).path;
  await removeIfExists(logPath);
  for (let pref of [BUNDLE_PATH_PREF, SIGNERS_PREF, TELEMETRY_PATH_PREF]) {
    if (Services.prefs.prefHasUserValue(pref)) {
      Services.prefs.clearUserPref(pref);
    }
  }
  clearSessionCache();
  let bundlePath = await writeBundle(testName, payloadObject, {
    tamperPayload,
  });
  Services.prefs.setStringPref(TELEMETRY_PATH_PREF, logPath);
  Services.prefs.setCharPref(SIGNERS_PREF, allowedSignerFingerprint);
  Services.prefs.setStringPref(BUNDLE_PATH_PREF, bundlePath);
  clearSessionCache();
  return { bundlePath, logPath };
}

async function readEvents(logPath) {
  let logFile = new FileUtils.File(logPath);
  if (!logFile.exists()) {
    return [];
  }
  let contents = readFile(logFile);
  if (!contents.trim()) {
    return [];
  }
  return contents
    .trim()
    .split("\n")
    .map(line => JSON.parse(line));
}

function hasEvent(events, eventType, reasonCode = undefined) {
  return events.some(
    event =>
      event.event_type == eventType &&
      (reasonCode == undefined || event.reason_code == reasonCode)
  );
}

function ensureCertImported(filename, trustString) {
  try {
    addCertFromFile(certdb, filename, trustString);
  } catch (e) {}
}

add_setup(async function () {
  gSignerCertPem = readFile(do_get_file(SIGNER_CERT_FILE, false));
  gSignerFingerprint = normalizedFingerprint(
    constructCertFromFile(SIGNER_CERT_FILE)
  );
  gBadCertRootFingerprint = normalizedFingerprint(
    constructCertFromFile("bad_certs/test-ca.pem")
  );
  gOcspRootFingerprint = normalizedFingerprint(
    constructCertFromFile("ocsp_certs/test-ca.pem")
  );
  gOcspIntermediateFingerprint = normalizedFingerprint(
    constructCertFromFile("ocsp_certs/test-int.pem")
  );

  registerCleanupFunction(async () => {
    for (let pref of [BUNDLE_PATH_PREF, SIGNERS_PREF, TELEMETRY_PATH_PREF]) {
      Services.prefs.clearUserPref(pref);
    }
    clearSessionCache();
    let entries = do_get_profile().directoryEntries;
    while (entries.hasMoreElements()) {
      let file = entries.getNext().QueryInterface(Ci.nsIFile);
      let filename = file.leafName;
      if (
        filename.startsWith("test_aegis_enterprise_") &&
        (filename.endsWith(".bundle.json") || filename.endsWith(".log.jsonl"))
      ) {
        await removeIfExists(file.path);
      }
    }
  });
});

add_task(async function test_aegis_enterprise_internal_hostname_private_ca() {
  ensureCertImported("bad_certs/test-ca.pem", "CTu,,");

  let { logPath } = await configureEnterprisePolicy(
    "test_aegis_enterprise_internal_hostname_private_ca",
    makePolicy({
      enterprise_domains: ["localhost"],
      approved_root_fingerprints_sha256: [gBadCertRootFingerprint],
    })
  );

  await checkCertErrorGenericAtTime(
    certdb,
    constructCertFromFile(SERVERAUTH_CERT_FILE),
    PRErrorCodeSuccess,
    Ci.nsIX509CertDB.verifyUsageTLSServer,
    VALIDATION_TIME,
    undefined,
    "localhost"
  );

  let events = await readEvents(logPath);
  ok(
    hasEvent(events, "browser_enterprise_trust_store_changed"),
    "should log enterprise policy reload"
  );
  ok(
    hasEvent(events, "tls_validation_success_enterprise"),
    "should log enterprise validation success"
  );
});

add_task(
  async function test_aegis_enterprise_internal_hostname_public_ca_blocked() {
    ensureCertImported("bad_certs/test-ca.pem", "CTu,,");

    let { logPath } = await configureEnterprisePolicy(
      "test_aegis_enterprise_internal_hostname_public_ca_blocked",
      makePolicy({
        enterprise_domains: ["localhost"],
        approved_root_fingerprints_sha256: [],
      })
    );

    await checkCertErrorGenericAtTime(
      certdb,
      constructCertFromFile("bad_certs/default-ee.pem"),
      SEC_ERROR_POLICY_VALIDATION_FAILED,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      VALIDATION_TIME,
      undefined,
      "localhost"
    );

    let events = await readEvents(logPath);
    ok(
      hasEvent(events, "tls_internal_hostname_public_ca"),
      "should log private/public scope mismatch for internal host"
    );
    ok(
      hasEvent(
        events,
        "tls_validation_failure_enterprise",
        "internal_hostname_public_ca"
      ),
      "should log enterprise validation failure"
    );
  }
);

add_task(
  async function test_aegis_enterprise_public_hostname_private_ca_blocked() {
    ensureCertImported("bad_certs/test-ca.pem", "CTu,,");

    let { logPath } = await configureEnterprisePolicy(
      "test_aegis_enterprise_public_hostname_private_ca_blocked",
      makePolicy({
        enterprise_domains: ["corp.local"],
        approved_root_fingerprints_sha256: [gBadCertRootFingerprint],
      })
    );

    await checkCertErrorGenericAtTime(
      certdb,
      constructCertFromFile("bad_certs/default-ee.pem"),
      SEC_ERROR_POLICY_VALIDATION_FAILED,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      VALIDATION_TIME,
      undefined,
      "public.example.com"
    );

    let events = await readEvents(logPath);
    ok(
      hasEvent(events, "tls_public_hostname_private_ca"),
      "should log private CA use on public hostname"
    );
  }
);

add_task(async function test_aegis_enterprise_requires_san() {
  ensureCertImported("bad_certs/test-ca.pem", "CTu,,");

  let { logPath } = await configureEnterprisePolicy(
    "test_aegis_enterprise_requires_san",
    makePolicy({
      enterprise_domains: ["doesntmatch.example.com"],
      approved_root_fingerprints_sha256: [gBadCertRootFingerprint],
    })
  );

  await checkCertErrorGenericAtTime(
    certdb,
    constructCertFromFile("bad_certs/mismatchCN.pem"),
    SSL_ERROR_BAD_CERT_DOMAIN,
    Ci.nsIX509CertDB.verifyUsageTLSServer,
    VALIDATION_TIME,
    undefined,
    "doesntmatch.example.com"
  );

  let events = await readEvents(logPath);
  ok(
    hasEvent(events, "tls_validation_failure_enterprise"),
    "should log enterprise validation failure for missing SAN"
  );
});

add_task(async function test_aegis_enterprise_unapproved_issuer_blocked() {
  ensureCertImported("ocsp_certs/test-ca.pem", "CTu,,");
  ensureCertImported("ocsp_certs/test-int.pem", ",,");

  let { logPath } = await configureEnterprisePolicy(
    "test_aegis_enterprise_unapproved_issuer_blocked",
    makePolicy({
      enterprise_domains: ["app.example.com"],
      approved_root_fingerprints_sha256: [gOcspRootFingerprint],
      approved_intermediate_fingerprints_sha256: [
        gOcspIntermediateFingerprint + "00",
      ],
      required_eku: [],
    })
  );

  await checkCertErrorGenericAtTime(
    certdb,
    constructCertFromFile("ocsp_certs/ocspEEWithIntermediate.pem"),
    SEC_ERROR_POLICY_VALIDATION_FAILED,
    Ci.nsIX509CertDB.verifyUsageTLSServer,
    VALIDATION_TIME,
    undefined,
    "app.example.com"
  );

  let events = await readEvents(logPath);
  ok(hasEvent(events, "tls_unapproved_issuer"), "should log unapproved issuer");
});

add_task(async function test_aegis_enterprise_pin_mismatch_blocked() {
  ensureCertImported("bad_certs/test-ca.pem", "CTu,,");

  let { logPath } = await configureEnterprisePolicy(
    "test_aegis_enterprise_pin_mismatch_blocked",
    makePolicy({
      enterprise_domains: ["example.com"],
      approved_root_fingerprints_sha256: [gBadCertRootFingerprint],
      pinsets: [
        {
          hostname: "service.example.com",
          spki_sha256: ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
          mode: "block",
        },
      ],
    })
  );

  await checkCertErrorGenericAtTime(
    certdb,
    constructCertFromFile(SERVERAUTH_CERT_FILE),
    MOZILLA_PKIX_ERROR_KEY_PINNING_FAILURE,
    Ci.nsIX509CertDB.verifyUsageTLSServer,
    VALIDATION_TIME,
    undefined,
    "service.example.com"
  );

  let events = await readEvents(logPath);
  ok(hasEvent(events, "tls_pin_mismatch"), "should log SPKI pin mismatch");
});

add_task(
  async function test_aegis_enterprise_reload_resets_host_observations() {
    ensureCertImported("bad_certs/test-ca.pem", "CTu,,");

    let testName = "test_aegis_enterprise_reload_resets_host_observations";
    let policy = makePolicy({
      enterprise_domains: ["localhost"],
      approved_root_fingerprints_sha256: [],
    });

    await configureEnterprisePolicy(testName, policy);

    for (let i = 0; i < 2; i++) {
      await checkCertErrorGenericAtTime(
        certdb,
        constructCertFromFile("bad_certs/default-ee.pem"),
        SEC_ERROR_POLICY_VALIDATION_FAILED,
        Ci.nsIX509CertDB.verifyUsageTLSServer,
        VALIDATION_TIME,
        undefined,
        "localhost"
      );
    }

    let { logPath } = await configureEnterprisePolicy(testName, policy);

    await checkCertErrorGenericAtTime(
      certdb,
      constructCertFromFile("bad_certs/default-ee.pem"),
      SEC_ERROR_POLICY_VALIDATION_FAILED,
      Ci.nsIX509CertDB.verifyUsageTLSServer,
      VALIDATION_TIME,
      undefined,
      "localhost"
    );

    let events = await readEvents(logPath);
    ok(
      !hasEvent(events, "repeated_tls_failures_same_host"),
      "should clear per-host failure observations on policy reload"
    );
  }
);

add_task(async function test_aegis_enterprise_tampered_bundle_rejected() {
  ensureCertImported("bad_certs/test-ca.pem", "CTu,,");

  let { logPath } = await configureEnterprisePolicy(
    "test_aegis_enterprise_tampered_bundle_rejected",
    makePolicy({
      enterprise_domains: ["localhost"],
      approved_root_fingerprints_sha256: [gBadCertRootFingerprint],
    }),
    { tamperPayload: true }
  );

  await checkCertErrorGenericAtTime(
    certdb,
    constructCertFromFile("bad_certs/default-ee.pem"),
    PRErrorCodeSuccess,
    Ci.nsIX509CertDB.verifyUsageTLSServer,
    VALIDATION_TIME,
    undefined,
    "localhost"
  );

  let events = await readEvents(logPath);
  ok(
    hasEvent(events, "browser_policy_signature_failure"),
    "should log tampered bundle rejection"
  );
});
