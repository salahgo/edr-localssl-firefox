/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <memory>

#include "EnterpriseBundleLoader.h"

#include "EnterpriseCertUtils.h"
#include "ScopedNSSTypes.h"
#include "cert.h"
#include "json/json.h"
#include "mozilla/Base64.h"
#include "mozpkix/pkixnss.h"
#include "mozpkix/pkixutil.h"
#include "nsComponentManagerUtils.h"
#include "nsIFile.h"
#include "nsIFileStreams.h"
#include "nsNetUtil.h"

namespace mozilla::psm::enterprise {

using namespace mozilla::pkix;

namespace {

bool ReadStringMember(const Json::Value& aObject, const char* aName,
                      nsCString& aOutValue, bool aRequired = false) {
  if (!aObject.isMember(aName)) {
    return !aRequired;
  }
  const Json::Value& value = aObject[aName];
  if (!value.isString()) {
    return false;
  }
  aOutValue.Assign(value.asCString());
  return true;
}

bool ReadBoolMember(const Json::Value& aObject, const char* aName,
                    bool& aOutValue) {
  if (!aObject.isMember(aName)) {
    return true;
  }
  const Json::Value& value = aObject[aName];
  if (!value.isBool()) {
    return false;
  }
  aOutValue = value.asBool();
  return true;
}

bool ReadUIntMember(const Json::Value& aObject, const char* aName,
                    uint32_t& aOutValue) {
  if (!aObject.isMember(aName)) {
    return true;
  }
  const Json::Value& value = aObject[aName];
  if (!value.isUInt()) {
    return false;
  }
  aOutValue = value.asUInt();
  return true;
}

bool ReadStringArray(const Json::Value& aObject, const char* aName,
                     nsTArray<nsCString>& aOutArray) {
  if (!aObject.isMember(aName)) {
    return true;
  }
  const Json::Value& value = aObject[aName];
  if (!value.isArray()) {
    return false;
  }
  for (const auto& entry : value) {
    if (!entry.isString()) {
      return false;
    }
    aOutArray.AppendElement(nsCString(entry.asCString()));
  }
  return true;
}

bool ReadJsonFile(const nsAString& aBundlePath, nsCString& aOutContents) {
  nsCOMPtr<nsIFile> bundleFile;
  nsresult rv = NS_NewLocalFile(aBundlePath, getter_AddRefs(bundleFile));
  if (NS_FAILED(rv) || !bundleFile) {
    return false;
  }

  bool exists = false;
  if (NS_FAILED(bundleFile->Exists(&exists)) || !exists) {
    return false;
  }

  int64_t fileSize = 0;
  if (NS_FAILED(bundleFile->GetFileSize(&fileSize)) || fileSize < 0 ||
      fileSize > INT32_MAX) {
    return false;
  }

  nsCOMPtr<nsIInputStream> stream;
  rv = NS_NewLocalFileInputStream(getter_AddRefs(stream), bundleFile);
  if (NS_FAILED(rv) || !stream) {
    return false;
  }

  aOutContents.Truncate();
  rv = NS_ReadInputStreamToString(stream, aOutContents,
                                  static_cast<uint32_t>(fileSize));
  return NS_SUCCEEDED(rv);
}

bool ParseJSON(const nsCString& aData, Json::Value& aOutRoot) {
  Json::CharReaderBuilder builder;
  builder["collectComments"] = false;
  std::string errors;
  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
  return reader->parse(aData.BeginReading(),
                       aData.BeginReading() + aData.Length(), &aOutRoot,
                       &errors);
}

bool DecodePEMCertificate(const nsCString& aPEM, nsTArray<uint8_t>& aOutDER) {
  nsCString base64(aPEM);
  base64.ReplaceSubstring("-----BEGIN CERTIFICATE-----"_ns, ""_ns);
  base64.ReplaceSubstring("-----END CERTIFICATE-----"_ns, ""_ns);
  base64.ReplaceSubstring("\r"_ns, ""_ns);
  base64.ReplaceSubstring("\n"_ns, ""_ns);

  nsAutoCString decoded;
  if (NS_FAILED(Base64Decode(base64, decoded))) {
    return false;
  }

  aOutDER.Clear();
  aOutDER.AppendElements(
      reinterpret_cast<const uint8_t*>(decoded.BeginReading()),
      decoded.Length());
  return true;
}

SignatureAlgorithm ParseSignatureAlgorithm(const nsCString& aAlgorithm,
                                           bool& aKnownAlgorithm) {
  aKnownAlgorithm = true;
  if (aAlgorithm.EqualsLiteral("rsa_pkcs1_sha256")) {
    return SignatureAlgorithm::RsaPkcs1Sha256;
  }
  if (aAlgorithm.EqualsLiteral("ecdsa_sha256")) {
    return SignatureAlgorithm::EcdsaSha256;
  }
  aKnownAlgorithm = false;
  return SignatureAlgorithm::RsaPkcs1Sha256;
}

bool VerifyDetachedSignature(const nsCString& aPayload,
                             const nsCString& aSignatureAlgorithm,
                             const nsCString& aSignatureBase64,
                             const nsCString& aSignerCertPEM,
                             const nsTArray<nsCString>& aAllowedSignerFPs,
                             nsCString& aOutSignerFingerprint) {
  nsTArray<uint8_t> signerDER;
  if (!DecodePEMCertificate(aSignerCertPEM, signerDER)) {
    return false;
  }

  if (NS_FAILED(ComputeFingerprintSha256Hex(signerDER, aOutSignerFingerprint)) ||
      !ContainsFingerprint(aAllowedSignerFPs, aOutSignerFingerprint)) {
    return false;
  }

  nsAutoCString signatureBytes;
  if (NS_FAILED(Base64Decode(aSignatureBase64, signatureBytes))) {
    return false;
  }

  Input payloadInput;
  if (payloadInput.Init(
          reinterpret_cast<const uint8_t*>(aPayload.BeginReading()),
          aPayload.Length()) != Success) {
    return false;
  }

  Input signatureInput;
  if (signatureInput.Init(
          reinterpret_cast<const uint8_t*>(signatureBytes.BeginReading()),
          signatureBytes.Length()) != Success) {
    return false;
  }

  Input certInput;
  if (certInput.Init(signerDER.Elements(), signerDER.Length()) != Success) {
    return false;
  }

  BackCert signerCert(certInput, EndEntityOrCA::MustBeEndEntity, nullptr);
  if (signerCert.Init() != Success) {
    return false;
  }

  bool knownAlgorithm = false;
  SignatureAlgorithm signatureAlgorithm =
      ParseSignatureAlgorithm(aSignatureAlgorithm, knownAlgorithm);
  if (!knownAlgorithm) {
    return false;
  }

  mozilla::pkix::Result rv = mozilla::pkix::Success;
  switch (signatureAlgorithm) {
    case SignatureAlgorithm::RsaPkcs1Sha256:
      rv = VerifyRSAPKCS1SignedDataNSS(
          payloadInput, mozilla::pkix::DigestAlgorithm::sha256,
                                        signatureInput,
                                        signerCert.GetSubjectPublicKeyInfo(),
                                        nullptr);
      break;
    case SignatureAlgorithm::EcdsaSha256:
      rv = VerifyECDSASignedDataNSS(
          payloadInput, mozilla::pkix::DigestAlgorithm::sha256,
                                     signatureInput,
                                     signerCert.GetSubjectPublicKeyInfo(),
                                     nullptr);
      break;
  }
  return rv == mozilla::pkix::Success;
}

bool ParseRevocationMode(const nsCString& aValue, RevocationMode& aOutMode) {
  if (aValue.IsEmpty() || aValue.EqualsLiteral("soft_fail")) {
    aOutMode = RevocationMode::SoftFail;
    return true;
  }
  if (aValue.EqualsLiteral("hard_fail")) {
    aOutMode = RevocationMode::HardFail;
    return true;
  }
  return false;
}

bool ParseEnforcementMode(const nsCString& aValue,
                          EnforcementMode& aOutMode) {
  if (aValue.IsEmpty() || aValue.EqualsLiteral("log_only")) {
    aOutMode = EnforcementMode::LogOnly;
    return true;
  }
  if (aValue.EqualsLiteral("block")) {
    aOutMode = EnforcementMode::Block;
    return true;
  }
  return false;
}

bool ParseRevocationOverrides(const Json::Value& aPayload,
                              nsTArray<RevocationOverride>& aOutOverrides) {
  if (!aPayload.isMember("revocation_overrides")) {
    return true;
  }
  const Json::Value& overrides = aPayload["revocation_overrides"];
  if (!overrides.isObject()) {
    return false;
  }
  for (const auto& member : overrides.getMemberNames()) {
    const Json::Value& modeValue = overrides[member];
    if (!modeValue.isString()) {
      return false;
    }
    RevocationOverride override;
    override.mHostnamePattern.Assign(member.c_str());
    if (!ParseRevocationMode(nsCString(modeValue.asCString()), override.mMode)) {
      return false;
    }
    aOutOverrides.AppendElement(std::move(override));
  }
  return true;
}

bool ParsePinsets(const Json::Value& aPayload, nsTArray<Pinset>& aOutPinsets) {
  if (!aPayload.isMember("pinsets")) {
    return true;
  }
  const Json::Value& pinsets = aPayload["pinsets"];
  if (!pinsets.isArray()) {
    return false;
  }
  for (const auto& pinsetValue : pinsets) {
    if (!pinsetValue.isObject()) {
      return false;
    }
    Pinset pinset;
    nsCString modeString;
    if (!ReadStringMember(pinsetValue, "hostname", pinset.mHostnamePattern,
                          true) ||
        !ReadStringArray(pinsetValue, "spki_sha256",
                         pinset.mSpkiSha256DigestsBase64) ||
        !ReadStringMember(pinsetValue, "mode", modeString, false) ||
        !ParseEnforcementMode(modeString, pinset.mMode)) {
      return false;
    }
    aOutPinsets.AppendElement(std::move(pinset));
  }
  return true;
}

bool ParseEnforcement(const Json::Value& aPayload,
                      EnforcementConfig& aOutEnforcement) {
  if (!aPayload.isMember("enforcement")) {
    return true;
  }
  const Json::Value& enforcement = aPayload["enforcement"];
  if (!enforcement.isObject()) {
    return false;
  }
  nsCString internalMode;
  nsCString publicMode;
  if (!ReadStringMember(enforcement, "internal_hostname_public_ca", internalMode,
                        false) ||
      !ReadStringMember(enforcement, "public_hostname_private_ca", publicMode,
                        false) ||
      !ParseEnforcementMode(internalMode,
                            aOutEnforcement.mInternalHostnamePublicCA) ||
      !ParseEnforcementMode(publicMode,
                            aOutEnforcement.mPublicHostnamePrivateCA)) {
    return false;
  }
  return true;
}

bool ParseTelemetry(const Json::Value& aPayload,
                    TelemetryConfig& aOutTelemetry) {
  if (!aPayload.isMember("telemetry")) {
    return true;
  }
  const Json::Value& telemetry = aPayload["telemetry"];
  if (!telemetry.isObject()) {
    return false;
  }
  nsCString logPath;
  if (!ReadBoolMember(telemetry, "enabled", aOutTelemetry.mEnabled) ||
      !ReadBoolMember(telemetry, "emit_successes",
                      aOutTelemetry.mEmitSuccesses) ||
      !ReadStringMember(telemetry, "log_path", logPath, false)) {
    return false;
  }
  aOutTelemetry.mLogPath.Assign(NS_ConvertUTF8toUTF16(logPath));
  return true;
}

bool BuildSnapshot(const Json::Value& aPayload, const nsACString& aProduct,
                   const nsACString& aProductVersion,
                   EnterprisePolicySnapshot& aOutSnapshot) {
  aOutSnapshot.mProduct = aProduct;
  aOutSnapshot.mProductVersion = aProductVersion;
  aOutSnapshot.mIntegrityStatus = "signature_valid"_ns;
  aOutSnapshot.mActive = true;

  nsCString revocationMode;
  if (!ReadStringMember(aPayload, "version", aOutSnapshot.mVersion, true) ||
      !ReadStringArray(aPayload, "enterprise_domains",
                       aOutSnapshot.mEnterpriseDomains) ||
      !ReadStringArray(aPayload, "approved_root_fingerprints_sha256",
                       aOutSnapshot.mApprovedRootFingerprintsSha256) ||
      !ReadStringArray(aPayload, "approved_intermediate_fingerprints_sha256",
                       aOutSnapshot.mApprovedIntermediateFingerprintsSha256) ||
      !ReadStringArray(aPayload, "required_eku", aOutSnapshot.mRequiredEKUs) ||
      !ReadBoolMember(aPayload, "require_san", aOutSnapshot.mRequireSAN) ||
      !ReadStringMember(aPayload, "revocation_mode", revocationMode, false) ||
      !ParseRevocationMode(revocationMode, aOutSnapshot.mRevocationMode) ||
      !ReadUIntMember(aPayload, "max_leaf_validity_days",
                      aOutSnapshot.mMaxLeafValidityDays) ||
      !ReadStringArray(aPayload, "required_policy_oids",
                       aOutSnapshot.mRequiredPolicyOids) ||
      !ParseRevocationOverrides(aPayload, aOutSnapshot.mRevocationOverrides) ||
      !ParsePinsets(aPayload, aOutSnapshot.mPinsets) ||
      !ParseEnforcement(aPayload, aOutSnapshot.mEnforcement) ||
      !ParseTelemetry(aPayload, aOutSnapshot.mTelemetry)) {
    return false;
  }

  return true;
}

}  // namespace

BundleLoadResult LoadEnterprisePolicyBundle(
    const nsAString& aBundlePath,
    const nsTArray<nsCString>& aAllowedSignerFingerprintsSha256,
    const nsACString& aProduct, const nsACString& aProductVersion) {
  BundleLoadResult loadResult;
  loadResult.mResolvedBundlePath.Assign(aBundlePath);

  if (aAllowedSignerFingerprintsSha256.IsEmpty()) {
    loadResult.mReasonCode = "missing_allowed_bundle_signers"_ns;
    return loadResult;
  }

  nsCString rawBundle;
  if (!ReadJsonFile(aBundlePath, rawBundle)) {
    loadResult.mReasonCode = "bundle_read_failed"_ns;
    return loadResult;
  }

  Json::Value bundleEnvelope;
  if (!ParseJSON(rawBundle, bundleEnvelope) || !bundleEnvelope.isObject()) {
    loadResult.mReasonCode = "bundle_parse_failed"_ns;
    return loadResult;
  }

  nsCString format;
  nsCString payloadString;
  if (!ReadStringMember(bundleEnvelope, "format", format, true) ||
      !format.EqualsLiteral("aegis-enterprise-policy-bundle/v1") ||
      !ReadStringMember(bundleEnvelope, "payload", payloadString, true) ||
      !bundleEnvelope.isMember("signature") ||
      !bundleEnvelope["signature"].isObject()) {
    loadResult.mReasonCode = "invalid_bundle_format"_ns;
    return loadResult;
  }

  const Json::Value& signature = bundleEnvelope["signature"];
  nsCString signatureAlgorithm;
  nsCString signatureBase64;
  nsCString signerCertPEM;
  if (!ReadStringMember(signature, "algorithm", signatureAlgorithm, true) ||
      !ReadStringMember(signature, "signature_base64", signatureBase64, true) ||
      !ReadStringMember(signature, "signer_cert_pem", signerCertPEM, true)) {
    loadResult.mReasonCode = "invalid_signature_metadata"_ns;
    return loadResult;
  }

  if (!VerifyDetachedSignature(payloadString, signatureAlgorithm,
                               signatureBase64, signerCertPEM,
                               aAllowedSignerFingerprintsSha256,
                               loadResult.mSignerFingerprintSha256)) {
    loadResult.mReasonCode = "signature_verification_failed"_ns;
    return loadResult;
  }

  Json::Value payload;
  if (!ParseJSON(payloadString, payload) || !payload.isObject()) {
    loadResult.mReasonCode = "payload_parse_failed"_ns;
    return loadResult;
  }

  EnterprisePolicySnapshot snapshot;
  if (!BuildSnapshot(payload, aProduct, aProductVersion, snapshot)) {
    loadResult.mReasonCode = "payload_validation_failed"_ns;
    return loadResult;
  }

  snapshot.mBundleSignerFingerprintSha256 = loadResult.mSignerFingerprintSha256;
  loadResult.mSuccess = true;
  loadResult.mReasonCode = "bundle_loaded"_ns;
  loadResult.mSnapshot.emplace(std::move(snapshot));
  return loadResult;
}

}  // namespace mozilla::psm::enterprise
