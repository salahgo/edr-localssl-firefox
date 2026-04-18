/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_psm_enterprise_EnterprisePolicyTypes_h
#define mozilla_psm_enterprise_EnterprisePolicyTypes_h

#include "mozilla/Maybe.h"
#include "nsString.h"
#include "nsTArray.h"

namespace mozilla::psm::enterprise {

enum class RevocationMode : uint8_t {
  SoftFail = 0,
  HardFail = 1,
};

enum class EnforcementMode : uint8_t {
  LogOnly = 0,
  Block = 1,
};

enum class SignatureAlgorithm : uint8_t {
  RsaPkcs1Sha256 = 0,
  EcdsaSha256 = 1,
};

struct RevocationOverride {
  nsCString mHostnamePattern;
  RevocationMode mMode = RevocationMode::SoftFail;
};

struct Pinset {
  nsCString mHostnamePattern;
  nsTArray<nsCString> mSpkiSha256DigestsBase64;
  EnforcementMode mMode = EnforcementMode::Block;

  Pinset() = default;
  Pinset(const Pinset& aOther) { *this = aOther; }
  Pinset& operator=(const Pinset& aOther) {
    if (this == &aOther) {
      return *this;
    }
    mHostnamePattern = aOther.mHostnamePattern;
    mSpkiSha256DigestsBase64.Clear();
    mSpkiSha256DigestsBase64.AppendElements(aOther.mSpkiSha256DigestsBase64);
    mMode = aOther.mMode;
    return *this;
  }
};

struct TelemetryConfig {
  bool mEnabled = true;
  bool mEmitSuccesses = true;
  nsString mLogPath;
};

struct EnforcementConfig {
  EnforcementMode mInternalHostnamePublicCA = EnforcementMode::Block;
  EnforcementMode mPublicHostnamePrivateCA = EnforcementMode::Block;
};

struct EnterprisePolicySnapshot {
  bool mActive = false;
  nsCString mVersion;
  nsCString mBundleSignerFingerprintSha256;
  nsCString mIntegrityStatus;
  nsCString mProduct;
  nsCString mProductVersion;
  nsTArray<nsCString> mEnterpriseDomains;
  nsTArray<nsCString> mApprovedRootFingerprintsSha256;
  nsTArray<nsCString> mApprovedIntermediateFingerprintsSha256;
  nsTArray<nsCString> mRequiredEKUs;
  bool mRequireSAN = true;
  RevocationMode mRevocationMode = RevocationMode::SoftFail;
  nsTArray<RevocationOverride> mRevocationOverrides;
  uint32_t mMaxLeafValidityDays = 825;
  nsTArray<nsCString> mRequiredPolicyOids;
  nsTArray<Pinset> mPinsets;
  EnforcementConfig mEnforcement;
  TelemetryConfig mTelemetry;

  EnterprisePolicySnapshot() = default;
  EnterprisePolicySnapshot(const EnterprisePolicySnapshot& aOther) {
    *this = aOther;
  }
  EnterprisePolicySnapshot& operator=(const EnterprisePolicySnapshot& aOther) {
    if (this == &aOther) {
      return *this;
    }
    mActive = aOther.mActive;
    mVersion = aOther.mVersion;
    mBundleSignerFingerprintSha256 = aOther.mBundleSignerFingerprintSha256;
    mIntegrityStatus = aOther.mIntegrityStatus;
    mProduct = aOther.mProduct;
    mProductVersion = aOther.mProductVersion;
    mEnterpriseDomains.Clear();
    mEnterpriseDomains.AppendElements(aOther.mEnterpriseDomains);
    mApprovedRootFingerprintsSha256.Clear();
    mApprovedRootFingerprintsSha256.AppendElements(
        aOther.mApprovedRootFingerprintsSha256);
    mApprovedIntermediateFingerprintsSha256.Clear();
    mApprovedIntermediateFingerprintsSha256.AppendElements(
        aOther.mApprovedIntermediateFingerprintsSha256);
    mRequiredEKUs.Clear();
    mRequiredEKUs.AppendElements(aOther.mRequiredEKUs);
    mRequireSAN = aOther.mRequireSAN;
    mRevocationMode = aOther.mRevocationMode;
    mRevocationOverrides.Clear();
    mRevocationOverrides.AppendElements(aOther.mRevocationOverrides);
    mMaxLeafValidityDays = aOther.mMaxLeafValidityDays;
    mRequiredPolicyOids.Clear();
    mRequiredPolicyOids.AppendElements(aOther.mRequiredPolicyOids);
    mPinsets.Clear();
    mPinsets.AppendElements(aOther.mPinsets);
    mEnforcement = aOther.mEnforcement;
    mTelemetry = aOther.mTelemetry;
    return *this;
  }

  bool IsActive() const { return mActive; }
};

struct BundleLoadResult {
  bool mSuccess = false;
  nsCString mReasonCode;
  nsString mResolvedBundlePath;
  nsCString mSignerFingerprintSha256;
  Maybe<EnterprisePolicySnapshot> mSnapshot;
};

}  // namespace mozilla::psm::enterprise

#endif  // mozilla_psm_enterprise_EnterprisePolicyTypes_h
