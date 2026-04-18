/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_psm_enterprise_EnterpriseTelemetryTypes_h
#define mozilla_psm_enterprise_EnterpriseTelemetryTypes_h

#include "nsString.h"
#include "nsTArray.h"

namespace mozilla::psm::enterprise {

enum class EventType : uint8_t {
  TLSValidationSuccessEnterprise = 0,
  TLSValidationFailureEnterprise = 1,
  TLSUnapprovedIssuer = 2,
  TLSRevokedCert = 3,
  TLSRevocationUnknown = 4,
  TLSInternalHostnamePublicCA = 5,
  TLSPublicHostnamePrivateCA = 6,
  TLSPinMismatch = 7,
  BrowserPolicySignatureFailure = 8,
  BrowserEnterpriseTrustStoreChanged = 9,
  ExtensionInstallOutsideAllowlist = 10,
  DangerousDownloadDetected = 11,
  RepeatedTLSFailuresSameHost = 12,
  UnexpectedIssuerChangeForInternalHost = 13,
};

enum class Severity : uint8_t {
  Info = 0,
  Warning = 1,
  Error = 2,
};

enum class ValidationResult : uint8_t {
  Allowed = 0,
  Blocked = 1,
  StockValidationFailed = 2,
};

struct EnterpriseTelemetryEvent {
  EventType mEventType = EventType::TLSValidationFailureEnterprise;
  Severity mSeverity = Severity::Error;
  ValidationResult mValidationResult = ValidationResult::Blocked;
  nsCString mReasonCode;
  nsCString mHostname;
  nsCString mUrl;
  nsCString mTrustSource;
  nsCString mCertSubject;
  nsTArray<nsCString> mCertSAN;
  nsCString mIssuerCN;
  nsCString mIssuerFingerprintSha256;
  nsCString mRootFingerprintSha256;
  nsTArray<nsCString> mPolicyOids;
  nsCString mRevocationStatus;

  EnterpriseTelemetryEvent() = default;
  EnterpriseTelemetryEvent(const EnterpriseTelemetryEvent& aOther) {
    *this = aOther;
  }
  EnterpriseTelemetryEvent& operator=(const EnterpriseTelemetryEvent& aOther) {
    if (this == &aOther) {
      return *this;
    }
    mEventType = aOther.mEventType;
    mSeverity = aOther.mSeverity;
    mValidationResult = aOther.mValidationResult;
    mReasonCode = aOther.mReasonCode;
    mHostname = aOther.mHostname;
    mUrl = aOther.mUrl;
    mTrustSource = aOther.mTrustSource;
    mCertSubject = aOther.mCertSubject;
    mCertSAN.Clear();
    mCertSAN.AppendElements(aOther.mCertSAN);
    mIssuerCN = aOther.mIssuerCN;
    mIssuerFingerprintSha256 = aOther.mIssuerFingerprintSha256;
    mRootFingerprintSha256 = aOther.mRootFingerprintSha256;
    mPolicyOids.Clear();
    mPolicyOids.AppendElements(aOther.mPolicyOids);
    mRevocationStatus = aOther.mRevocationStatus;
    return *this;
  }
};

const char* ToString(EventType aEventType);
const char* ToString(Severity aSeverity);
const char* ToString(ValidationResult aValidationResult);

}  // namespace mozilla::psm::enterprise

#endif  // mozilla_psm_enterprise_EnterpriseTelemetryTypes_h
