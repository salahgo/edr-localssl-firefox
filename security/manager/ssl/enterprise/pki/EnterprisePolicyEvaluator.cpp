/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "EnterprisePolicyEvaluator.h"

#include "mozpkix/Time.h"

namespace mozilla::psm::enterprise {

namespace pkix = mozilla::pkix;

namespace {

EnterpriseTelemetryEvent MakeEvent(
    EventType aEventType, Severity aSeverity, ValidationResult aValidationResult,
    const nsACString& aReasonCode, const nsACString& aHostname,
    const nsACString& aTrustSource, const EnterpriseChainInfo& aChainInfo,
    const nsACString& aRevocationStatus) {
  EnterpriseTelemetryEvent event;
  event.mEventType = aEventType;
  event.mSeverity = aSeverity;
  event.mValidationResult = aValidationResult;
  event.mReasonCode = aReasonCode;
  event.mHostname = aHostname;
  event.mUrl = "https://"_ns + nsCString(aHostname) + "/"_ns;
  event.mTrustSource = aTrustSource;
  event.mCertSubject = aChainInfo.mLeaf.mSubject;
  event.mCertSAN = aChainInfo.mLeaf.mSubjectAltNames.Clone();
  event.mIssuerCN = aChainInfo.mImmediateIssuerCommonName;
  event.mIssuerFingerprintSha256 = aChainInfo.mImmediateIssuerFingerprintSha256;
  event.mRootFingerprintSha256 = aChainInfo.mRootFingerprintSha256;
  event.mPolicyOids = aChainInfo.mLeaf.mPolicyOids.Clone();
  event.mRevocationStatus = aRevocationStatus;
  return event;
}

bool HostInInternalScope(const EnterprisePolicySnapshot& aPolicy,
                         const nsACString& aHostname) {
  for (const auto& pattern : aPolicy.mEnterpriseDomains) {
    if (MatchesHostnamePattern(aHostname, pattern)) {
      return true;
    }
  }
  return false;
}

const Pinset* FindMatchingPinset(const EnterprisePolicySnapshot& aPolicy,
                                 const nsACString& aHostname) {
  for (const auto& pinset : aPolicy.mPinsets) {
    if (MatchesHostnamePattern(aHostname, pinset.mHostnamePattern)) {
      return &pinset;
    }
  }
  return nullptr;
}

bool HasRequiredEKUs(const EnterprisePolicySnapshot& aPolicy,
                     const EnterpriseChainInfo& aChainInfo) {
  if (aPolicy.mRequiredEKUs.IsEmpty()) {
    return true;
  }
  for (const auto& eku : aPolicy.mRequiredEKUs) {
    if (eku.EqualsLiteral("serverAuth") &&
        !aChainInfo.mLeaf.mHasServerAuthEku) {
      return false;
    }
  }
  return true;
}

bool ImmediateIssuerApproved(const EnterprisePolicySnapshot& aPolicy,
                             const EnterpriseChainInfo& aChainInfo) {
  return ContainsFingerprint(aPolicy.mApprovedRootFingerprintsSha256,
                             aChainInfo.mImmediateIssuerFingerprintSha256) ||
         ContainsFingerprint(aPolicy.mApprovedIntermediateFingerprintsSha256,
                             aChainInfo.mImmediateIssuerFingerprintSha256);
}

}  // namespace

EnterpriseEvaluationResult EvaluateEnterpriseTlsConnection(
    const EnterprisePolicySnapshot& aPolicy, const nsACString& aHostname,
    const nsTArray<nsTArray<uint8_t>>& aBuiltChain) {
  EnterpriseEvaluationResult result;

  if (!aPolicy.IsActive()) {
    return result;
  }

  result.mInternalHostname = HostInInternalScope(aPolicy, aHostname);
  nsresult rv = ExtractEnterpriseChainInfo(aBuiltChain, result.mChainInfo);
  if (NS_FAILED(rv)) {
    result.mResult = pkix::Result::ERROR_POLICY_VALIDATION_FAILED;
    result.mReasonCode = "unable_to_parse_built_chain"_ns;
    result.mAppliedEnterprisePolicy = true;
    return result;
  }

  bool rootApproved = ContainsFingerprint(aPolicy.mApprovedRootFingerprintsSha256,
                                          result.mChainInfo.mRootFingerprintSha256);
  bool issuerApproved = ImmediateIssuerApproved(aPolicy, result.mChainInfo);
  result.mPrivateChain = rootApproved || issuerApproved;
  result.mTrustSource =
      result.mPrivateChain ? "enterprise_private_pki"_ns : "public_web_pki"_ns;
  result.mRevocationStatus = "stock_passed"_ns;

  if (!result.mInternalHostname) {
    if (!result.mPrivateChain) {
      return result;
    }
    result.mAppliedEnterprisePolicy = true;
    result.mReasonCode = "public_hostname_private_ca"_ns;
    auto mismatchEvent = MakeEvent(
        EventType::TLSPublicHostnamePrivateCA, Severity::Warning,
        aPolicy.mEnforcement.mPublicHostnamePrivateCA == EnforcementMode::Block
            ? ValidationResult::Blocked
            : ValidationResult::Allowed,
        result.mReasonCode, aHostname, result.mTrustSource, result.mChainInfo,
        result.mRevocationStatus);
    result.mEvents.AppendElement(std::move(mismatchEvent));
    if (aPolicy.mEnforcement.mPublicHostnamePrivateCA ==
        EnforcementMode::Block) {
      result.mResult = pkix::Result::ERROR_POLICY_VALIDATION_FAILED;
      result.mEvents.AppendElement(MakeEvent(
          EventType::TLSValidationFailureEnterprise, Severity::Error,
          ValidationResult::Blocked, result.mReasonCode, aHostname,
          result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
    }
    return result;
  }

  result.mAppliedEnterprisePolicy = true;
  if (!result.mPrivateChain) {
    result.mReasonCode = "internal_hostname_public_ca"_ns;
    result.mEvents.AppendElement(MakeEvent(
        EventType::TLSInternalHostnamePublicCA, Severity::Warning,
        aPolicy.mEnforcement.mInternalHostnamePublicCA == EnforcementMode::Block
            ? ValidationResult::Blocked
            : ValidationResult::Allowed,
        result.mReasonCode, aHostname, result.mTrustSource, result.mChainInfo,
        result.mRevocationStatus));
    if (aPolicy.mEnforcement.mInternalHostnamePublicCA ==
        EnforcementMode::Block) {
      result.mResult = pkix::Result::ERROR_POLICY_VALIDATION_FAILED;
      result.mEvents.AppendElement(MakeEvent(
          EventType::TLSValidationFailureEnterprise, Severity::Error,
          ValidationResult::Blocked, result.mReasonCode, aHostname,
          result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
    }
    return result;
  }

  if (aPolicy.mRequireSAN) {
    pkix::Result sanResult =
        CheckStrictSubjectAltName(aBuiltChain[0], aHostname);
    if (sanResult != pkix::Success) {
      result.mResult = pkix::Result::ERROR_BAD_CERT_DOMAIN;
      result.mReasonCode = "missing_or_mismatched_san"_ns;
      result.mEvents.AppendElement(MakeEvent(
          EventType::TLSValidationFailureEnterprise, Severity::Error,
          ValidationResult::Blocked, result.mReasonCode, aHostname,
          result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
      return result;
    }
  }

  if (!HasRequiredEKUs(aPolicy, result.mChainInfo)) {
    result.mResult = pkix::Result::ERROR_INADEQUATE_CERT_TYPE;
    result.mReasonCode = "missing_required_eku"_ns;
    result.mEvents.AppendElement(MakeEvent(
        EventType::TLSValidationFailureEnterprise, Severity::Error,
        ValidationResult::Blocked, result.mReasonCode, aHostname,
        result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
    return result;
  }

  if (!result.mChainInfo.mLeaf.mHasSuitableKeyUsage) {
    result.mResult = pkix::Result::ERROR_INADEQUATE_KEY_USAGE;
    result.mReasonCode = "unsuitable_key_usage"_ns;
    result.mEvents.AppendElement(MakeEvent(
        EventType::TLSValidationFailureEnterprise, Severity::Error,
        ValidationResult::Blocked, result.mReasonCode, aHostname,
        result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
    return result;
  }

  if (!issuerApproved) {
    result.mResult = pkix::Result::ERROR_POLICY_VALIDATION_FAILED;
    result.mReasonCode = "unapproved_issuer"_ns;
    result.mEvents.AppendElement(MakeEvent(
        EventType::TLSUnapprovedIssuer, Severity::Error,
        ValidationResult::Blocked, result.mReasonCode, aHostname,
        result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
    result.mEvents.AppendElement(MakeEvent(
        EventType::TLSValidationFailureEnterprise, Severity::Error,
        ValidationResult::Blocked, result.mReasonCode, aHostname,
        result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
    return result;
  }

  if (!HasRequiredPolicyOids(result.mChainInfo.mLeaf,
                             aPolicy.mRequiredPolicyOids)) {
    result.mResult = pkix::Result::ERROR_POLICY_VALIDATION_FAILED;
    result.mReasonCode = "missing_required_policy_oid"_ns;
    result.mEvents.AppendElement(MakeEvent(
        EventType::TLSValidationFailureEnterprise, Severity::Error,
        ValidationResult::Blocked, result.mReasonCode, aHostname,
        result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
    return result;
  }

  if (aPolicy.mMaxLeafValidityDays > 0) {
    pkix::Duration leafValidity(result.mChainInfo.mLeaf.mNotBefore,
                                result.mChainInfo.mLeaf.mNotAfter);
    pkix::Duration maxValidity(
        uint64_t(aPolicy.mMaxLeafValidityDays) * pkix::Time::ONE_DAY_IN_SECONDS);
    if (leafValidity > maxValidity) {
      result.mResult = pkix::Result::ERROR_POLICY_VALIDATION_FAILED;
      result.mReasonCode = "leaf_validity_exceeds_policy"_ns;
      result.mEvents.AppendElement(MakeEvent(
          EventType::TLSValidationFailureEnterprise, Severity::Error,
          ValidationResult::Blocked, result.mReasonCode, aHostname,
          result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
      return result;
    }
  }

  const Pinset* pinset = FindMatchingPinset(aPolicy, aHostname);
  if (pinset && !pinset->mSpkiSha256DigestsBase64.Contains(
                    result.mChainInfo.mLeaf.mSpkiDigestSha256Base64)) {
    result.mReasonCode = "pin_mismatch"_ns;
    result.mEvents.AppendElement(MakeEvent(
        EventType::TLSPinMismatch, Severity::Error,
        pinset->mMode == EnforcementMode::Block ? ValidationResult::Blocked
                                                : ValidationResult::Allowed,
        result.mReasonCode, aHostname, result.mTrustSource, result.mChainInfo,
        result.mRevocationStatus));
    if (pinset->mMode == EnforcementMode::Block) {
      result.mResult = pkix::Result::ERROR_KEY_PINNING_FAILURE;
      result.mEvents.AppendElement(MakeEvent(
          EventType::TLSValidationFailureEnterprise, Severity::Error,
          ValidationResult::Blocked, result.mReasonCode, aHostname,
          result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
      return result;
    }
  }

  result.mReasonCode = "enterprise_policy_passed"_ns;
  result.mEvents.AppendElement(MakeEvent(
      EventType::TLSValidationSuccessEnterprise, Severity::Info,
      ValidationResult::Allowed, result.mReasonCode, aHostname,
      result.mTrustSource, result.mChainInfo, result.mRevocationStatus));
  return result;
}

}  // namespace mozilla::psm::enterprise
