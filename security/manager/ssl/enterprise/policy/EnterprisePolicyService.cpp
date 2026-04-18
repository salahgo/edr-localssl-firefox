/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "EnterprisePolicyService.h"

#include "EnterpriseBundleLoader.h"
#include "EnterprisePolicyEvaluator.h"
#include "EnterpriseTelemetryLogger.h"
#include "mozilla/Preferences.h"
#include "mozpkix/Result.h"
#include "nsAppDirectoryServiceDefs.h"
#include "nsCharSeparatedTokenizer.h"
#include "nsDirectoryServiceUtils.h"
#include "nsIFile.h"
#include "nsIXULAppInfo.h"
#include "nsNetUtil.h"
#include "nsServiceManagerUtils.h"
#include "nsThreadUtils.h"
#include "nsXULAppAPI.h"

namespace mozilla::psm::enterprise {

namespace pkix = mozilla::pkix;

namespace {

constexpr auto kBundlePathPref = "security.aegis.enterprise_policy.bundle_path";
constexpr auto kSignerPref =
    "security.aegis.enterprise_policy.allowed_signer_fingerprints_sha256";
constexpr auto kTelemetryPathPref = "security.aegis.telemetry.log_path";

void ParseFingerprintsPref(const nsCString& aPrefValue,
                           nsTArray<nsCString>& aFingerprints) {
  aFingerprints.Clear();
  nsCCharSeparatedTokenizer tokenizer(aPrefValue, ',');
  while (tokenizer.hasMoreTokens()) {
    nsDependentCSubstring token = tokenizer.nextToken();
    if (!token.IsEmpty()) {
      aFingerprints.AppendElement(NormalizeFingerprint(token));
    }
  }
}

bool LooksAbsolutePath(const nsAString& aPath) {
  if (aPath.Length() >= 2 && aPath.CharAt(1) == u':') {
    return true;
  }
  if (aPath.IsEmpty()) {
    return false;
  }
  char16_t first = aPath.CharAt(0);
  return first == u'/' || first == u'\\';
}

nsresult ResolveConfiguredPath(const nsAString& aConfiguredPath, nsIFile* aBase,
                               nsString& aResolvedPath) {
  if (aConfiguredPath.IsEmpty()) {
    return NS_ERROR_INVALID_ARG;
  }

  nsCOMPtr<nsIFile> candidate;
  nsresult rv;
  if (LooksAbsolutePath(aConfiguredPath)) {
    rv = NS_NewLocalFile(aConfiguredPath, getter_AddRefs(candidate));
    if (NS_SUCCEEDED(rv) && candidate) {
      (void)candidate->Normalize();
      return candidate->GetPath(aResolvedPath);
    }
  }

  nsCOMPtr<nsIFile> baseDirectory;
  if (aBase) {
    baseDirectory = aBase;
  } else {
    rv = NS_GetSpecialDirectory(XRE_APP_DISTRIBUTION_DIR,
                                getter_AddRefs(baseDirectory));
    if (NS_FAILED(rv) || !baseDirectory) {
      rv = NS_GetSpecialDirectory(NS_APP_USER_PROFILE_50_DIR,
                                  getter_AddRefs(baseDirectory));
      if (NS_FAILED(rv)) {
        return rv;
      }
    }
  }

  rv = baseDirectory->Clone(getter_AddRefs(candidate));
  if (NS_FAILED(rv)) {
    return rv;
  }
  rv = candidate->AppendRelativePath(aConfiguredPath);
  if (NS_FAILED(rv)) {
    return rv;
  }
  (void)candidate->Normalize();
  return candidate->GetPath(aResolvedPath);
}

void AppendRepeatedFailureEvent(nsTArray<EnterpriseTelemetryEvent>& aEvents,
                                const nsACString& aHostname) {
  EnterpriseTelemetryEvent event;
  event.mEventType = EventType::RepeatedTLSFailuresSameHost;
  event.mSeverity = Severity::Warning;
  event.mValidationResult = ValidationResult::Blocked;
  event.mReasonCode = "repeated_tls_failures_same_host"_ns;
  event.mHostname = aHostname;
  event.mUrl = "https://"_ns + nsCString(aHostname) + "/"_ns;
  event.mTrustSource = "enterprise_policy_scope"_ns;
  event.mRevocationStatus = "not_applicable"_ns;
  aEvents.AppendElement(std::move(event));
}

void AppendIssuerChangeEvent(nsTArray<EnterpriseTelemetryEvent>& aEvents,
                             const nsACString& aHostname,
                             const EnterpriseEvaluationResult& aEvaluation) {
  EnterpriseTelemetryEvent event;
  event.mEventType = EventType::UnexpectedIssuerChangeForInternalHost;
  event.mSeverity = Severity::Warning;
  event.mValidationResult = ValidationResult::Allowed;
  event.mReasonCode = "unexpected_issuer_change_for_internal_host"_ns;
  event.mHostname = aHostname;
  event.mUrl = "https://"_ns + nsCString(aHostname) + "/"_ns;
  event.mTrustSource = aEvaluation.mTrustSource;
  event.mCertSubject = aEvaluation.mChainInfo.mLeaf.mSubject;
  event.mCertSAN = aEvaluation.mChainInfo.mLeaf.mSubjectAltNames.Clone();
  event.mIssuerCN = aEvaluation.mChainInfo.mImmediateIssuerCommonName;
  event.mIssuerFingerprintSha256 =
      aEvaluation.mChainInfo.mImmediateIssuerFingerprintSha256;
  event.mRootFingerprintSha256 = aEvaluation.mChainInfo.mRootFingerprintSha256;
  event.mPolicyOids = aEvaluation.mChainInfo.mLeaf.mPolicyOids.Clone();
  event.mRevocationStatus = aEvaluation.mRevocationStatus;
  aEvents.AppendElement(std::move(event));
}

bool HostMatchesAny(const nsTArray<nsCString>& aPatterns,
                    const nsACString& aHostname) {
  for (const auto& pattern : aPatterns) {
    if (MatchesHostnamePattern(aHostname, pattern)) {
      return true;
    }
  }
  return false;
}

const char* MapFailureReason(pkix::Result aResult) {
  switch (aResult) {
    case pkix::Result::ERROR_REVOKED_CERTIFICATE:
      return "revoked_cert";
    case pkix::Result::ERROR_OCSP_UNKNOWN_CERT:
    case pkix::Result::ERROR_OCSP_SERVER_ERROR:
    case pkix::Result::ERROR_OCSP_TRY_SERVER_LATER:
    case pkix::Result::ERROR_OCSP_UNAUTHORIZED_REQUEST:
    case pkix::Result::ERROR_OCSP_INVALID_SIGNING_CERT:
    case pkix::Result::ERROR_OCSP_MALFORMED_RESPONSE:
    case pkix::Result::ERROR_OCSP_OLD_RESPONSE:
    case pkix::Result::ERROR_OCSP_MALFORMED_REQUEST:
      return "revocation_unknown";
    default:
      return MapResultToName(aResult);
  }
}

const char* MapRevocationStatus(pkix::Result aResult) {
  switch (aResult) {
    case pkix::Result::ERROR_REVOKED_CERTIFICATE:
      return "revoked";
    case pkix::Result::ERROR_OCSP_UNKNOWN_CERT:
    case pkix::Result::ERROR_OCSP_SERVER_ERROR:
    case pkix::Result::ERROR_OCSP_TRY_SERVER_LATER:
    case pkix::Result::ERROR_OCSP_UNAUTHORIZED_REQUEST:
    case pkix::Result::ERROR_OCSP_INVALID_SIGNING_CERT:
    case pkix::Result::ERROR_OCSP_MALFORMED_RESPONSE:
    case pkix::Result::ERROR_OCSP_OLD_RESPONSE:
    case pkix::Result::ERROR_OCSP_MALFORMED_REQUEST:
      return "unknown";
    default:
      return "not_applicable";
  }
}

EnterprisePolicyService::HostObservation* FindObservation(
    nsTArray<EnterprisePolicyService::HostObservation>& aObservations,
    const nsACString& aHostname) {
  for (auto& observation : aObservations) {
    if (observation.mHostname.Equals(aHostname)) {
      return &observation;
    }
  }
  return nullptr;
}

}  // namespace

EnterprisePolicyService& EnterprisePolicyService::GetInstance() {
  static EnterprisePolicyService sService;
  return sService;
}

Maybe<EnterprisePolicySnapshot> EnterprisePolicyService::GetSnapshot() const {
  auto snapshot = mSnapshot.Lock();
  if (snapshot->isNothing()) {
    return Nothing();
  }
  return Some(snapshot->ref());
}

void EnterprisePolicyService::ReloadFromPrefs() {
  if (!NS_IsMainThread()) {
    return;
  }

  {
    auto observations = mHostObservations.Lock();
    observations->Clear();
  }

  nsAutoString configuredBundlePath;
  Preferences::GetString(kBundlePathPref, configuredBundlePath);
  if (configuredBundlePath.IsEmpty()) {
    auto snapshot = mSnapshot.Lock();
    snapshot->reset();
    return;
  }

  nsAutoCString allowedSignerPref;
  Preferences::GetCString(kSignerPref, allowedSignerPref);
  nsTArray<nsCString> allowedSignerFingerprints;
  ParseFingerprintsPref(allowedSignerPref, allowedSignerFingerprints);

  nsString resolvedBundlePath;
  if (NS_FAILED(ResolveConfiguredPath(configuredBundlePath, nullptr,
                                      resolvedBundlePath))) {
    auto snapshot = mSnapshot.Lock();
    snapshot->reset();
    return;
  }

  nsCString productVersion("unknown");
  nsCOMPtr<nsIXULAppInfo> appInfo(do_GetService("@mozilla.org/xre/app-info;1"));
  if (appInfo) {
    (void)appInfo->GetVersion(productVersion);
  }

  BundleLoadResult loadResult =
      LoadEnterprisePolicyBundle(resolvedBundlePath, allowedSignerFingerprints,
                                 "Aegis Firefox"_ns, productVersion);

  nsAutoString telemetryOverridePath;
  Preferences::GetString(kTelemetryPathPref, telemetryOverridePath);

  if (!loadResult.mSuccess || loadResult.mSnapshot.isNothing()) {
    {
      auto snapshot = mSnapshot.Lock();
      snapshot->reset();
    }
    EnterprisePolicySnapshot failureSnapshot;
    failureSnapshot.mActive = true;
    failureSnapshot.mVersion = "unavailable"_ns;
    failureSnapshot.mProduct = "Aegis Firefox"_ns;
    failureSnapshot.mProductVersion = productVersion;
    failureSnapshot.mIntegrityStatus = loadResult.mReasonCode;
    if (!telemetryOverridePath.IsEmpty()) {
      nsCOMPtr<nsIFile> bundleFile;
      if (NS_SUCCEEDED(NS_NewLocalFile(resolvedBundlePath,
                                       getter_AddRefs(bundleFile)))) {
        nsCOMPtr<nsIFile> parent;
        if (NS_SUCCEEDED(bundleFile->GetParent(getter_AddRefs(parent)))) {
          (void)ResolveConfiguredPath(telemetryOverridePath, parent,
                                      failureSnapshot.mTelemetry.mLogPath);
        }
      }
    }
    EnterpriseTelemetryEvent failureEvent;
    failureEvent.mEventType = EventType::BrowserPolicySignatureFailure;
    failureEvent.mSeverity = Severity::Error;
    failureEvent.mValidationResult = ValidationResult::Blocked;
    failureEvent.mReasonCode = loadResult.mReasonCode;
    failureEvent.mTrustSource = "enterprise_policy_bundle"_ns;
    failureEvent.mRevocationStatus = "not_applicable"_ns;
    nsTArray<EnterpriseTelemetryEvent> events;
    events.AppendElement(std::move(failureEvent));
    EnterpriseTelemetryLogger::LogEvents(failureSnapshot, events);
    return;
  }

  EnterprisePolicySnapshot snapshot = loadResult.mSnapshot.ref();
  snapshot.mIntegrityStatus = "signature_valid"_ns;
  if (!telemetryOverridePath.IsEmpty()) {
    nsCOMPtr<nsIFile> bundleFile;
    if (NS_SUCCEEDED(
            NS_NewLocalFile(resolvedBundlePath, getter_AddRefs(bundleFile)))) {
      nsCOMPtr<nsIFile> parent;
      if (NS_SUCCEEDED(bundleFile->GetParent(getter_AddRefs(parent)))) {
        (void)ResolveConfiguredPath(telemetryOverridePath, parent,
                                    snapshot.mTelemetry.mLogPath);
      }
    }
  } else if (!snapshot.mTelemetry.mLogPath.IsEmpty()) {
    nsCOMPtr<nsIFile> bundleFile;
    if (NS_SUCCEEDED(
            NS_NewLocalFile(resolvedBundlePath, getter_AddRefs(bundleFile)))) {
      nsCOMPtr<nsIFile> parent;
      if (NS_SUCCEEDED(bundleFile->GetParent(getter_AddRefs(parent)))) {
        nsString resolvedLogPath;
        if (NS_SUCCEEDED(ResolveConfiguredPath(snapshot.mTelemetry.mLogPath,
                                               parent, resolvedLogPath))) {
          snapshot.mTelemetry.mLogPath.Assign(resolvedLogPath);
        }
      }
    }
  }

  {
    auto storedSnapshot = mSnapshot.Lock();
    *storedSnapshot = Some(snapshot);
  }

  EnterpriseTelemetryEvent trustStoreChanged;
  trustStoreChanged.mEventType = EventType::BrowserEnterpriseTrustStoreChanged;
  trustStoreChanged.mSeverity = Severity::Info;
  trustStoreChanged.mValidationResult = ValidationResult::Allowed;
  trustStoreChanged.mReasonCode = "enterprise_policy_reloaded"_ns;
  trustStoreChanged.mTrustSource = "enterprise_policy_bundle"_ns;
  trustStoreChanged.mRevocationStatus = "not_applicable"_ns;
  nsTArray<EnterpriseTelemetryEvent> events;
  events.AppendElement(std::move(trustStoreChanged));
  EnterpriseTelemetryLogger::LogEvents(snapshot, events);
}

bool EnterprisePolicyService::ShouldRequireHardFailRevocation(
    const nsACString& aHostname) const {
  Maybe<EnterprisePolicySnapshot> snapshot = GetSnapshot();
  if (snapshot.isNothing() ||
      !HostMatchesAny(snapshot.ref().mEnterpriseDomains, aHostname)) {
    return false;
  }

  for (const auto& override : snapshot.ref().mRevocationOverrides) {
    if (MatchesHostnamePattern(aHostname, override.mHostnamePattern)) {
      return override.mMode == RevocationMode::HardFail;
    }
  }
  return snapshot.ref().mRevocationMode == RevocationMode::HardFail;
}

pkix::Result EnterprisePolicyService::MaybeEnforceSuccessfulTLS(
    const nsACString& aHostname,
    const nsTArray<nsTArray<uint8_t>>& aBuiltChain) {
  Maybe<EnterprisePolicySnapshot> snapshot = GetSnapshot();
  if (snapshot.isNothing()) {
    return pkix::Success;
  }

  EnterpriseEvaluationResult evaluation =
      EvaluateEnterpriseTlsConnection(snapshot.ref(), aHostname, aBuiltChain);
  if (!evaluation.mAppliedEnterprisePolicy && evaluation.mEvents.IsEmpty()) {
    return evaluation.mResult;
  }

  {
    auto observations = mHostObservations.Lock();
    HostObservation* observation = FindObservation(*observations, aHostname);
    if (!observation) {
      HostObservation newObservation;
      newObservation.mHostname.Assign(aHostname);
      observations->AppendElement(std::move(newObservation));
      observation = &observations->LastElement();
    }

    if (evaluation.mResult == pkix::Success) {
      observation->mFailureCount = 0;
      if (evaluation.mInternalHostname && evaluation.mPrivateChain) {
        if (!observation->mLastSuccessfulIssuerFingerprintSha256.IsEmpty() &&
            !observation->mLastSuccessfulIssuerFingerprintSha256.Equals(
                evaluation.mChainInfo.mImmediateIssuerFingerprintSha256)) {
          AppendIssuerChangeEvent(evaluation.mEvents, aHostname, evaluation);
        }
        observation->mLastSuccessfulIssuerFingerprintSha256 =
            evaluation.mChainInfo.mImmediateIssuerFingerprintSha256;
      }
    } else {
      observation->mFailureCount++;
      if (observation->mFailureCount == 3) {
        AppendRepeatedFailureEvent(evaluation.mEvents, aHostname);
      }
    }
  }

  EnterpriseTelemetryLogger::LogEvents(snapshot.ref(), evaluation.mEvents);
  return evaluation.mResult;
}

void EnterprisePolicyService::NoteTLSValidationFailure(
    const nsACString& aHostname, pkix::Result aResult) {
  Maybe<EnterprisePolicySnapshot> snapshot = GetSnapshot();
  if (snapshot.isNothing() ||
      !HostMatchesAny(snapshot.ref().mEnterpriseDomains, aHostname)) {
    return;
  }

  nsTArray<EnterpriseTelemetryEvent> events;
  const char* reason = MapFailureReason(aResult);
  const char* revocationStatus = MapRevocationStatus(aResult);

  if (aResult == pkix::Result::ERROR_REVOKED_CERTIFICATE) {
    EnterpriseTelemetryEvent revokedEvent;
    revokedEvent.mEventType = EventType::TLSRevokedCert;
    revokedEvent.mSeverity = Severity::Error;
    revokedEvent.mValidationResult = ValidationResult::StockValidationFailed;
    revokedEvent.mReasonCode = reason;
    revokedEvent.mHostname = aHostname;
    revokedEvent.mUrl = "https://"_ns + nsCString(aHostname) + "/"_ns;
    revokedEvent.mTrustSource = "enterprise_policy_scope"_ns;
    revokedEvent.mRevocationStatus = revocationStatus;
    events.AppendElement(std::move(revokedEvent));
  } else if (nsCString(reason).EqualsLiteral("revocation_unknown")) {
    EnterpriseTelemetryEvent revocationUnknownEvent;
    revocationUnknownEvent.mEventType = EventType::TLSRevocationUnknown;
    revocationUnknownEvent.mSeverity = Severity::Error;
    revocationUnknownEvent.mValidationResult =
        ValidationResult::StockValidationFailed;
    revocationUnknownEvent.mReasonCode = reason;
    revocationUnknownEvent.mHostname = aHostname;
    revocationUnknownEvent.mUrl = "https://"_ns + nsCString(aHostname) + "/"_ns;
    revocationUnknownEvent.mTrustSource = "enterprise_policy_scope"_ns;
    revocationUnknownEvent.mRevocationStatus = revocationStatus;
    events.AppendElement(std::move(revocationUnknownEvent));
  }

  EnterpriseTelemetryEvent failureEvent;
  failureEvent.mEventType = EventType::TLSValidationFailureEnterprise;
  failureEvent.mSeverity = Severity::Error;
  failureEvent.mValidationResult = ValidationResult::StockValidationFailed;
  failureEvent.mReasonCode = reason;
  failureEvent.mHostname = aHostname;
  failureEvent.mUrl = "https://"_ns + nsCString(aHostname) + "/"_ns;
  failureEvent.mTrustSource = "enterprise_policy_scope"_ns;
  failureEvent.mRevocationStatus = revocationStatus;
  events.AppendElement(std::move(failureEvent));

  {
    auto observations = mHostObservations.Lock();
    HostObservation* observation = FindObservation(*observations, aHostname);
    if (!observation) {
      HostObservation newObservation;
      newObservation.mHostname.Assign(aHostname);
      observations->AppendElement(std::move(newObservation));
      observation = &observations->LastElement();
    }
    observation->mFailureCount++;
    if (observation->mFailureCount == 3) {
      AppendRepeatedFailureEvent(events, aHostname);
    }
  }

  EnterpriseTelemetryLogger::LogEvents(snapshot.ref(), events);
}

}  // namespace mozilla::psm::enterprise
