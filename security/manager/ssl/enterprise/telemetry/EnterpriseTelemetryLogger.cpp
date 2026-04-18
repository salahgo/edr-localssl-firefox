/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "EnterpriseTelemetryLogger.h"

#include "mozilla/JSONWriter.h"
#include "nsCOMPtr.h"
#include "nsComponentManagerUtils.h"
#include "nsDirectoryServiceUtils.h"
#include "nsIFile.h"
#include "nsIFileStreams.h"
#include "nsNetUtil.h"
#include "nsPrintfCString.h"
#include "prenv.h"
#include "prsystem.h"
#include "prtime.h"
#include "mozilla/JSONStringWriteFuncs.h"

namespace mozilla::psm::enterprise {

namespace {

constexpr char kProductName[] = "Aegis Firefox";

const char* ValidationResultString(ValidationResult aValidationResult) {
  switch (aValidationResult) {
    case ValidationResult::Allowed:
      return "allowed";
    case ValidationResult::Blocked:
      return "blocked";
    case ValidationResult::StockValidationFailed:
      return "stock_validation_failed";
  }
  return "unknown";
}

nsCString CurrentTimestamp() {
  PRExplodedTime exploded;
  PR_ExplodeTime(PR_Now(), PR_GMTParameters, &exploded);
  return nsPrintfCString(
      "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", exploded.tm_year,
      exploded.tm_month + 1, exploded.tm_mday, exploded.tm_hour,
      exploded.tm_min, exploded.tm_sec, exploded.tm_usec / 1000);
}

nsCString GetUserName() {
  const char* user = PR_GetEnv("USERNAME");
  if (!user || !*user) {
    user = PR_GetEnv("USER");
  }
  return user ? nsCString(user) : "unknown"_ns;
}

nsCString GetDeviceName() {
  char hostname[256] = {};
  if (PR_GetSystemInfo(PR_SI_HOSTNAME, hostname, sizeof(hostname)) == PR_SUCCESS) {
    return nsCString(hostname);
  }
  return "unknown"_ns;
}

void AppendArrayProperty(JSONWriter& aWriter, const char* aName,
                         const nsTArray<nsCString>& aValues) {
  aWriter.StartArrayProperty(nsDependentCString(aName),
                             JSONWriter::SingleLineStyle);
  for (const auto& value : aValues) {
    aWriter.StringElement(value);
  }
  aWriter.EndArray();
}

void LogSingleEvent(const EnterprisePolicySnapshot& aPolicy,
                    const EnterpriseTelemetryEvent& aEvent) {
  if (!aPolicy.mTelemetry.mEnabled || aPolicy.mTelemetry.mLogPath.IsEmpty()) {
    return;
  }

  nsCOMPtr<nsIFile> logFile;
  nsresult rv = NS_NewLocalFile(aPolicy.mTelemetry.mLogPath,
                                getter_AddRefs(logFile));
  if (NS_FAILED(rv) || !logFile) {
    return;
  }

  nsCOMPtr<nsIFile> parent;
  rv = logFile->GetParent(getter_AddRefs(parent));
  if (NS_SUCCEEDED(rv) && parent) {
    bool exists = false;
    if (NS_SUCCEEDED(parent->Exists(&exists)) && !exists) {
      (void)parent->Create(nsIFile::DIRECTORY_TYPE, 0700);
    }
  }

  nsCOMPtr<nsIOutputStream> outputStream;
  rv = NS_NewLocalFileOutputStream(getter_AddRefs(outputStream), logFile,
                                   PR_WRONLY | PR_CREATE_FILE | PR_APPEND,
                                   0600);
  if (NS_FAILED(rv) || !outputStream) {
    return;
  }

  nsAutoCString json;
  JSONStringRefWriteFunc writeFunc(json);
  JSONWriter writer(writeFunc, JSONWriter::SingleLineStyle);
  writer.Start();
  writer.StringProperty("timestamp", CurrentTimestamp());
  writer.StringProperty("product", kProductName);
  writer.StringProperty("version", aPolicy.mProductVersion);
  writer.StringProperty("event_type",
                        nsDependentCString(ToString(aEvent.mEventType)));
  writer.StringProperty("severity",
                        nsDependentCString(ToString(aEvent.mSeverity)));
  writer.StringProperty("hostname", aEvent.mHostname);
  writer.StringProperty("url", aEvent.mUrl);
  writer.StringProperty("validation_result",
                        nsDependentCString(
                            ValidationResultString(aEvent.mValidationResult)));
  writer.StringProperty("reason_code", aEvent.mReasonCode);
  writer.StringProperty("trust_source", aEvent.mTrustSource);
  writer.StringProperty("cert_subject", aEvent.mCertSubject);
  AppendArrayProperty(writer, "cert_san", aEvent.mCertSAN);
  writer.StringProperty("issuer_cn", aEvent.mIssuerCN);
  writer.StringProperty("issuer_fp_sha256", aEvent.mIssuerFingerprintSha256);
  writer.StringProperty("root_fp_sha256", aEvent.mRootFingerprintSha256);
  AppendArrayProperty(writer, "policy_oids", aEvent.mPolicyOids);
  writer.StringProperty("revocation_status", aEvent.mRevocationStatus);
  writer.StringProperty("policy_version", aPolicy.mVersion);
  writer.StringProperty("device", GetDeviceName());
  writer.StringProperty("user", GetUserName());
  writer.StringProperty("integrity_status", aPolicy.mIntegrityStatus);
  writer.End();
  json.Append('\n');

  uint32_t written = 0;
  (void)outputStream->Write(json.get(), json.Length(), &written);
}

}  // namespace

const char* ToString(EventType aEventType) {
  switch (aEventType) {
    case EventType::TLSValidationSuccessEnterprise:
      return "tls_validation_success_enterprise";
    case EventType::TLSValidationFailureEnterprise:
      return "tls_validation_failure_enterprise";
    case EventType::TLSUnapprovedIssuer:
      return "tls_unapproved_issuer";
    case EventType::TLSRevokedCert:
      return "tls_revoked_cert";
    case EventType::TLSRevocationUnknown:
      return "tls_revocation_unknown";
    case EventType::TLSInternalHostnamePublicCA:
      return "tls_internal_hostname_public_ca";
    case EventType::TLSPublicHostnamePrivateCA:
      return "tls_public_hostname_private_ca";
    case EventType::TLSPinMismatch:
      return "tls_pin_mismatch";
    case EventType::BrowserPolicySignatureFailure:
      return "browser_policy_signature_failure";
    case EventType::BrowserEnterpriseTrustStoreChanged:
      return "browser_enterprise_trust_store_changed";
    case EventType::ExtensionInstallOutsideAllowlist:
      return "extension_install_outside_allowlist";
    case EventType::DangerousDownloadDetected:
      return "dangerous_download_detected";
    case EventType::RepeatedTLSFailuresSameHost:
      return "repeated_tls_failures_same_host";
    case EventType::UnexpectedIssuerChangeForInternalHost:
      return "unexpected_issuer_change_for_internal_host";
  }
  return "unknown";
}

const char* ToString(Severity aSeverity) {
  switch (aSeverity) {
    case Severity::Info:
      return "info";
    case Severity::Warning:
      return "warning";
    case Severity::Error:
      return "error";
  }
  return "unknown";
}

const char* ToString(ValidationResult aValidationResult) {
  return ValidationResultString(aValidationResult);
}

void EnterpriseTelemetryLogger::LogEvents(
    const EnterprisePolicySnapshot& aPolicy,
    const nsTArray<EnterpriseTelemetryEvent>& aEvents) {
  for (const auto& event : aEvents) {
    if (event.mEventType == EventType::TLSValidationSuccessEnterprise &&
        !aPolicy.mTelemetry.mEmitSuccesses) {
      continue;
    }
    LogSingleEvent(aPolicy, event);
  }
}

}  // namespace mozilla::psm::enterprise
