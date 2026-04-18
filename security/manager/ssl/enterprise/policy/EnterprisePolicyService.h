/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_psm_enterprise_EnterprisePolicyService_h
#define mozilla_psm_enterprise_EnterprisePolicyService_h

#include "EnterprisePolicyTypes.h"
#include "mozpkix/Result.h"
#include "mozilla/DataMutex.h"

namespace mozilla::psm::enterprise {

class EnterprisePolicyService final {
 public:
  struct HostObservation {
    nsCString mHostname;
    uint32_t mFailureCount = 0;
    nsCString mLastSuccessfulIssuerFingerprintSha256;
  };

  static EnterprisePolicyService& GetInstance();

  void ReloadFromPrefs();
  bool ShouldRequireHardFailRevocation(const nsACString& aHostname) const;
  mozilla::pkix::Result MaybeEnforceSuccessfulTLS(
      const nsACString& aHostname,
      const nsTArray<nsTArray<uint8_t>>& aBuiltChain);
  void NoteTLSValidationFailure(const nsACString& aHostname,
                                mozilla::pkix::Result aResult);

 private:
  EnterprisePolicyService() = default;

  Maybe<EnterprisePolicySnapshot> GetSnapshot() const;

  mutable DataMutex<Maybe<EnterprisePolicySnapshot>> mSnapshot{
      "EnterprisePolicyService::mSnapshot"};
  DataMutex<nsTArray<HostObservation>> mHostObservations{
      "EnterprisePolicyService::mHostObservations"};
};

}  // namespace mozilla::psm::enterprise

#endif  // mozilla_psm_enterprise_EnterprisePolicyService_h
