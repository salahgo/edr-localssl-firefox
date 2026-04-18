/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_psm_enterprise_EnterpriseCertUtils_h
#define mozilla_psm_enterprise_EnterpriseCertUtils_h

#include "mozpkix/Result.h"
#include "mozpkix/Time.h"
#include "nsString.h"
#include "nsTArray.h"

namespace mozilla::psm::enterprise {

struct EnterpriseCertInfo {
  nsCString mSubject;
  nsCString mCommonName;
  nsCString mIssuerCommonName;
  nsCString mFingerprintSha256;
  nsCString mSpkiDigestSha256Base64;
  nsTArray<nsCString> mSubjectAltNames;
  nsTArray<nsCString> mPolicyOids;
  bool mHasSubjectAltName = false;
  bool mHasServerAuthEku = false;
  bool mHasSuitableKeyUsage = true;
  mozilla::pkix::Time mNotBefore{mozilla::pkix::Time::uninitialized};
  mozilla::pkix::Time mNotAfter{mozilla::pkix::Time::uninitialized};
};

struct EnterpriseChainInfo {
  EnterpriseCertInfo mLeaf;
  nsCString mImmediateIssuerFingerprintSha256;
  nsCString mImmediateIssuerCommonName;
  nsCString mRootFingerprintSha256;
};

nsCString NormalizeFingerprint(const nsACString& aFingerprint);
bool MatchesHostnamePattern(const nsACString& aHostname,
                            const nsACString& aPattern);
bool ContainsFingerprint(const nsTArray<nsCString>& aFingerprints,
                         const nsACString& aFingerprint);
nsresult ComputeFingerprintSha256Hex(const nsTArray<uint8_t>& aBytes,
                                     nsACString& aOutFingerprint);
mozilla::pkix::Result CheckStrictSubjectAltName(const nsTArray<uint8_t>& aDER,
                                                const nsACString& aHostname);
bool HasRequiredPolicyOids(const EnterpriseCertInfo& aLeaf,
                           const nsTArray<nsCString>& aRequiredPolicyOids);
nsresult ExtractEnterpriseChainInfo(
    const nsTArray<nsTArray<uint8_t>>& aBuiltChain,
    EnterpriseChainInfo& aOutChainInfo);

}  // namespace mozilla::psm::enterprise

#endif  // mozilla_psm_enterprise_EnterpriseCertUtils_h
