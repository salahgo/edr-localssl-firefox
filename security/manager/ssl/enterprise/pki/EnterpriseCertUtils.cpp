/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "EnterpriseCertUtils.h"

#include "ScopedNSSTypes.h"
#include "cert.h"
#include "certt.h"
#include "genname.h"
#include "mozilla/Casting.h"
#include "mozilla/Base64.h"
#include "mozpkix/pkix.h"
#include "mozpkix/pkixcheck.h"
#include "mozpkix/pkixder.h"
#include "mozpkix/pkixutil.h"
#include "nsCRTGlue.h"
#include "nsPrintfCString.h"
#include "nsReadableUtils.h"
#include "pk11pub.h"
#include "secder.h"

namespace mozilla::psm::enterprise {

namespace pkix = mozilla::pkix;
namespace der = mozilla::pkix::der;

namespace {

bool ParseDNSNames(CERTCertificate* aCert, nsTArray<nsCString>& aNames) {
  SECItem altName = {};
  if (CERT_FindCertExtension(aCert, SEC_OID_X509_SUBJECT_ALT_NAME, &altName) !=
      SECSuccess) {
    return false;
  }

  PLArenaPool* arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
  if (!arena) {
    SECITEM_FreeItem(&altName, PR_FALSE);
    return false;
  }

  CERTGeneralName* names =
      CERT_DecodeAltNameExtension(arena, &altName);
  if (!names) {
    PORT_FreeArena(arena, PR_FALSE);
    SECITEM_FreeItem(&altName, PR_FALSE);
    return false;
  }

  CERTGeneralName* current = names;
  do {
    if (current->type == certDNSName && current->name.other.data &&
        current->name.other.len > 0) {
      aNames.AppendElement(
          nsDependentCSubstring(
              reinterpret_cast<const char*>(current->name.other.data),
              current->name.other.len));
    }
    current = CERT_GetNextGeneralName(current);
  } while (current != names);

  PORT_FreeArena(arena, PR_FALSE);
  SECITEM_FreeItem(&altName, PR_FALSE);
  return true;
}

bool LeafHasServerAuthEku(const pkix::BackCert& aBackCert) {
  static const uint8_t kServerAuth[] = {(40 * 1) + 3, 6, 1, 5, 5, 7, 3, 1};

  const pkix::Input* ekuInput = aBackCert.GetExtKeyUsage();
  if (!ekuInput) {
    return false;
  }

  pkix::Reader eku(*ekuInput);
  pkix::Reader ekuSequence;
  pkix::Result rv = der::ExpectTagAndGetValue(eku, der::SEQUENCE, ekuSequence);
  if (rv != pkix::Success || !eku.AtEnd()) {
    return false;
  }
  while (!ekuSequence.AtEnd()) {
    pkix::Reader keyPurposeId;
    rv = der::ExpectTagAndGetValue(ekuSequence, der::OIDTag, keyPurposeId);
    if (rv != pkix::Success) {
      return false;
    }
    if (keyPurposeId.MatchRest(kServerAuth)) {
      return true;
    }
  }
  return false;
}

bool LeafHasSuitableKeyUsage(CERTCertificate* aCert) {
  SECItem keyUsageItem = {};
  if (CERT_FindKeyUsageExtension(aCert, &keyUsageItem) != SECSuccess ||
      !keyUsageItem.data || keyUsageItem.len == 0) {
    return true;
  }
  const uint8_t keyUsage = keyUsageItem.data[0];
  bool suitable = keyUsage & (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT |
                              KU_KEY_AGREEMENT);
  SECITEM_FreeItem(&keyUsageItem, PR_FALSE);
  return suitable;
}

void ExtractPolicyOids(const pkix::BackCert& aBackCert,
                       nsTArray<nsCString>& aOids) {
  const pkix::Input* policiesInput = aBackCert.GetCertificatePolicies();
  if (!policiesInput) {
    return;
  }

  pkix::Reader extension(*policiesInput);
  pkix::Reader policies;
  if (der::ExpectTagAndGetValue(extension, der::SEQUENCE, policies) !=
          pkix::Success ||
      !extension.AtEnd()) {
    return;
  }

  while (!policies.AtEnd()) {
    pkix::Reader policyInformation;
    if (der::ExpectTagAndGetValue(policies, der::SEQUENCE, policyInformation) !=
        pkix::Success) {
      return;
    }
    pkix::Input policyOid;
    if (der::ExpectTagAndGetValue(policyInformation, der::OIDTag, policyOid) !=
        pkix::Success) {
      return;
    }
    SECItem oidItem = {siBuffer,
                       const_cast<unsigned char*>(policyOid.UnsafeGetData()),
                       policyOid.GetLength()};
    UniquePORTString oidString(CERT_GetOidString(&oidItem));
    if (oidString) {
      aOids.AppendElement(nsCString(oidString.get()));
    }
    policyInformation.SkipToEnd();
  }
}

nsresult ComputeSpkiDigest(const pkix::BackCert& aBackCert,
                           nsACString& aDigestOut) {
  nsTArray<uint8_t> digestArray;
  nsresult rv = Digest::DigestBuf(SEC_OID_SHA256,
                                  aBackCert.GetSubjectPublicKeyInfo()
                                      .UnsafeGetData(),
                                  aBackCert.GetSubjectPublicKeyInfo()
                                      .GetLength(),
                                  digestArray);
  if (NS_FAILED(rv)) {
    return rv;
  }
  return Base64Encode(
      nsDependentCSubstring(
          reinterpret_cast<const char*>(digestArray.Elements()),
          digestArray.Length()),
      aDigestOut);
}

nsresult ExtractCertInfo(const nsTArray<uint8_t>& aDER,
                         EnterpriseCertInfo& aCertInfo) {
  nsresult rv = ComputeFingerprintSha256Hex(aDER, aCertInfo.mFingerprintSha256);
  if (NS_FAILED(rv)) {
    return rv;
  }

  SECItem certItem = {
      siBuffer, const_cast<unsigned char*>(aDER.Elements()),
      static_cast<unsigned int>(aDER.Length())};
  UniqueCERTCertificate cert(CERT_NewTempCertificate(
      CERT_GetDefaultCertDB(), &certItem, nullptr, false, true));
  if (!cert) {
    return NS_ERROR_FAILURE;
  }

  if (cert->subjectName) {
    aCertInfo.mSubject.Assign(cert->subjectName);
  }
  UniquePORTString commonName(CERT_GetCommonName(&cert->subject));
  if (commonName) {
    aCertInfo.mCommonName.Assign(commonName.get());
  }
  UniquePORTString issuerCN(CERT_GetCommonName(&cert->issuer));
  if (issuerCN) {
    aCertInfo.mIssuerCommonName.Assign(issuerCN.get());
  }

  aCertInfo.mHasSubjectAltName =
      ParseDNSNames(cert.get(), aCertInfo.mSubjectAltNames);
  aCertInfo.mHasSuitableKeyUsage = LeafHasSuitableKeyUsage(cert.get());

  pkix::Input certInput;
  pkix::Result result = certInput.Init(aDER.Elements(), aDER.Length());
  if (result != pkix::Success) {
    return NS_ERROR_FAILURE;
  }

  pkix::BackCert backCert(certInput, pkix::EndEntityOrCA::MustBeEndEntity,
                          nullptr);
  result = backCert.Init();
  if (result != pkix::Success) {
    return NS_ERROR_FAILURE;
  }

  aCertInfo.mHasSubjectAltName =
      aCertInfo.mHasSubjectAltName || backCert.GetSubjectAltName() != nullptr;
  aCertInfo.mHasServerAuthEku = LeafHasServerAuthEku(backCert);
  ExtractPolicyOids(backCert, aCertInfo.mPolicyOids);
  rv = ComputeSpkiDigest(backCert, aCertInfo.mSpkiDigestSha256Base64);
  if (NS_FAILED(rv)) {
    return rv;
  }
  result = pkix::ParseValidity(backCert.GetValidity(), &aCertInfo.mNotBefore,
                               &aCertInfo.mNotAfter);
  if (result != pkix::Success) {
    return NS_ERROR_FAILURE;
  }

  return NS_OK;
}

}  // namespace

nsCString NormalizeFingerprint(const nsACString& aFingerprint) {
  nsAutoCString normalized;
  normalized.SetCapacity(aFingerprint.Length());
  for (const char* cursor = aFingerprint.BeginReading();
       cursor != aFingerprint.EndReading(); ++cursor) {
    char c = *cursor;
    if (c == ':' || c == '-' || c == ' ' || c == '\t' || c == '\n' ||
        c == '\r') {
      continue;
    }
    normalized.Append(c);
  }
  ToUpperCase(normalized);
  return normalized;
}

bool MatchesHostnamePattern(const nsACString& aHostname,
                            const nsACString& aPattern) {
  if (aHostname.IsEmpty() || aPattern.IsEmpty()) {
    return false;
  }

  nsAutoCString hostname(aHostname);
  nsAutoCString pattern(aPattern);
  ToLowerCase(hostname);
  ToLowerCase(pattern);

  if (StringBeginsWith(pattern, "*."_ns)) {
    nsDependentCSubstring suffix = Substring(pattern, 2);
    if (hostname.Length() <= suffix.Length()) {
      return false;
    }
    nsAutoCString wildcardSuffix(".");
    wildcardSuffix.Append(suffix);
    return StringEndsWith(hostname, wildcardSuffix);
  }

  if (hostname.Equals(pattern)) {
    return true;
  }
  nsAutoCString suffix(".");
  suffix.Append(pattern);
  return StringEndsWith(hostname, suffix);
}

bool ContainsFingerprint(const nsTArray<nsCString>& aFingerprints,
                         const nsACString& aFingerprint) {
  nsCString normalized = NormalizeFingerprint(aFingerprint);
  for (const auto& fingerprint : aFingerprints) {
    if (NormalizeFingerprint(fingerprint).Equals(normalized)) {
      return true;
    }
  }
  return false;
}

nsresult ComputeFingerprintSha256Hex(const nsTArray<uint8_t>& aBytes,
                                     nsACString& aOutFingerprint) {
  unsigned char digest[SHA256_LENGTH] = {};
  if (PK11_HashBuf(SEC_OID_SHA256, digest, aBytes.Elements(), aBytes.Length()) !=
      SECSuccess) {
    return NS_ERROR_FAILURE;
  }
  SECItem digestItem = {siBuffer, digest, SHA256_LENGTH};
  UniquePORTString digestString(CERT_Hexify(&digestItem, false));
  if (!digestString) {
    return NS_ERROR_OUT_OF_MEMORY;
  }
  aOutFingerprint.Assign(digestString.get());
  return NS_OK;
}

pkix::Result CheckStrictSubjectAltName(const nsTArray<uint8_t>& aDER,
                                       const nsACString& aHostname) {
  pkix::Input certInput;
  pkix::Result rv = certInput.Init(aDER.Elements(), aDER.Length());
  if (rv != pkix::Success) {
    return rv;
  }

  pkix::Input hostnameInput;
  rv = hostnameInput.Init(
      BitwiseCast<const uint8_t*, const char*>(aHostname.BeginReading()),
      aHostname.Length());
  if (rv != pkix::Success) {
    return rv;
  }

  rv = pkix::CheckCertHostname(certInput, hostnameInput);
  if (rv == pkix::Result::ERROR_BAD_DER) {
    return pkix::Result::ERROR_BAD_CERT_DOMAIN;
  }
  return rv;
}

bool HasRequiredPolicyOids(const EnterpriseCertInfo& aLeaf,
                           const nsTArray<nsCString>& aRequiredPolicyOids) {
  if (aRequiredPolicyOids.IsEmpty()) {
    return true;
  }

  for (const auto& requiredOid : aRequiredPolicyOids) {
    if (!aLeaf.mPolicyOids.Contains(requiredOid)) {
      return false;
    }
  }
  return true;
}

nsresult ExtractEnterpriseChainInfo(
    const nsTArray<nsTArray<uint8_t>>& aBuiltChain,
    EnterpriseChainInfo& aOutChainInfo) {
  if (aBuiltChain.IsEmpty()) {
    return NS_ERROR_INVALID_ARG;
  }

  nsresult rv = ExtractCertInfo(aBuiltChain[0], aOutChainInfo.mLeaf);
  if (NS_FAILED(rv)) {
    return rv;
  }

  const nsTArray<uint8_t>& rootDER = aBuiltChain.LastElement();
  rv = ComputeFingerprintSha256Hex(rootDER, aOutChainInfo.mRootFingerprintSha256);
  if (NS_FAILED(rv)) {
    return rv;
  }

  const nsTArray<uint8_t>& issuerDER =
      aBuiltChain.Length() > 1 ? aBuiltChain[1] : rootDER;
  rv = ComputeFingerprintSha256Hex(
      issuerDER, aOutChainInfo.mImmediateIssuerFingerprintSha256);
  if (NS_FAILED(rv)) {
    return rv;
  }

  EnterpriseCertInfo issuerInfo;
  rv = ExtractCertInfo(issuerDER, issuerInfo);
  if (NS_FAILED(rv)) {
    return rv;
  }
  aOutChainInfo.mImmediateIssuerCommonName = issuerInfo.mCommonName;

  return NS_OK;
}

}  // namespace mozilla::psm::enterprise
