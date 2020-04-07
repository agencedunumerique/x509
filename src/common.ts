'use strict'
// **Github:** https://github.com/fidm/x509
//
// **License:** MIT

import { isIP } from 'net'

/**
 * Converts IP string into buffer, 4 bytes for IPv4, and 16 bytes for IPv6.
 * It will return null when IP string invalid.
 *
 * ```js
 * console.log(bytesFromIP('::1')) // <Buffer 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01>
 * ```
 * @param ip IP string to convert
 */
export function bytesFromIP (ip: string): Buffer | null {
  switch (isIP(ip)) {
  case 4:
    return Buffer.from(ip.split('.').map((val) => parseInt(val, 10)))
  case 6:
    const vals = ip.split(':')
    const buf = Buffer.alloc(16)
    let offset = 0
    if (vals[vals.length - 1] === '') {
      vals[vals.length - 1] = '0'
    }
    for (let i = 0; i < vals.length; i++) {
      if (vals[i] === '') {
        if (i + 1 < vals.length && vals[i + 1] !== '') {
          // reset offset for non-zero values
          offset = 16 - (vals.length - i - 1) * 2
        }
        // skip zero bytes
        continue
      }
      buf.writeUInt16BE(parseInt(vals[i], 16), offset)
      offset += 2
    }
    return buf
  default:
   return null
  }
}

/**
 * Converts 4-bytes into an IPv4 string representation or 16-bytes into
 * an IPv6 string representation. The bytes must be in network order.
 *
 * ```js
 * console.log(bytesToIP(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]))) // '::1'
 * ```
 * @param bytes buffer to convert
 */
export function bytesToIP (bytes: Buffer): string {
  switch (bytes.length) {
  case 4:
    return [bytes[0], bytes[1], bytes[2], bytes[3]].join('.')
  case 16:
    const ip = []
    let zeroAt = -1
    let zeroLen = 0
    let maxAt = -1
    let maxLen = 0

    for (let i = 0; i < bytes.length; i += 2) {
      const hex = (bytes[i] << 8) | bytes[i + 1]
      if (hex === 0) {
        zeroLen++
        if (zeroAt === -1) {
          zeroAt = ip.length
        }
        if (zeroLen > maxLen) {
          maxLen = zeroLen
          maxAt = zeroAt
        }
      } else {
        zeroAt = -1
        zeroLen = 0
      }
      ip.push(hex.toString(16))
    }

    if (maxLen > 0) {
      let padding = ''
      const rest = ip.slice(maxAt + maxLen)
      ip.length = maxAt
      if (ip.length === 0) {
        padding += ':'
      }
      if (rest.length === 0) {
        padding += ':'
      }
      ip.push(padding, ...rest)
    }
    return ip.join(':')
  default:
    return ''
  }
}

const oids: { [index: string]: string } = Object.create(null)
const oidReg = /^[0-9.]+$/

/**
 * Returns Object Identifier (dot-separated numeric string) that registered by initOID function.
 * It will return empty string if not exists.
 * @param nameOrId OID name or OID
 */
export function getOID (nameOrId: string): string {
  if (oidReg.test(nameOrId) && oids[nameOrId] !== '') {
    return nameOrId
  }
  return oids[nameOrId] == null ? '' : oids[nameOrId]
}

/**
 * Returns Object Identifier name that registered by initOID function.
 * It will return the argument nameOrId if not exists.
 * @param nameOrId OID name or OID
 */
export function getOIDName (nameOrId: string): string {
  if (!oidReg.test(nameOrId) && oids[nameOrId] !== '') {
    return nameOrId
  }
  return oids[nameOrId] == null ? nameOrId : oids[nameOrId]
}

/**
 * Register OID and name
 * @param oid Object Identifier
 * @param name Object Identifier name
 */
function initOID (oid: string, name: string) {
  oids[oid] = name
  oids[name] = oid
}

// algorithm OIDs
initOID('1.2.840.113549.1.1.1', 'rsaEncryption')
initOID('1.2.840.113549.1.1.4', 'md5WithRsaEncryption')
initOID('1.2.840.113549.1.1.5', 'sha1WithRsaEncryption')
initOID('1.2.840.113549.1.1.8', 'mgf1')
initOID('1.2.840.113549.1.1.10', 'RSASSA-PSS')
initOID('1.2.840.113549.1.1.11', 'sha256WithRsaEncryption')
initOID('1.2.840.113549.1.1.12', 'sha384WithRsaEncryption')
initOID('1.2.840.113549.1.1.13', 'sha512WithRsaEncryption')

initOID('1.2.840.10045.2.1', 'ecEncryption') // ECDSA and ECDH Public Key
initOID('1.2.840.10045.4.1', 'ecdsaWithSha1')
initOID('1.2.840.10045.4.3.2', 'ecdsaWithSha256')
initOID('1.2.840.10045.4.3.3', 'ecdsaWithSha384')
initOID('1.2.840.10045.4.3.4', 'ecdsaWithSha512')

initOID('1.2.840.10040.4.3', 'dsaWithSha1')
initOID('2.16.840.1.101.3.4.3.2', 'dsaWithSha256')

initOID('1.3.14.3.2.7', 'desCBC')
initOID('1.3.14.3.2.26', 'sha1')
initOID('2.16.840.1.101.3.4.2.1', 'sha256')
initOID('2.16.840.1.101.3.4.2.2', 'sha384')
initOID('2.16.840.1.101.3.4.2.3', 'sha512')
initOID('1.2.840.113549.2.5', 'md5')

// Algorithm Identifiers for Ed25519, Ed448, X25519 and X448 for use in the Internet X.509 Public Key Infrastructure
// https://tools.ietf.org/html/draft-ietf-curdle-pkix-10
initOID('1.3.101.110', 'X25519')
initOID('1.3.101.111', 'X448')
initOID('1.3.101.112', 'Ed25519')
initOID('1.3.101.113', 'Ed448')

// pkcs#7 content types
initOID('1.2.840.113549.1.7.1', 'data')
initOID('1.2.840.113549.1.7.2', 'signedData')
initOID('1.2.840.113549.1.7.3', 'envelopedData')
initOID('1.2.840.113549.1.7.4', 'signedAndEnvelopedData')
initOID('1.2.840.113549.1.7.5', 'digestedData')
initOID('1.2.840.113549.1.7.6', 'encryptedData')

// pkcs#9 oids
initOID('1.2.840.113549.1.9.1', 'emailAddress')
initOID('1.2.840.113549.1.9.2', 'unstructuredName')
initOID('1.2.840.113549.1.9.3', 'contentType')
initOID('1.2.840.113549.1.9.4', 'messageDigest')
initOID('1.2.840.113549.1.9.5', 'signingTime')
initOID('1.2.840.113549.1.9.6', 'counterSignature')
initOID('1.2.840.113549.1.9.7', 'challengePassword')
initOID('1.2.840.113549.1.9.8', 'unstructuredAddress')
initOID('1.2.840.113549.1.9.14', 'extensionRequest')
initOID('1.2.840.113549.1.9.20', 'friendlyName')
initOID('1.2.840.113549.1.9.21', 'localKeyId')
initOID('1.2.840.113549.1.9.22.1', 'x509Certificate')

// pkcs#12 safe bags
initOID('1.2.840.113549.1.12.10.1.1', 'keyBag')
initOID('1.2.840.113549.1.12.10.1.2', 'pkcs8ShroudedKeyBag')
initOID('1.2.840.113549.1.12.10.1.3', 'certBag')
initOID('1.2.840.113549.1.12.10.1.4', 'crlBag')
initOID('1.2.840.113549.1.12.10.1.5', 'secretBag')
initOID('1.2.840.113549.1.12.10.1.6', 'safeContentsBag')

// password-based-encryption for pkcs#12
initOID('1.2.840.113549.1.5.13', 'pkcs5PBES2')
initOID('1.2.840.113549.1.5.12', 'pkcs5PBKDF2')

// hmac OIDs
initOID('1.2.840.113549.2.7', 'hmacWithSha1')
initOID('1.2.840.113549.2.9', 'hmacWithSha256')
initOID('1.2.840.113549.2.10', 'hmacWithSha384')
initOID('1.2.840.113549.2.11', 'hmacWithSha512')

// symmetric key algorithm oids
initOID('1.2.840.113549.3.7', '3desCBC')
initOID('2.16.840.1.101.3.4.1.2', 'aesCBC128')
initOID('2.16.840.1.101.3.4.1.42', 'aesCBC256')

initOID('2.5.4.0', 'objectClass') // RFC 4512
initOID('2.5.4.1', 'aliasedObjectName') // RFC 4512
initOID('2.5.4.2', 'knowledgeInformation') // RFC 2256
initOID('2.5.4.3', 'commonName') // RFC 4519
initOID('2.5.4.4', 'surname') // RFC 4519
initOID('2.5.4.5', 'serialName') // RFC 4519
initOID('2.5.4.6', 'countryName') // RFC 4519
initOID('2.5.4.7', 'localityName') // RFC 4519
initOID('2.5.4.8', 'stateOrProvinceName') // RFC 4519
initOID('2.5.4.9', 'street') // RFC 4519
initOID('2.5.4.10', 'organizationName') // RFC 4519
initOID('2.5.4.11', 'organizationalUnitName') // RFC 4519
initOID('2.5.4.12', 'title') // RFC 4519
initOID('2.5.4.13', 'description') // RFC 4519
initOID('2.5.4.14', 'searchGuide') // RFC 4519
initOID('2.5.4.15', 'businessCategory') // RFC 4519
initOID('2.5.4.16', 'postalAddress') // RFC 4519
initOID('2.5.4.17', 'postalCode') // RFC 4519
initOID('2.5.4.18', 'postOfficeBox') // RFC 4519
initOID('2.5.4.19', 'physicalDeliveryOfficeName') // RFC 4519
initOID('2.5.4.20', 'telephoneNumber') // RFC 4519
initOID('2.5.4.21', 'telexNumber') // RFC 4519
initOID('2.5.4.22', 'teletexTerminalIdentifier') // RFC 4519
initOID('2.5.4.23', 'facsimileTelephoneNumber') // RFC 4519
initOID('2.5.4.24', 'x121Address') // RFC 4519
initOID('2.5.4.25', 'internationaliSDNNumber') // RFC 4519
initOID('2.5.4.26', 'registeredAddress') // RFC 4519
initOID('2.5.4.27', 'destinationIndicator') // RFC 4519
initOID('2.5.4.28', 'preferredDeliveryMethod') // RFC 4519
initOID('2.5.4.29', 'presentationAddress') // RFC 2256
initOID('2.5.4.30', 'supportedApplicationContext') // RFC 2256
initOID('2.5.4.31', 'member') // RFC 4519
initOID('2.5.4.32', 'owner') // RFC 4519
initOID('2.5.4.33', 'roleOccupant') // RFC 4519
initOID('2.5.4.34', 'seeAlso') // RFC 4519
initOID('2.5.4.35', 'userPassword') // RFC 4519
initOID('2.5.4.36', 'userCertificate') // RFC 4523
initOID('2.5.4.37', 'cACertificate') // RFC 4523
initOID('2.5.4.38', 'authorityRevocationList') // RFC 4523
initOID('2.5.4.39', 'certificateRevocationList') // RFC 4523
initOID('2.5.4.40', 'crossCertificatePair') // RFC 4523
initOID('2.5.4.41', 'name') // RFC 4519
initOID('2.5.4.42', 'givenName') // RFC 4519
initOID('2.5.4.43', 'initials') // RFC 4519
initOID('2.5.4.44', 'generationQualifier') // RFC 4519
initOID('2.5.4.45', 'x500UniqueIdentifier') // RFC 4519
initOID('2.5.4.46', 'dnQualifier') // RFC 4519
initOID('2.5.4.47', 'enhancedSearchGuide') // RFC 4519
initOID('2.5.4.48', 'protocolInformation') // RFC 2256
initOID('2.5.4.49', 'distinguishedName') // RFC 4519
initOID('2.5.4.50', 'uniqueMember') // RFC 4519
initOID('2.5.4.51', 'houseIdentifier') // RFC 4519
initOID('2.5.4.52', 'supportedAlgorithms') // RFC 4523
initOID('2.5.4.53', 'deltaRevocationList') // RFC 4523
initOID('2.5.4.54', 'dmdName') // RFC 2256
initOID('2.5.4.65', 'pseudonym') // RFC 2985

initOID('2.5.6.0', 'top') // RFC 4512
initOID('2.5.6.1', 'alias') // RFC 4512
initOID('2.5.6.2', 'country') // RFC 4519
initOID('2.5.6.3', 'locality') // RFC 4519
initOID('2.5.6.4', 'organization') // RFC 4519
initOID('2.5.6.5', 'organizationalUnit') // RFC 4519
initOID('2.5.6.6', 'person') // RFC 4519
initOID('2.5.6.7', 'organizationalPerson') // RFC 4519
initOID('2.5.6.8', 'organizationalRole') // RFC 4519
initOID('2.5.6.9', 'groupOfNames') // RFC 4519
initOID('2.5.6.10', 'residentialPerson') // RFC 4519
initOID('2.5.6.11', 'applicationProcess') // RFC 4519
initOID('2.5.6.12', 'applicationEntity') // RFC 4519
initOID('2.5.6.13', 'dSA') // RFC 4519
initOID('2.5.6.14', 'device') // RFC 4519
initOID('2.5.6.15', 'strongAuthenticationUser') // RFC 4519
initOID('2.5.6.16', 'certificationAuthority') // RFC 4519
initOID('2.5.6.16.2', 'certificationAuthority-V2') // RFC 4519
initOID('2.5.6.17', 'groupOfUniqueNames') // RFC 4519
initOID('2.5.6.18', 'userSecurityInformation') // RFC 4519
initOID('2.5.6.19', 'cRLDistributionPoint') // RFC 4519
initOID('2.5.6.20', 'dmd') // RFC 4519
initOID('2.5.6.21', 'pkiUser') // RFC 4519
initOID('2.5.6.22', 'pkiCA') // RFC 4519
initOID('2.5.6.23', 'deltaCRL') // RFC 4519

initOID('2.5.13.0', 'objectIdentifierMatch')
initOID('2.5.13.1', 'distinguishedNameMatch')
initOID('2.5.13.2', 'caseIgnoreMatch')
initOID('2.5.13.3', 'caseIgnoreOrderingMatch')
initOID('2.5.13.4', 'caseIgnoreSubstringsMatch')
initOID('2.5.13.5', 'caseExactMatch')
initOID('2.5.13.6', 'caseExactOrderingMatch')
initOID('2.5.13.7', 'caseExactSubstringsMatch')
initOID('2.5.13.8', 'numericStringMatch')
initOID('2.5.13.9', 'numericStringOrderingMatch')
initOID('2.5.13.10', 'numericStringSubstringsMatch')
initOID('2.5.13.11', 'caseIgnoreListMatch')
initOID('2.5.13.12', 'caseIgnoreListSubstringsMatch')
initOID('2.5.13.13', 'booleanMatch')
initOID('2.5.13.14', 'integerMatch')
initOID('2.5.13.15', 'integerOrderingMatch')
initOID('2.5.13.16', 'bitStringMatch')
initOID('2.5.13.17', 'octetStringMatch')
initOID('2.5.13.18', 'octetStringOrderingMatch')
initOID('2.5.13.20', 'telephoneNumberMatch')
initOID('2.5.13.21', 'telephoneNumberSubstringsMatch')
initOID('2.5.13.23', 'uniqueMemberMatch')
initOID('2.5.13.27', 'generalizedTimeMatch')
initOID('2.5.13.28', 'generalizedTimeOrderingMatch')
initOID('2.5.13.29', 'integerFirstComponentMatch')
initOID('2.5.13.30', 'objectIdentifierFirstComponentMatch')
initOID('2.5.13.31', 'directoryStringFirstComponentMatch')
initOID('2.5.13.32', 'wordMatch')
initOID('2.5.13.33', 'keywordMatch')

initOID('2.5.18.1', 'createTimestamp')
initOID('2.5.18.2', 'modifyTimestamp')
initOID('2.5.18.3', 'creatorsName')
initOID('2.5.18.4', 'modifiersName')
initOID('2.5.18.9', 'hasSubordinates')
initOID('2.5.18.10', 'subschemaSubentry')

initOID('2.5.20.1', 'subschema')

initOID('2.5.21.1', 'dITStructureRules')
initOID('2.5.21.2', 'dITContentRules')
initOID('2.5.21.4', 'matchingRules')
initOID('2.5.21.5', 'attributeTypes')
initOID('2.5.21.6', 'objectClasses')
initOID('2.5.21.7', 'nameForms')
initOID('2.5.21.8', 'matchingRuleUse')
initOID('2.5.21.9', 'structuralObjectClass')
initOID('2.5.21.10', 'governingStructureRule')

// X.509 extension OIDs
initOID('2.16.840.1.113730.1.1', 'nsCertType')
initOID('2.5.29.2', 'keyAttributes') // obsolete, use .37 or .15
initOID('2.5.29.4', 'keyUsageRestriction') // obsolete, use .37 or .15
initOID('2.5.29.6', 'subtreesConstraint') // obsolete, use .30
initOID('2.5.29.9', 'subjectDirectoryAttributes')
initOID('2.5.29.14', 'subjectKeyIdentifier')
initOID('2.5.29.15', 'keyUsage')
initOID('2.5.29.16', 'privateKeyUsagePeriod')
initOID('2.5.29.17', 'subjectAltName')
initOID('2.5.29.18', 'issuerAltName')
initOID('2.5.29.19', 'basicConstraints')
initOID('2.5.29.20', 'cRLNumber')
initOID('2.5.29.21', 'cRLReason')
initOID('2.5.29.22', 'expirationDate')
initOID('2.5.29.23', 'instructionCode')
initOID('2.5.29.24', 'invalidityDate')
initOID('2.5.29.27', 'deltaCRLIndicator')
initOID('2.5.29.28', 'issuingDistributionPoint')
initOID('2.5.29.29', 'certificateIssuer')
initOID('2.5.29.30', 'nameConstraints')
initOID('2.5.29.31', 'cRLDistributionPoints')
initOID('2.5.29.32', 'certificatePolicies')
initOID('2.5.29.33', 'policyMappings')
initOID('2.5.29.35', 'authorityKeyIdentifier')
initOID('2.5.29.36', 'policyConstraints')
initOID('2.5.29.37', 'extKeyUsage')
initOID('2.5.29.46', 'freshestCRL')
initOID('2.5.29.54', 'inhibitAnyPolicy')

// extKeyUsage purposes
initOID('1.3.6.1.4.1.311.60.2.1.2', 'jurisdictionST')
initOID('1.3.6.1.4.1.311.60.2.1.3', 'jurisdictionC')
initOID('1.3.6.1.4.1.11129.2.4.2', 'timestampList')
initOID('1.3.6.1.5.5.7.1.1', 'authorityInfoAccess')
initOID('1.3.6.1.5.5.7.3.1', 'serverAuth')
initOID('1.3.6.1.5.5.7.3.2', 'clientAuth')
initOID('1.3.6.1.5.5.7.3.3', 'codeSigning')
initOID('1.3.6.1.5.5.7.3.4', 'emailProtection')
initOID('1.3.6.1.5.5.7.3.8', 'timeStamping')
initOID('1.3.6.1.5.5.7.48.1', 'authorityInfoAccessOcsp')
initOID('1.3.6.1.5.5.7.48.2', 'authorityInfoAccessIssuers')
