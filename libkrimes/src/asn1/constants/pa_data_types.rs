use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, Clone, Copy, TryFromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum PaDataType {
    PaTgsReq = 1,
    PaEncTimestamp = 2,
    PaPwSalt = 3,
    Reserved4 = 4,
    PaEncUnixTime = 5, // (deprecated)
    PaSandiaSecureid = 6,
    PaSesame = 7,
    PaOsfDce = 8,
    PaCybersafeSecureid = 9,
    PaAfs3Salt = 10,
    PaEtypeInfo = 11,
    PaSamChallenge = 12, // (sam/otp)
    PaSamResponse = 13,  // (sam/otp)
    PaPkAsReqOld = 14,   // (pkinit)
    PaPkAsRepOld = 15,   // (pkinit)
    PaPkAsReq = 16,      // (pkinit)
    PaPkAsRep = 17,      // (pkinit)
    PaEtypeInfo2 = 19,   // (replaces pa-etype-info)
    PaUseSpecifiedKvno = 20,
    PaSamRedirect = 21, // (sam/otp)
    //PaGetFromTypedData = 22,     // (embedded in typed data)
    TdPadata = 22,                 // (embeds padata)
    PaSamEtypeInfo = 23,           // (sam/otp)
    PaAltPrinc = 24,               // (crawdad@fnal.gov)
    PaSamChallenge2 = 30,          // (kenh@pobox.com)
    PaSamResponse2 = 31,           // (kenh@pobox.com)
    PaExtraTgt = 41,               // Reserved extra Tgt
    TdPkinitCmsCertificates = 101, // CertificateSet from Cms
    TdKrbPrincipal = 102,          // PrincipalName
    TdKrbRealm = 103,              // Realm
    TdTrustedCertifiers = 104,     // from Pkinit
    TdCertificateIndex = 105,      // from Pkinit
    TdAppDefinedError = 106,       // application specific
    TdReqNonce = 107,              // Integer
    TdReqSeq = 108,                // Integer
    PaPacRequest = 128,            // Include Windows PAC
    PaFxCookie = 133,              // RFC6113 FAST Cookie
    PaFxFast = 136,                // RFC6113 FAST
    EncpadataReqEncPaRep = 149,    // RFC 6806
    PadataAsFreshness = 150,       // RFC 8070
    PadataSpake = 151,             // draft-ietf-kitten-krb-spake-preauth-13
}
