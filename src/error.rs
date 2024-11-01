#[derive(Debug)]
pub enum KrbError {
    InvalidHmacSha1Key,
    MessageAuthenticationFailed,
    MessageEmpty,
    InsufficientData,
    PlaintextEmpty,
    CtsCiphertextInvalid,
    UnsupportedEncryption,
    MissingPaData,
    MissingServiceNameWithRealm,
    MissingClientName,
    MissingRealm,
    DerDecodePaData,
    DerDecodeEtypeInfo2,
    DerEncodePaEncTsEnc,
    DerDecodePaEncTsEnc,
    DerDecodeEncKdcRepPart,
    DerEncodeEncKdcRepPart,
    DerEncodeOctetString(der::Error),
    DerEncodeEncTicketPart,
    DerEncodeAuthenticator(der::Error),
    DerDecodeAuthenticator(der::Error),
    DerEncodeApReq(der::Error),
    DerEncodeKdcReqBody(der::Error),

    PreauthUnsupported,
    PreauthMissingEtypeInfo2,
    PreauthInvalidUnixTs,
    PreauthInvalidS2KParams,

    TgsMissingPaApReq,
    TgsInvalidPaApReq,

    TgsAuthMissingChecksum,
    TgsAuthChecksumFailure,

    NameNotPrincipal,
    NameNotServiceHost,
    NameNumberOfComponents,

    UnsupportedCredentialCacheType,
    UnsupportedKeytabType,
    IoError(std::io::Error),
    BinRWError(binrw::Error),

    InvalidMessageType,
    InvalidMessageDirection,
    InvalidPvno,
    InvalidEncryptionKey,
    InvalidEnumValue(String, i32),
    InvalidPrincipalNameType(i32),
}
