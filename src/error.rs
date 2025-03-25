#[derive(Debug)]
pub enum KrbError {
    // IMPORTANT: Don't add values to this enum - it's a potential security risk
    // as you can leak internal state in an error. If you want to debug the error,
    // then use the error! macro at the error raise site to report relevant information.
    InvalidHmacSha1Key,
    MessageAuthenticationFailed,
    MessageEmpty,
    InsufficientData,
    PlaintextEmpty,
    CtsCiphertextInvalid,
    InsecurePassphrase,
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
    DerEncodeKerberosString,
    DerError(der::Error),
    DerEncodeKerberosTime,

    PreauthUnsupported,
    PreauthMissingEtypeInfo2,
    PreauthInvalidUnixTs,
    PreauthInvalidS2KParams,

    TgsMissingPaApReq,
    TgsInvalidPaApReq,

    TgsAuthMissingChecksum,
    TgsAuthChecksumFailure,
    TgsNotForRealm,
    TgsTicketIsNotTgt,
    TgsKdcReqMissingServiceName,
    TgsKdcMissingStartTime,

    NameNotPrincipal,
    NameNotServiceHost,
    NameNumberOfComponents,
    PrincipalNameInvalidComponents,
    PrincipalNameInvalidType,

    CredentialCacheCannotCreate(String),
    UnsupportedCredentialCacheType,
    UnsupportedKeytabType,
    IoError(std::io::Error),
    BinRWError(binrw::Error),
    KeyutilsError(errno::Errno),
    FromHexError(hex::FromHexError),

    InvalidMessageType,
    InvalidMessageDirection,
    InvalidPvno,
    InvalidEncryptionKey,
    InvalidEnumValue(String, i32),
}

impl From<der::Error> for KrbError {
    fn from(value: der::Error) -> Self {
        KrbError::DerError(value)
    }
}

impl From<binrw::Error> for KrbError {
    fn from(value: binrw::Error) -> Self {
        KrbError::BinRWError(value)
    }
}

impl From<std::io::Error> for KrbError {
    fn from(value: std::io::Error) -> Self {
        KrbError::IoError(value)
    }
}

impl From<hex::FromHexError> for KrbError {
    fn from(value: hex::FromHexError) -> Self {
        KrbError::FromHexError(value)
    }
}
