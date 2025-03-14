#[derive(Debug)]
pub enum KrbError {
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
    InvalidPrincipalNameType(i32),
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
