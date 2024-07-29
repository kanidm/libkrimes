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

    PreauthUnsupported,
    PreauthMissingEtypeInfo2,
    PreauthInvalidUnixTs,
    PreauthInvalidS2KParams,

    NameNotPrincipal,

    UnsupportedCredentialCacheType,
    IoError(std::io::Error),
    BinRWError(binrw::Error),

    InvalidMessageType,
    InvalidMessageDirection,
    InvalidPvno,
    InvalidEncryptionKey,
    InvalidEnumValue(String, i32),
}
