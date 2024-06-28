#[derive(Debug, Clone)]
pub enum KrbError {
    InvalidHmacSha1Key,
    MessageAuthenticationFailed,
    MessageEmpty,
    InsufficientData,
    PlaintextEmpty,
    CtsCiphertextInvalid,
    UnsupportedEncryption,
    MissingPaData,
    DerDecodePaData,
    DerDecodeEtypeInfo2,

    InvalidMessageType(i32, i32),
    InvalidEnumValue(String, i32),
}
