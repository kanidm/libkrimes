#[derive(Debug)]
pub enum KrbError {
    // =========================================================================================
    // IMPORTANT: Don't add variables to variants in this  enum - it's a potential security risk
    // as you can leak internal state in an error as these can end up in userfacing contexts!!!
    //
    // In other words, any extra information you add here is a potential CVE.
    //
    // If you want to debug the error, then use the error! macro at the error raise site to
    // report relevant information.
    //
    // Lastly, the whole reason we have so many error variants is so that just from the error
    // variant alone, we already have a large amount of anonymised detail about the potential
    // cause the error.
    // =========================================================================================
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
    DerEncodeOctetString,
    DerEncodeEncTicketPart,
    DerEncodeAny,
    DerEncodeAuthenticator,
    DerDecodeAuthenticator,
    DerEncodeApReq,
    DerEncodeKdcReqBody,
    DerDecodeKdcReqBody,
    DerEncodeKerberosString,
    DerEncodeKerberosTime,
    DerEncodeKrbErrorCode,

    PreauthUnsupported,
    PreauthMissingEtypeInfo2,
    PreauthInvalidUnixTs,
    PreauthInvalidS2KParams,

    RequestTooLarge,
    RequestIoRead,

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

    CredentialCacheError,
    UnsupportedCredentialCacheType,
    UnsupportedKeytabType,
    KeytabFileError,

    IoError,
    BinRWError,
    KeyutilsError,

    InvalidMessageType,
    InvalidMessageDirection,
    InvalidPvno,
    InvalidEncryptionKey,

    LastRequestInvalidType,

    /// No really, do you have a time machine? How did you go back to before 1970?
    DoYouHaveATimeMachine,
}
