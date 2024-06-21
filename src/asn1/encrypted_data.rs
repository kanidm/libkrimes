use der::asn1::OctetString;
use der::Sequence;

/// ```text
/// EncryptedData   ::= SEQUENCE {
///         etype   [0] Int32 -- EncryptionType --,
///         kvno    [1] UInt32 OPTIONAL,
///         cipher  [2] OCTET STRING -- ciphertext
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct EncryptedData {
    #[asn1(context_specific = "0")]
    etype: i32,
    #[asn1(context_specific = "1", optional = "true")]
    kvno: Option<u32>,
    #[asn1(context_specific = "2")]
    cipher: OctetString,
}

#[cfg(test)]
mod tests {
    use crate::asn1::constants::EncryptionType;
    use crate::asn1::encrypted_data::EncryptedData;
    use crate::asn1::pa_enc_ts_enc::PaEncTsEnc;
    use der::{Decode, DateTime};

    #[test]
    fn encrypted_data_parse() {
        let blob = "3041a003020112a23a0438a708af058781f75eb72d318ecae2f2830aa8ad4c659faeb477e29e131f923db70a33247ed25aa9d7dda218bcdbdf2203e2125fce1465265e";
        let blob = hex::decode(&blob).expect("Failed to decode sample");
        let edata = EncryptedData::from_der(&blob).expect("Failed to decode");
        assert_eq!(edata.etype, EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32);
        let tcipher = hex::decode("a708af058781f75eb72d318ecae2f2830aa8ad4c659faeb477e29e131f923db70a33247ed25aa9d7dda218bcdbdf2203e2125fce1465265e").expect("Failed to decode sample");
        assert_eq!(edata.cipher.as_bytes(), tcipher);

        let key = kerberos_crypto::aes_hmac_sha1::generate_key_from_string(
            "Suse1234",
            b"AFOREST.ADuser1",
            &kerberos_crypto::AesSizes::Aes256
        );
        let plain = kerberos_crypto::aes_hmac_sha1::decrypt(&key, 1, edata.cipher.as_bytes(), &kerberos_crypto::AesSizes::Aes256).expect("Failed to decrypt");
        let paenctsenc = PaEncTsEnc::from_der(&plain).expect("Failed to decode");
        assert_eq!(paenctsenc.patimestamp.to_date_time(), DateTime::new(2024, 6, 12, 11, 48, 7).expect("Failed to build datetime"));
        assert_eq!(paenctsenc.pausec, Some(751259));
    }
}
