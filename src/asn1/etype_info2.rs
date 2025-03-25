use super::kerberos_string::KerberosString;
use der::asn1::OctetString;
use der::Sequence;

/// ```text
/// ETYPE-INFO2-ENTRY       ::= SEQUENCE {
///         etype           [0] Int32,
///         salt            [1] KerberosString OPTIONAL,
///         s2kparams       [2] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct ETypeInfo2Entry {
    #[asn1(context_specific = "0")]
    pub(crate) etype: i32,
    #[asn1(context_specific = "1", optional = "true")]
    pub(crate) salt: Option<KerberosString>,
    #[asn1(context_specific = "2", optional = "true")]
    pub(crate) s2kparams: Option<OctetString>,
}

/// ```text
/// ETYPE-INFO2             ::= SEQUENCE SIZE (1..MAX) OF ETYPE-INFO2-ENTRY
/// ```
pub(crate) type ETypeInfo2 = Vec<ETypeInfo2Entry>;

#[cfg(test)]
mod tests {
    use crate::asn1::constants::EncryptionType;
    use crate::asn1::etype_info2::ETypeInfo2Entry;
    use der::Decode;

    #[test]
    fn etype_info2_entry_parse() {
        let blob = "3018a003020112a1111b0f41464f524553542e41447573657231";
        let blob = hex::decode(blob).expect("Failed to decode sample");
        let info2 = ETypeInfo2Entry::from_der(&blob).expect("Failed to decode");
        assert_eq!(info2.etype, EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32);
        assert_eq!(info2.salt.unwrap().0.to_string(), "AFOREST.ADuser1");
        assert!(info2.s2kparams.is_none());
    }
}
