use der::asn1::OctetString;
use der::Sequence;

/// ```text
/// EncryptionKey   ::= SEQUENCE {
///         keytype         [0] Int32 -- actually encryption type --,
///         keyvalue        [1] OCTET STRING
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct EncryptionKey {
    #[asn1(context_specific = "0")]
    key_type: i32,
    #[asn1(context_specific = "0")]
    key_value: OctetString,
}
