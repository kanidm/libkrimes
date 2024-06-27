use der::asn1::OctetString;
use der::Sequence;

/// ```text
/// TransitedEncoding       ::= SEQUENCE {
///        tr-type         [0] Int32 -- must be registered --,
///        contents        [1] OCTET STRING
///}
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct TransitedEncoding {
    #[asn1(context_specific = "0")]
    tr_type: i32,
    #[asn1(context_specific = "1")]
    contents: OctetString,
}
