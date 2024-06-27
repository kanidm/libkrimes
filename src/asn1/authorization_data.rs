use der::asn1::OctetString;
use der::Sequence;

/// ```text
/// AuthorizationData       ::= SEQUENCE OF SEQUENCE {
///        ad-type         [0] Int32,
///        ad-data         [1] OCTET STRING
///}
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct AuthorizationData {
    #[asn1(context_specific = "0")]
    ad_type: i32,
    #[asn1(context_specific = "1")]
    ad_data: OctetString,
}
