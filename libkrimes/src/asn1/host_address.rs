use der::asn1::OctetString;
use der::Sequence;

/// ```text
/// HostAddress     ::= SEQUENCE  {
///         addr-type       [0] Int32,
///         address         [1] OCTET STRING
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct HostAddress {
    #[asn1(context_specific = "0")]
    pub(crate) addr_type: i32,
    #[asn1(context_specific = "1")]
    pub(crate) address: OctetString,
}
