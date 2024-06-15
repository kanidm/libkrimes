use der::asn1::OctetString;
use der::Sequence;

/// ```text
/// PA-DATA         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         padata-type     [1] Int32,
///         padata-value    [2] OCTET STRING -- might be encoded AP-REQ
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct PaData {
    #[asn1(context_specific = "1")]
    pub(crate) padata_type: u32,
    #[asn1(context_specific = "2")]
    pub(crate) padata_value: OctetString,
}
