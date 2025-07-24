use der::asn1::OctetString;
use der::Sequence;

//```
// Checksum        ::= SEQUENCE {
//     cksumtype       [0] Int32,
//     checksum        [1] OCTET STRING
// }
//
//```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub struct Checksum {
    #[asn1(context_specific = "0")]
    // This field indicates the algorithm used to generate the accompanying checksum.
    pub(crate) checksum_type: i32,
    #[asn1(context_specific = "1")]
    // This field contains the checksum itself, encoded as an octet string.
    pub(crate) checksum: OctetString,
}
