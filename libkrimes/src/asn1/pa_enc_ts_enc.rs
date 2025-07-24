use super::kerberos_time::KerberosTime;
use super::microseconds::Microseconds;
use der::Sequence;

/// ```text
/// PA-ENC-TS-ENC           ::= SEQUENCE {
///           patimestamp     [0] KerberosTime -- client's time --,
///           pausec          [1] Microseconds OPTIONAL
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub struct PaEncTsEnc {
    #[asn1(context_specific = "0")]
    pub(crate) patimestamp: KerberosTime,
    #[asn1(context_specific = "1", optional = "true")]
    pub(crate) pausec: Option<Microseconds>,
}
