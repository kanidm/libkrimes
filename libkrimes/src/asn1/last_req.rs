use super::kerberos_time::KerberosTime;
use der::Sequence;

/// ```text
/// LastReq         ::=     SEQUENCE OF SEQUENCE {
///         lr-type         [0] Int32,
///         lr-value        [1] KerberosTime
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct LastReqItem {
    #[asn1(context_specific = "0")]
    pub lr_type: i32,
    #[asn1(context_specific = "1")]
    pub lr_value: KerberosTime,
}

pub(crate) type LastReq = Vec<LastReqItem>;
