use super::pa_data::PaData;
use der::asn1::Any;
use der::Sequence;

/// ```text
/// KDC-REQ         ::= SEQUENCE {
///         -- NOTE: first tag is [1], not [0]
///         pvno            [1] INTEGER (5) ,
///         msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
///         padata          [3] SEQUENCE OF PA-DATA OPTIONAL
///                             -- NOTE: not empty --,
///         req-body        [4] KDC-REQ-BODY
/// }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub struct KdcReq {
    #[asn1(context_specific = "1")]
    pub(crate) pvno: u8,
    #[asn1(context_specific = "2")]
    pub(crate) msg_type: u8,
    #[asn1(context_specific = "3", optional = "true")]
    pub(crate) padata: Option<Vec<PaData>>,
    #[asn1(context_specific = "4")]
    pub(crate) req_body: Any,
    // pub(crate) req_body: KdcReqBody,
}
