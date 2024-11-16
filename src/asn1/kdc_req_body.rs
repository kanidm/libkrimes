use super::encrypted_data::EncryptedData;
use super::host_addresses::HostAddresses;
use super::kdc_options::KdcOptions;
use super::kerberos_time::KerberosTime;
use super::principal_name::PrincipalName;
use super::realm::Realm;
use super::tagged_ticket::TaggedTicket;
use der::Sequence;

/// ```text
/// KDC-REQ-BODY    ::= SEQUENCE {
///         kdc-options             [0] KDCOptions,
///         cname                   [1] PrincipalName OPTIONAL
///                                     -- Used only in AS-REQ --,
///         realm                   [2] Realm
///                                     -- Server's realm
///                                     -- Also client's in AS-REQ --,
///         sname                   [3] PrincipalName OPTIONAL,
///         from                    [4] KerberosTime OPTIONAL,
///         till                    [5] KerberosTime,
///         rtime                   [6] KerberosTime OPTIONAL,
///         nonce                   [7] UInt32,
///         etype                   [8] SEQUENCE OF Int32 -- EncryptionType
///                                     -- in preference order --,
///         addresses               [9] HostAddresses OPTIONAL,
///         enc-authorization-data  [10] EncryptedData OPTIONAL
///                                     -- AuthorizationData --,
///         additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
///                                         -- NOTE: not empty
/// }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct KdcReqBody {
    #[asn1(context_specific = "0")]
    pub(crate) kdc_options: KdcOptions,
    #[asn1(context_specific = "1", optional = "true")]
    pub(crate) cname: Option<PrincipalName>,
    #[asn1(context_specific = "2")]
    pub(crate) realm: Realm,
    #[asn1(context_specific = "3", optional = "true")]
    pub(crate) sname: Option<PrincipalName>,
    #[asn1(context_specific = "4", optional = "true")]
    pub(crate) from: Option<KerberosTime>,
    #[asn1(context_specific = "5")]
    pub(crate) till: KerberosTime,
    #[asn1(context_specific = "6", optional = "true")]
    pub(crate) rtime: Option<KerberosTime>,
    #[asn1(context_specific = "7")]
    pub(crate) nonce: u32,
    #[asn1(context_specific = "8")]
    pub(crate) etype: Vec<i32>,
    #[asn1(context_specific = "9", optional = "true")]
    pub(crate) addresses: Option<HostAddresses>,
    #[asn1(context_specific = "10", optional = "true")]
    pub(crate) enc_authorization_data: Option<EncryptedData>,
    #[asn1(context_specific = "11", optional = "true")]
    pub(crate) additional_tickets: Option<Vec<TaggedTicket>>,
}


#[cfg(test)]
mod tests {
    use super::KdcReqBody;
    use der::Decode;

    #[test]
    fn krb_kdc_req_heimal_macos() {
        let _ = tracing_subscriber::fmt::try_init();
        // Sample taken from macos while attempting to access a samba share.
        //
        // FIRST ISSUE HERE
        // called `Result::unwrap()` on an `Err` value: Error { kind: Value { tag: Tag(0x02: INTEGER) }, position: None }
        //
        // tracing::debug!(kdc_req_body = hex::encode(&req_body.to_der().unwrap()));

        let req_body_bytes = hex::decode("3079a00703050000000000a2151b134445562e4649525354594541522e49442e4155a32c302aa003020101a12330211b04636966731b1966696c65732e6465762e6669727374796561722e69642e6175a511180f31393730303130313030303030305aa7060204cd5c0274a80e300c020112020111020110020117").unwrap();
        let req_body = der::Any::from_der(&req_body_bytes).unwrap();

        let req_body = req_body.decode_as::<KdcReqBody>().unwrap();
        tracing::trace!(?req_body);
    }

}
