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
    pub(crate) nonce: i32,
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
    fn krb_kdc_req_heimdal_macos() {
        let _ = tracing_subscriber::fmt::try_init();
        // Sample taken from macos while attempting to access a samba share.
        //
        // FIRST ISSUE HERE
        // called `Result::unwrap()` on an `Err` value: Error { kind: Value { tag: Tag(0x02: INTEGER) }, position: None }
        //
        // tracing::debug!(kdc_req_body = hex::encode(&req_body.to_der().unwrap()));

        let req_body_bytes = hex::decode(concat!(
            // Sequence
            "3079",
            // bit string
            "a007",
            "03050000000000",
            // Realm
            "a215",
            "1b134445562e4649525354594541522e49442e4155",
            // Service Name
            "a32c",
            // Sequence
            "302a",
            // Name type 1
            "a003",
            "020101",
            // The name bits
            "a123",
            // Sequence
            "3021",
            // String "cifs"
            "1b04",
            "63696673",
            // String "dev.firstyear.id.au"
            "1b19",
            "66696c65732e6465762e6669727374796561722e69642e6175",
            // Generalised time
            "a511",
            "180f31393730303130313030303030305a",
            // Nonce u32
            // BUG BUG BUG
            // KRB spec claims this is a u32, but heimdal sends i32, and MIT treats this as u31.
            // When this is negative it causes our decode to break, where MIT ignores this.
            "a706",
            "02",
            "04",
            "cd5c0274",
            // etypes
            "a80e",
            // Sequence
            "300c",
            "02",
            "01",
            "12",
            "02",
            "01",
            "11",
            "02",
            "01",
            "10",
            "02",
            "01",
            "17",
        ))
        .unwrap();
        let req_body = der::Any::from_der(&req_body_bytes).unwrap();

        tracing::trace!(?req_body);

        let req_body = req_body.decode_as::<KdcReqBody>().unwrap();
        tracing::trace!(?req_body);
    }
}
