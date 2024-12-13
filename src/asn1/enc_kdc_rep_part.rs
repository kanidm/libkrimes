use super::encryption_key::EncryptionKey;
use super::host_addresses::HostAddresses;
use super::kerberos_time::KerberosTime;
use super::last_req::LastReq;
use super::principal_name::PrincipalName;
use super::realm::Realm;
use super::ticket_flags::TicketFlags;
use der::flagset::FlagSet;
use der::Sequence;

/// ```text
/// EncKDCRepPart   ::= SEQUENCE {
///         key             [0] EncryptionKey,
///         last-req        [1] LastReq,
///         nonce           [2] UInt32,
///         key-expiration  [3] KerberosTime OPTIONAL,
///         flags           [4] TicketFlags,
///         authtime        [5] KerberosTime,
///         starttime       [6] KerberosTime OPTIONAL,
///         endtime         [7] KerberosTime,
///         renew-till      [8] KerberosTime OPTIONAL,
///         srealm          [9] Realm,
///         sname           [10] PrincipalName,
///         caddr           [11] HostAddresses OPTIONAL
/// }
/// ```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct EncKdcRepPart {
    #[asn1(context_specific = "0")]
    pub(crate) key: EncryptionKey,
    #[asn1(context_specific = "1")]
    pub(crate) last_req: LastReq,
    #[asn1(context_specific = "2")]
    pub(crate) nonce: i32,
    #[asn1(context_specific = "3", optional = "true")]
    pub(crate) key_expiration: Option<KerberosTime>,
    #[asn1(context_specific = "4")]
    pub(crate) flags: FlagSet<TicketFlags>,
    #[asn1(context_specific = "5")]
    pub(crate) auth_time: KerberosTime,
    #[asn1(context_specific = "6", optional = "true")]
    pub(crate) start_time: Option<KerberosTime>,
    #[asn1(context_specific = "7")]
    pub(crate) end_time: KerberosTime,
    #[asn1(context_specific = "8", optional = "true")]
    pub(crate) renew_till: Option<KerberosTime>,
    #[asn1(context_specific = "9")]
    pub(crate) server_realm: Realm,
    #[asn1(context_specific = "10")]
    pub(crate) server_name: PrincipalName,
    #[asn1(context_specific = "11", optional = "true")]
    pub(crate) client_addresses: Option<HostAddresses>,
}
