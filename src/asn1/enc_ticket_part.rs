use super::authorization_data::AuthorizationData;
use super::encryption_key::EncryptionKey;
use super::host_addresses::HostAddresses;
use super::kerberos_time::KerberosTime;
use super::principal_name::PrincipalName;
use super::realm::Realm;
use super::ticket_flags::TicketFlags;
use super::transited_encoding::TransitedEncoding;
use der::flagset::FlagSet;
use der::Sequence;

/// ```text
/// EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
///         flags                   [0] TicketFlags,
///         key                     [1] EncryptionKey,
///         crealm                  [2] Realm,
///         cname                   [3] PrincipalName,
///         transited               [4] TransitedEncoding,
///         authtime                [5] KerberosTime,
///         starttime               [6] KerberosTime OPTIONAL,
///         endtime                 [7] KerberosTime,
///         renew-till              [8] KerberosTime OPTIONAL,
///         caddr                   [9] HostAddresses OPTIONAL,
///         authorization-data      [10] AuthorizationData OPTIONAL
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct EncTicketPart {
    #[asn1(context_specific = "0")]
    pub flags: u32,
    // flags: FlagSet<TicketFlags>,
    #[asn1(context_specific = "1")]
    pub key: EncryptionKey,
    #[asn1(context_specific = "2")]
    pub crealm: Realm,
    #[asn1(context_specific = "3")]
    pub cname: PrincipalName,
    #[asn1(context_specific = "4")]
    pub transited: TransitedEncoding,
    #[asn1(context_specific = "5")]
    pub auth_time: KerberosTime,
    #[asn1(context_specific = "6", optional = "true")]
    pub start_time: Option<KerberosTime>,
    #[asn1(context_specific = "7")]
    pub end_time: KerberosTime,
    #[asn1(context_specific = "8", optional = "true")]
    pub renew_till: Option<KerberosTime>,
    #[asn1(context_specific = "9", optional = "true")]
    pub client_addresses: Option<HostAddresses>,
    /// Per RFC4120: Experience has shown that the name of this
    /// field is confusing, and that a better name would be
    /// "restrictions".
    #[asn1(context_specific = "10", optional = "true")]
    pub authorization_data: Option<Vec<AuthorizationData>>,
}
