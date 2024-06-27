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
    flags: FlagSet<TicketFlags>,
    #[asn1(context_specific = "1")]
    key: EncryptionKey,
    #[asn1(context_specific = "2")]
    crealm: Realm,
    #[asn1(context_specific = "3")]
    cname: PrincipalName,
    #[asn1(context_specific = "4")]
    transited: TransitedEncoding,
    #[asn1(context_specific = "5")]
    authtime: KerberosTime,
    #[asn1(context_specific = "6", optional = "true")]
    starttime: Option<KerberosTime>,
    #[asn1(context_specific = "7")]
    endtime: KerberosTime,
    #[asn1(context_specific = "8", optional = "true")]
    till: Option<KerberosTime>,
    #[asn1(context_specific = "9", optional = "true")]
    cadr: Option<HostAddresses>,
    #[asn1(context_specific = "10", optional = "true")]
    authorization_data: Option<Vec<AuthorizationData>>,
}
