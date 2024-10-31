use super::{
    authorization_data::AuthorizationData, checksum::Checksum, encryption_key::EncryptionKey,
    kerberos_time::KerberosTime, microseconds::Microseconds, principal_name::PrincipalName,
    realm::Realm,
};
use der::{Decode, DecodeValue, Encode, EncodeValue, FixedTag, Sequence, Tag, TagNumber};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// ```text
/// Authenticator   ::= [APPLICATION 2] SEQUENCE  {
///        authenticator-vno       [0] INTEGER (5),
///        crealm                  [1] Realm,
///        cname                   [2] PrincipalName,
///        cksum                   [3] Checksum OPTIONAL,
///        cusec                   [4] Microseconds,
///        ctime                   [5] KerberosTime,
///        subkey                  [6] EncryptionKey OPTIONAL,
///        seq-number              [7] UInt32 OPTIONAL,
///        authorization-data      [8] AuthorizationData OPTIONAL
/// }
///```
#[derive(Debug, Eq, PartialEq, Sequence)]
pub(crate) struct AuthenticatorInner {
    #[asn1(context_specific = "0")]
    // This field specifies the version number for the format of the
    // authenticator.
    pub(crate) authenticator_vno: u8,
    #[asn1(context_specific = "1")]
    // This field contains the name of the realm in which the client is
    // registered and in which initial authentication took place.
    pub(crate) crealm: Realm,
    #[asn1(context_specific = "2")]
    // This field contains the name part of the client's principal identifier.
    pub(crate) cname: PrincipalName,
    #[asn1(context_specific = "3", optional = "true")]
    // This field contains a checksum of the application data that
    // accompanies the KRB_AP_REQ, computed using a key usage value of 10
    // in normal application exchanges, or 6 when used in the TGS-REQ
    // PA-TGS-REQ AP-DATA field.
    pub(crate) cksum: Option<Checksum>,
    #[asn1(context_specific = "4")]
    // This field contains the microsecond part of the client's
    // timestamp.  Its value (before encryption) ranges from 0 to 999999.
    // It often appears along with ctime.  The two fields are used
    // together to specify a reasonably accurate timestamp.
    pub(crate) cusec: Microseconds,
    #[asn1(context_specific = "5")]
    // This field contains the current time on the client's host.
    pub(crate) ctime: KerberosTime,
    #[asn1(context_specific = "6", optional = "true")]
    // This field contains the client's choice for an encryption key to
    // be used to protect this specific application session.  Unless an
    // application specifies otherwise, if this field is left out, the
    // session key from the ticket will be used.
    pub(crate) subkey: Option<EncryptionKey>,
    #[asn1(context_specific = "7", optional = "true")]
    // This optional field includes the initial sequence number to be
    // used by the KRB_PRIV or KRB_SAFE messages when sequence numbers
    // are used to detect replays.  (It may also be used by application
    // specific messages.)  When included in the authenticator, this
    // field specifies the initial sequence number for messages from the
    // client to the server.  When included in the AP-REP message, the
    // initial sequence number is that for messages from the server to
    // the client.  When used in KRB_PRIV or KRB_SAFE messages, it is
    // incremented by one after each message is sent.  Sequence numbers
    // fall in the range 0 through 2^32 - 1 and wrap to zero following
    // the value 2^32 - 1.
    //
    // For sequence numbers to support the detection of replays
    // adequately, they SHOULD be non-repeating, even across connection
    // boundaries.  The initial sequence number SHOULD be random and
    // uniformly distributed across the full space of possible sequence
    // numbers, so that it cannot be guessed by an attacker and so that
    // it and the successive sequence numbers do not repeat other
    // sequences.  In the event that more than 2^32 messages are to be
    // generated in a series of KRB_PRIV or KRB_SAFE messages, rekeying
    // SHOULD be performed before sequence numbers are reused with the
    // same encryption key.
    pub(crate) seq_number: Option<u32>,
    #[asn1(context_specific = "8", optional = "true")]
    // This field is the same as described for the ticket in Section 5.3.
    // It is optional and will only appear when additional restrictions
    // are to be placed on the use of a ticket, beyond those carried in
    // the ticket itself.
    pub(crate) authorization_data: Option<AuthorizationData>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Authenticator(AuthenticatorInner);

impl Authenticator {
    pub fn new(
        client_name: PrincipalName,
        client_realm: Realm,
        client_time: SystemTime,
        checksum: Option<Checksum>,
        subkey: Option<EncryptionKey>,
        sequence_number: Option<u32>,
        authorization_data: Option<AuthorizationData>,
    ) -> Self {
        let client_time: Duration = client_time
            .duration_since(UNIX_EPOCH)
            .expect("System time before unix epoch");
        let cusec: Microseconds = client_time.subsec_micros();
        let ctime: KerberosTime =
            KerberosTime::from_unix_duration(Duration::from_secs(client_time.as_secs()))
                .expect("Failed to build KerberosTime");
        let a: AuthenticatorInner = AuthenticatorInner {
            authenticator_vno: 5,
            crealm: client_realm,
            cname: client_name,
            cksum: checksum,
            cusec,
            ctime,
            subkey,
            seq_number: sequence_number,
            authorization_data,
        };
        Self(a)
    }
}

impl FixedTag for Authenticator {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::N2,
    };
}

impl<'a> DecodeValue<'a> for Authenticator {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        let inner: AuthenticatorInner = AuthenticatorInner::decode(reader)?;
        Ok(Self(inner))
    }
}

impl<'a> EncodeValue for Authenticator {
    fn value_len(&self) -> der::Result<der::Length> {
        self.0.encoded_len()
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        self.0.encode(encoder)?;
        Ok(())
    }
}

impl Into<AuthenticatorInner> for Authenticator {
    fn into(self) -> AuthenticatorInner {
        self.0
    }
}
