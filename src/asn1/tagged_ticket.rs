use super::encrypted_data::EncryptedData;
use super::principal_name::PrincipalName;
use super::realm::Realm;
use der::{DecodeValue, EncodeValue, FixedTag, Sequence, Tag, TagNumber};

/// ```text
/// Ticket          ::= [APPLICATION 1] SEQUENCE {
///         tkt-vno         [0] INTEGER (5),
///         realm           [1] Realm,
///         sname           [2] PrincipalName,
///         enc-part        [3] EncryptedData -- EncTicketPart
/// }
/// ````
#[derive(Debug, Eq, PartialEq, Sequence)]
struct Ticket {
    #[asn1(context_specific = "0")]
    tkt_vno: i8,
    #[asn1(context_specific = "1")]
    realm: Realm,
    #[asn1(context_specific = "2")]
    sname: PrincipalName,
    #[asn1(context_specific = "3")]
    enc_part: EncryptedData,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TaggedTicket(Ticket);

impl FixedTag for TaggedTicket {
    const TAG: Tag = Tag::Application {
        constructed: true,
        number: TagNumber::N1,
    };
}

impl<'a> DecodeValue<'a> for TaggedTicket {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let t: Ticket = Ticket::decode_value(reader, header)?;
        Ok(Self(t))
    }
}

impl<'a> EncodeValue for TaggedTicket {
    fn value_len(&self) -> der::Result<der::Length> {
        Ticket::value_len(&self.0)
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        Ticket::encode_value(&self.0, encoder)
    }
}
