use der::asn1::Ia5String;
use der::DecodeValue;
use der::EncodeValue;
use der::FixedTag;
use der::Tag;

/// ```text
/// KerberosString  ::= GeneralString (IA5String)
/// ````
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct KerberosString(pub(crate) Ia5String);

impl FixedTag for KerberosString {
    const TAG: Tag = Tag::GeneralString;
}

impl<'a> DecodeValue<'a> for KerberosString {
    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let r: Ia5String = der::asn1::Ia5String::decode_value(reader, header)?;
        Ok(Self(r))
    }
}

impl<'a> EncodeValue for KerberosString {
    fn value_len(&self) -> der::Result<der::Length> {
        Ia5String::value_len(&self.0)
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        Ia5String::encode_value(&self.0, encoder)
    }
}
