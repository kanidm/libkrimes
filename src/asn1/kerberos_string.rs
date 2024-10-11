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

impl Into<String> for KerberosString {
    fn into(self) -> String {
        self.0.to_string()
    }
}

impl Into<String> for &KerberosString {
    fn into(self) -> String {
        self.0.to_string()
    }
}

impl KerberosString {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for KerberosString {
    fn from(value: String) -> Self {
        KerberosString(Ia5String::new(&value).expect("Failed to build Ia5String"))
    }
}

impl From<&str> for KerberosString {
    fn from(value: &str) -> Self {
        KerberosString(Ia5String::new(value).expect("Failed to build Ia5String"))
    }
}
