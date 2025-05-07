use crate::error::KrbError;
use der::asn1::Ia5String;
use der::DecodeValue;
use der::EncodeValue;
use der::FixedTag;
use der::Tag;
use std::fmt;
use std::str::FromStr;

/// ```text
/// KerberosString  ::= GeneralString (IA5String)
/// ````
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct KerberosString(pub(crate) Ia5String);

impl FixedTag for KerberosString {
    const TAG: Tag = Tag::GeneralString;
}

impl<'a> DecodeValue<'a> for KerberosString {
    type Error = der::Error;

    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        let r: Ia5String = der::asn1::Ia5String::decode_value(reader, header)?;
        Ok(Self(r))
    }
}

impl EncodeValue for KerberosString {
    fn value_len(&self) -> der::Result<der::Length> {
        Ia5String::value_len(&self.0)
    }
    fn encode_value(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        Ia5String::encode_value(&self.0, encoder)
    }
}

impl fmt::Display for KerberosString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for KerberosString {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl KerberosString {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
}

impl From<&KerberosString> for String {
    fn from(value: &KerberosString) -> Self {
        value.to_string()
    }
}

impl FromStr for KerberosString {
    type Err = KrbError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ia5String::new(s)
            .map_err(|_| KrbError::DerEncodeKerberosString)
            .map(KerberosString)
    }
}
