use super::enc_kdc_rep_part::EncKdcRepPart;
use der::{Tag, TagNumber, Writer};

/// ```text
///  EncASRepPart    ::= [APPLICATION 25] EncKDCRepPart
///  EncTGSRepPart   ::= [APPLICATION 26] EncKDCRepPart
/// ```
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum TaggedEncKdcRepPart {
    EncAsRepPart(EncKdcRepPart),
    EncTgsRepPart(EncKdcRepPart),
}

impl<'a> ::der::Decode<'a> for TaggedEncKdcRepPart {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let tag: der::Tag = decoder.decode()?;
        let _len: der::Length = decoder.decode()?;

        match tag {
            Tag::Application {
                constructed: true,
                number: TagNumber::N25,
            } => {
                let enc_kdc_rep_part: EncKdcRepPart = decoder.decode()?;
                Ok(TaggedEncKdcRepPart::EncAsRepPart(enc_kdc_rep_part))
            }
            Tag::Application {
                constructed: true,
                number: TagNumber::N26,
            } => {
                let enc_kdc_rep_part: EncKdcRepPart = decoder.decode()?;
                Ok(TaggedEncKdcRepPart::EncTgsRepPart(enc_kdc_rep_part))
            }
            _ => Err(der::Error::from(der::ErrorKind::TagUnexpected {
                expected: None,
                actual: tag,
            })),
        }
    }
}

impl ::der::Encode for TaggedEncKdcRepPart {
    fn encoded_len(&self) -> Result<der::Length, der::Error> {
        let len: der::Length = match self {
            TaggedEncKdcRepPart::EncAsRepPart(enc_as_rep_part) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber::N25,
                }
                .encoded_len()?
                    + enc_as_rep_part.encoded_len()?
                    + enc_as_rep_part.encoded_len()?.encoded_len()?
            }
            TaggedEncKdcRepPart::EncTgsRepPart(enc_tgs_rep_part) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber::N26,
                }
                .encoded_len()?
                    + enc_tgs_rep_part.encoded_len()?
                    + enc_tgs_rep_part.encoded_len()?.encoded_len()?
            }
        }?;
        Ok(len)
    }

    fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
        match self {
            TaggedEncKdcRepPart::EncAsRepPart(enc_as_rep_part) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber::N25,
                }
                .encode(writer)?;
                enc_as_rep_part.encoded_len()?.encode(writer)?;
                enc_as_rep_part.encode(writer)
            }
            TaggedEncKdcRepPart::EncTgsRepPart(enc_tgs_rep_part) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber::N26,
                }
                .encode(writer)?;
                enc_tgs_rep_part.encoded_len()?.encode(writer)?;
                enc_tgs_rep_part.encode(writer)
            }
        }
    }
}
