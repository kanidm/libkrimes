use super::kdc_rep::KdcRep;
use der::{Tag, TagNumber, Writer};

/// ```text
/// AS-REP          ::= [APPLICATION 11] KDC-REP
/// TGS-REP         ::= [APPLICATION 13] KDC-REP
/// ```
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum KrbKdcRep {
    AsRep(KdcRep),
    TgsRep(KdcRep),
}

impl<'a> ::der::Decode<'a> for KrbKdcRep {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let tag: der::Tag = decoder.decode()?;
        let _len: der::Length = decoder.decode()?;

        match tag {
            Tag::Application {
                constructed: true,
                number: TagNumber::N11,
            } => {
                let kdc_rep: KdcRep = decoder.decode()?;
                Ok(KrbKdcRep::AsRep(kdc_rep))
            }
            Tag::Application {
                constructed: true,
                number: TagNumber::N13,
            } => {
                let kdc_rep: KdcRep = decoder.decode()?;
                Ok(KrbKdcRep::TgsRep(kdc_rep))
            }
            _ => Err(der::Error::from(der::ErrorKind::TagUnexpected {
                expected: None,
                actual: tag,
            })),
        }
    }
}

impl ::der::Encode for KrbKdcRep {
    fn encoded_len(&self) -> Result<der::Length, der::Error> {
        let len: der::Length = match self {
            KrbKdcRep::AsRep(asrep) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber::N11,
                }
                .encoded_len()?
                    + asrep.encoded_len()?
                    + asrep.encoded_len()?.encoded_len()?
            }
            KrbKdcRep::TgsRep(tgsrep) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber::N13,
                }
                .encoded_len()?
                    + tgsrep.encoded_len()?
                    + tgsrep.encoded_len()?.encoded_len()?
            }
        }?;
        Ok(len)
    }

    fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
        match self {
            KrbKdcRep::AsRep(asrep) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber::N11,
                }
                .encode(writer)?;
                asrep.encoded_len()?.encode(writer)?;
                asrep.encode(writer)
            }
            KrbKdcRep::TgsRep(tgsrep) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber::N13,
                }
                .encode(writer)?;
                tgsrep.encoded_len()?.encode(writer)?;
                tgsrep.encode(writer)
            }
        }
    }
}
