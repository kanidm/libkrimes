use super::kdc_rep::KdcRep;
use super::krb_error::KrbError;
use der::{Tag, TagNumber, Writer};

/// ```text
/// AS-REP          ::= [APPLICATION 11] KDC-REP
/// TGS-REP         ::= [APPLICATION 13] KDC-REP
/// ```
#[derive(Debug, Eq, PartialEq)]
// For clarity and keeping to the spec, we allow this warning.
// Normally clippy likes to say "no" because each variant ends
// with 'rep'.
#[allow(clippy::enum_variant_names)]
pub(crate) enum KrbKdcRep {
    AsRep(KdcRep),
    TgsRep(KdcRep),
    ErrRep(KrbError),
}

impl<'a> ::der::Decode<'a> for KrbKdcRep {
    type Error = der::Error;

    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let tag: der::Tag = decoder.decode()?;
        let _len: der::Length = decoder.decode()?;

        match tag {
            Tag::Application {
                constructed: true,
                number: TagNumber(11),
            } => {
                let kdc_rep: KdcRep = decoder.decode()?;
                Ok(KrbKdcRep::AsRep(kdc_rep))
            }
            Tag::Application {
                constructed: true,
                number: TagNumber(13),
            } => {
                let kdc_rep: KdcRep = decoder.decode()?;
                Ok(KrbKdcRep::TgsRep(kdc_rep))
            }
            Tag::Application {
                constructed: true,
                number: TagNumber(30),
            } => {
                let err_rep: KrbError = decoder.decode()?;
                Ok(KrbKdcRep::ErrRep(err_rep))
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
                    number: TagNumber(11),
                }
                .encoded_len()?
                    + asrep.encoded_len()?
                    + asrep.encoded_len()?.encoded_len()?
            }
            KrbKdcRep::TgsRep(tgsrep) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber(13),
                }
                .encoded_len()?
                    + tgsrep.encoded_len()?
                    + tgsrep.encoded_len()?.encoded_len()?
            }
            KrbKdcRep::ErrRep(err_rep) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber(30),
                }
                .encoded_len()?
                    + err_rep.encoded_len()?
                    + err_rep.encoded_len()?.encoded_len()?
            }
        }?;
        Ok(len)
    }

    fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
        match self {
            KrbKdcRep::AsRep(asrep) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber(11),
                }
                .encode(writer)?;
                asrep.encoded_len()?.encode(writer)?;
                asrep.encode(writer)
            }
            KrbKdcRep::TgsRep(tgsrep) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber(13),
                }
                .encode(writer)?;
                tgsrep.encoded_len()?.encode(writer)?;
                tgsrep.encode(writer)
            }
            KrbKdcRep::ErrRep(err_rep) => {
                Tag::Application {
                    constructed: true,
                    number: TagNumber(30),
                }
                .encode(writer)?;
                err_rep.encoded_len()?.encode(writer)?;
                err_rep.encode(writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::asn1::encrypted_data::EncryptedData;
    use crate::asn1::kerberos_string::KerberosString;
    use crate::asn1::principal_name::PrincipalName;
    use crate::asn1::tagged_ticket::{TaggedTicket, Ticket};
    use der::asn1::Ia5String;
    use der::asn1::OctetString;
    use std::iter::zip;

    use super::KdcRep;
    use super::KrbKdcRep;
    use der::Decode;

    struct TestPaData {
        padata_type: u32,
        padata_value: Vec<u8>,
    }

    struct TestAsRep {
        blob: String,
        padata: Option<Vec<TestPaData>>,
        crealm: String,
        cname: PrincipalName,
        ticket: TaggedTicket,
        encpart: EncryptedData,
    }

    fn verify_as_rep(asrep: &KdcRep, tasrep: &TestAsRep) {
        assert_eq!(asrep.pvno, 5);
        assert_eq!(asrep.msg_type, 11);

        if let Some(tpadata) = &tasrep.padata {
            let padata = &asrep
                .padata
                .as_ref()
                .expect("AS-REP pa_data should be there");
            assert_eq!(tpadata.len(), padata.len());
            let iter = zip(*padata, tpadata);
            for (pa, tpa) in iter {
                assert_eq!(pa.padata_type, tpa.padata_type);
                assert_eq!(pa.padata_value.as_bytes(), tpa.padata_value);
            }
        }

        assert_eq!(asrep.crealm.0.as_str(), tasrep.crealm);

        assert_eq!(asrep.cname.name_type, tasrep.cname.name_type);
        assert_eq!(
            asrep.cname.name_string.len(),
            tasrep.cname.name_string.len()
        );
        let iter = zip(&asrep.cname.name_string, &tasrep.cname.name_string);
        for (name, tname) in iter {
            assert_eq!(name.0.as_str(), tname.0.as_str());
        }

        assert_eq!(asrep.ticket, tasrep.ticket);
        assert_eq!(asrep.enc_part, tasrep.encpart);
    }

    #[test]
    fn krb_kdc_rep_parse() {
        let samples: Vec<TestAsRep> = vec![
            TestAsRep {
                blob: "6b8203513082034da003020105a10302010ba22d302b3029a103020113a2220420301e301ca003020112a1151b134558414d504c452e434f4d7465737475736572a30d1b0b4558414d504c452e434f4da4153013a003020101a10c300a1b087465737475736572a58201ba618201b6308201b2a003020105a10d1b0b4558414d504c452e434f4da220301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da382017830820174a003020112a103020101a28201660482016297d16c13bbd7fdd8dac58f284e9eea01c1cc89413195aee01d12ab05c5775f701849e25fd416427693cf8cf6567180cb5c9c1bf157521fdf38316c0ddb0a824b60c98056677ace3bcbccd2c82c203aaad8a0e6df44d07c76be2ddb70349a3c23b7b7bc2211c8bcc879a704872cf46d1d650b55f75e487eafdffbae8dc00e9083e9e0b59aa275a4591a7965d5ffb15f8d96d84a9d0a5840ef5d4715f2e99b3cf3cdc961ce416e4d9e49e7a1a617d9199006d07eb886a70a49c1e8e966f99d6939c0d853636081a1ed0b9fdc4971f447cc5aa503092d91f352d451e349bf58a4320aa116d9a30e944402014aee43f51a457c01ae7f3a6863a8df05569ed969edc97f298bf93be1ed85d64914b293e6dc6ebc8229a6aa040ce7c184cf7082ab3b3b3ff53bc4b47b3512e29479b4ffe8508cfcc1f3e5ec6371039bff5b5c78facc9e00a6d818d4b6ea2be680547abbe8bd79e804814699f51fcdc531bb94613dc9923840a682012c30820128a003020112a282011f0482011be5fca41337468155848766f655f34e00f7124a268bbfc79b68d4e949aa466c05a5cdaca4f21f62303e0175b5112b544c9b8dd950c85c58498aaf0e950ac4eecebd56616c192b640bca93298f4c2ed63bef8efe82ed585847ff4af54ae74bf6d2f9103fd99f90b724df57c0f8daea1d5e801c11d49af9671a1a8a4e8be6f86219e22af04b1b2a76c09489ea3b78eda7d0cf791a598f1e238586a0563b5fa690459cc3a8be3ea6c6a1dc539e37e1e055d2473f30d51e2e91bd5387f3be96d58add57057635ed29da77eeb9d111f18416e9eb3ef192e92c39151f171bd9fbeea181ced330bb6d53ef08001db94a0276914c24ecabf7629bea0309748e4b1630a0e36159f8db557d7e2a87eeaa499ea6d8d8a17efa582ca8b1e023d9a8".to_string(),
                padata: Some(vec![
                    TestPaData { padata_type: 19_u32, padata_value: hex::decode("301e301ca003020112a1151b134558414d504c452e434f4d7465737475736572").expect("Failed to hex encode") }
                ]),
                crealm: "EXAMPLE.COM".to_string(),
                cname: PrincipalName {
                    name_type: 1_i32,
                    name_string: vec![
                        KerberosString(Ia5String::new("testuser").expect("Failed to build test Ia5String"))
                    ]
                },
                ticket: TaggedTicket::new(
                    Ticket {
                        tkt_vno: 5,
                        realm: KerberosString(Ia5String::new("EXAMPLE.COM").expect("Failed to build Ia5String")),
                        sname: PrincipalName {
                            name_type: 2_i32,
                            name_string: vec![
                                KerberosString(Ia5String::new("krbtgt").expect("Failed to build test Ia5String")),
                                KerberosString(Ia5String::new("EXAMPLE.COM").expect("Failed to build test Ia5String"))
                            ],
                        },
                        enc_part: EncryptedData {
                            etype: 18,
                            kvno: Some(1),
                            cipher: OctetString::new(hex::decode("97d16c13bbd7fdd8dac58f284e9eea01c1cc89413195aee01d12ab05c5775f701849e25fd416427693cf8cf6567180cb5c9c1bf157521fdf38316c0ddb0a824b60c98056677ace3bcbccd2c82c203aaad8a0e6df44d07c76be2ddb70349a3c23b7b7bc2211c8bcc879a704872cf46d1d650b55f75e487eafdffbae8dc00e9083e9e0b59aa275a4591a7965d5ffb15f8d96d84a9d0a5840ef5d4715f2e99b3cf3cdc961ce416e4d9e49e7a1a617d9199006d07eb886a70a49c1e8e966f99d6939c0d853636081a1ed0b9fdc4971f447cc5aa503092d91f352d451e349bf58a4320aa116d9a30e944402014aee43f51a457c01ae7f3a6863a8df05569ed969edc97f298bf93be1ed85d64914b293e6dc6ebc8229a6aa040ce7c184cf7082ab3b3b3ff53bc4b47b3512e29479b4ffe8508cfcc1f3e5ec6371039bff5b5c78facc9e00a6d818d4b6ea2be680547abbe8bd79e804814699f51fcdc531bb94613dc9923840").expect("Failed to hex decode")).expect("Failed to build OctetString"),
                        },
                    }
                ),
                encpart: EncryptedData {
                    etype: 18,
                    kvno: None,
                    cipher: OctetString::new(hex::decode("e5fca41337468155848766f655f34e00f7124a268bbfc79b68d4e949aa466c05a5cdaca4f21f62303e0175b5112b544c9b8dd950c85c58498aaf0e950ac4eecebd56616c192b640bca93298f4c2ed63bef8efe82ed585847ff4af54ae74bf6d2f9103fd99f90b724df57c0f8daea1d5e801c11d49af9671a1a8a4e8be6f86219e22af04b1b2a76c09489ea3b78eda7d0cf791a598f1e238586a0563b5fa690459cc3a8be3ea6c6a1dc539e37e1e055d2473f30d51e2e91bd5387f3be96d58add57057635ed29da77eeb9d111f18416e9eb3ef192e92c39151f171bd9fbeea181ced330bb6d53ef08001db94a0276914c24ecabf7629bea0309748e4b1630a0e36159f8db557d7e2a87eeaa499ea6d8d8a17efa582ca8b1e023d9a8").expect("Failed to hex decode")).expect("Failed to build OctetString"),
                },
            }
        ];

        for sample in samples {
            let blob = hex::decode(&sample.blob).expect("Failed to decode sample");
            let message = KrbKdcRep::from_der(&blob).expect("Failed to decode");
            match message {
                KrbKdcRep::AsRep(asrep) => verify_as_rep(&asrep, &sample),
                KrbKdcRep::TgsRep(_) | KrbKdcRep::ErrRep(_) => {
                    unimplemented!("TGS-REP and ErrRep not implemented")
                }
            }
        }
    }
}
