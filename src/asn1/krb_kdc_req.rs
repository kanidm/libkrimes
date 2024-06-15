use super::kdc_req::KdcReq;
use der::{Tag, TagNumber};

/// ```text
/// AS-REQ          ::= [APPLICATION 10] KDC-REQ
/// TGS-REQ         ::= [APPLICATION 12] KDC-REQ
/// ```
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum KrbKdcReq {
    AsReq(KdcReq),
    TgsReq(KdcReq),
}

impl<'a> ::der::Decode<'a> for KrbKdcReq {
    fn decode<R: der::Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        let tag: der::Tag = decoder.decode()?;
        let _len: der::Length = decoder.decode()?;

        match tag {
            Tag::Application {
                constructed: true,
                number: TagNumber::N10,
            } => {
                let kdc_req: KdcReq = decoder.decode()?;
                Ok(KrbKdcReq::AsReq(kdc_req))
            }
            Tag::Application {
                constructed: true,
                number: TagNumber::N12,
            } => {
                let kdc_req: KdcReq = decoder.decode()?;
                Ok(KrbKdcReq::TgsReq(kdc_req))
            }
            _ => Err(der::Error::from(der::ErrorKind::TagUnexpected {
                expected: None,
                actual: tag,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::asn1::constants::{EncryptionType, KrbMessageType, PaDataType};
    use crate::asn1::kdc_req::KdcReq;
    use crate::asn1::kerberos_flags::KerberosFlags;
    use crate::asn1::kerberos_time::KerberosTime;
    use crate::asn1::krb_kdc_req::KrbKdcReq;
    use core::iter::zip;
    use der::asn1::OctetString;
    use der::flagset::FlagSet;
    use der::DateTime;
    use der::Decode;
    use tracing::*;

    struct TestPaData {
        padata_type: u32,
        padata_value: Vec<u8>,
    }

    struct TestAsReq {
        blob: String,
        principal: String,
        realm: String,
        padata: Vec<TestPaData>,
        kdc_options: FlagSet<KerberosFlags>,
        from: Option<KerberosTime>,
        till: KerberosTime,
        rtime: Option<KerberosTime>,
        nonce: u32,
        etype: Vec<i32>,
        addresses: Option<Vec<(i32, OctetString)>>,
    }

    fn verify_as_req(asreq: &KdcReq, tasreq: &TestAsReq) {
        assert_eq!(asreq.pvno, 5);
        assert_eq!(asreq.msg_type, KrbMessageType::KrbAsReq.into());

        let pa = asreq.padata.as_ref().unwrap();
        assert_eq!(pa.len(), tasreq.padata.len());
        let iter = zip(pa, &tasreq.padata);
        for (pa, tpa) in iter {
            assert_eq!(pa.padata_type, tpa.padata_type);
            assert_eq!(pa.padata_value.as_bytes(), tpa.padata_value);
        }

        let bits = asreq.req_body.kdc_options;
        assert_eq!(bits, tasreq.kdc_options);

        let ref cname = &asreq.req_body.cname.as_ref().unwrap();
        assert_eq!(cname.name_type, 1);
        assert_eq!(cname.name_string[0].0.to_string(), tasreq.principal);

        assert_eq!(asreq.req_body.realm.0.to_string(), tasreq.realm);

        let ref sname = &asreq.req_body.sname.as_ref().unwrap();
        assert_eq!(sname.name_type, 2);
        assert_eq!(sname.name_string[0].0.to_string(), "krbtgt");
        assert_eq!(sname.name_string[1].0.to_string(), tasreq.realm);

        if let Some(trtime) = tasreq.rtime {
            let rtime = asreq.req_body.rtime.expect("rtime must be there");
            assert_eq!(rtime, trtime);
        } else {
            assert!(asreq.req_body.rtime.is_none());
        }

        assert_eq!(asreq.req_body.till, tasreq.till);

        if let Some(tfrom) = tasreq.from {
            let from = asreq.req_body.from.expect("from must be there");
            assert_eq!(from, tfrom);
        } else {
            assert!(asreq.req_body.from.is_none());
        }

        assert_eq!(asreq.req_body.nonce, tasreq.nonce);
        assert_eq!(asreq.req_body.etype, tasreq.etype);

        if let Some(taddrs) = &tasreq.addresses {
            let addrs = asreq
                .req_body
                .addresses
                .as_ref()
                .expect("addresses must be there");
            assert_eq!(addrs.len(), taddrs.len());

            let iter = zip(addrs, taddrs);
            for (addr, taddr) in iter {
                assert_eq!(addr.addr_type, taddr.0);
                assert_eq!(addr.address, taddr.1);
            }
        } else {
            assert!(asreq.req_body.addresses.is_none());
        }
    }

    #[test]
    fn krb_kdc_req_parse() {
        let samples: Vec<TestAsReq> = vec![
            TestAsReq {
                blob: "6a81b23081afa103020105a20302010aa31a3018300aa10402020096a2020400300aa10402020095a2020400a48186308183a00703050000000010a1143012a003020101a10b30091b0777696c6c69616da20b1b094b4b4443502e444556a31e301ca003020102a11530131b066b72627467741b094b4b4443502e444556a511180f32303234303431373034313534395aa70602047fbda7aea81a301802011202011102011402011302011002011702011902011a".to_string(),
                principal: "william".to_string(),
                realm: "KKDCP.DEV".to_string(),
                padata: vec![
                    TestPaData {
                        padata_type: PaDataType::PadataAsFreshness as u32,
                        padata_value: vec![],
                    },
                    TestPaData {
                        padata_type: PaDataType::EncpadataReqEncPaRep as u32,
                        padata_value: vec![],
                    }
                ],
                kdc_options: KerberosFlags::RenewableOk.into(),
                from: None,
                till: KerberosTime::from_date_time(DateTime::new(2024, 04, 17, 04, 15, 49).expect("Failed to build DateTime")),
                rtime: None,
                nonce: 2143135662,
                etype: vec![
                    EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::AES256_CTS_HMAC_SHA384_192 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA256_128 as i32,
                    EncryptionType::DES3_CBC_SHA1_KD as i32,
                    EncryptionType::RC4_HMAC as i32,
                    EncryptionType::CAMELLIA128_CTS_CMAC as i32,
                    EncryptionType::CAMELLIA256_CTS_CMAC as i32,
                ],
                addresses: None,
            },
            TestAsReq {
                blob: "6a81ff3081fca103020105a20302010aa32d302b300aa10402020096a2020400300aa10402020095a20204003011a10402020080a20904073005a0030101ffa481c03081bda00703050050010010a1123010a003020101a10930071b057573657231a20c1b0a41464f524553542e4144a31f301da003020102a11630141b066b72627467741b0a41464f524553542e4144a511180f32303234303631323134353130395aa7060204586155dda814301202011402011302011202011102011a020119a93e303c300da003020102a1060404c0a80164300da003020102a1060404ac110001300da003020102a1060404c0a86501300da003020102a10604040a95d65a".to_string(),
                principal: "user1".to_string(),
                realm: "AFOREST.AD".to_string(),
                padata: vec![
                    TestPaData {
                        padata_type: PaDataType::PadataAsFreshness as u32,
                        padata_value: vec![],
                    },
                    TestPaData {
                        padata_type: PaDataType::EncpadataReqEncPaRep as u32,
                        padata_value: vec![],
                    },
                    TestPaData {
                        padata_type: PaDataType::PaPacRequest as u32,
                        padata_value: vec![0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff],
                    }
                ],
                kdc_options: KerberosFlags::RenewableOk | KerberosFlags::Forwardable | KerberosFlags::Canonicalize | KerberosFlags::Proxiable,
                from: None,
                till: KerberosTime::from_date_time(DateTime::new(2024, 06, 12, 14, 51, 09).expect("Failed to build DateTime")),
                rtime: None,
                nonce: 1482773981,
                etype: vec![
                    EncryptionType::AES256_CTS_HMAC_SHA384_192 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA256_128 as i32,
                    EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::CAMELLIA256_CTS_CMAC as i32,
                    EncryptionType::CAMELLIA128_CTS_CMAC as i32,
                ],
                addresses: Some(vec![
                    (2, OctetString::new(vec![0xc0, 0xa8, 0x01, 0x64]).expect("Failed to build octet string")),
                    (2, OctetString::new(vec![0xAC, 0x11, 0x00, 0x01]).expect("Failed to build octet string")),
                    (2, OctetString::new(vec![0xC0, 0xA8, 0x65, 0x01]).expect("Failed to build octet string")),
                    (2, OctetString::new(vec![0x0A, 0x95, 0xD6, 0x5A]).expect("Failed to build octet string"))
                ]),
            }
        ];

        for sample in samples {
            let blob = hex::decode(&sample.blob).expect("Failed to decode sample");
            let message = KrbKdcReq::from_der(&blob).expect("Failed to decode");
            match message {
                KrbKdcReq::AsReq(asreq) => verify_as_req(&asreq, &sample),
                KrbKdcReq::TgsReq(_) => todo!(),
            }
        }
    }

    #[test]
    fn krb_kdc_req_rep_parse() {
        let _ = tracing_subscriber::fmt::try_init();

        // request = 00 00 00 cd
        let data = "6a81ca3081c7a103020105a20302010aa31a3018300aa10402020096a2020400300aa10402020095a2020400a4819e30819ba00703050000800000a1153013a003020101a10c300a1b087465737475736572a20d1b0b4558414d504c452e434f4da320301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da511180f32303234303631363035323730315aa611180f32303234303632323035323730315aa70602042e71de55a81a301802011202011102011402011302011002011702011902011a";

        let blob = hex::decode(&data)
            .expect("Failed to decode sample");
        let message = KrbKdcReq::from_der(&blob).expect("Failed to decode");

        trace!(?message);

        // response = 00 00 03 55
        let data = "6b8203513082034da003020105a10302010ba22d302b3029a103020113a2220420301e301ca003020112a1151b134558414d504c452e434f4d7465737475736572a30d1b0b4558414d504c452e434f4da4153013a003020101a10c300a1b087465737475736572a58201ba618201b6308201b2a003020105a10d1b0b4558414d504c452e434f4da220301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da382017830820174a003020112a103020101a282016604820162eac20712018638db059fc4580cb6aad87fbc722c85219b83574df7a6cee9ee5f6d83569c8ddfcd0695bd9ec215540200f905ec11f91353d6724be7fbfe9444606d39b4d85e4ae084a72a14a0f652a922da109e652b68dae1a519d2c2087b07c7d8f738738fe2276ead3c31d83bd3f8cbcc6c6ca8b5133a1cca5f09bfb45489fca80cecfc754d13f93418dc6385475400795d7f06f8ae9a146e21eeccd10f2efaa0bf1d3acde3f8d1c71cb7a555eedb1ce333a32941141c8ed7552a31df706d11be06b21c02178d2ac8bbed10964ff67b0b06e7f56f1c2422be26ac862521bf1be90b3977975a3346f2d2404342bf53b9c45d83a56c45fef0a7386ed82ffc0c4b23e10e9cb51ab18076d8fe9fc3d66d0ad9cd44764f2af929a181fe008d99de0acc44d689874ad433f1b04d129c2bb65f3070aa7c0343d9b07a44c9d031f950119f90744ff0085b0f4c08b29b281d376525736f9dd292eec03c16d2f5a681eb24bb56a682012c30820128a003020112a282011f0482011b602fe69bf3c949b575e0303ebec6975c3921b38a7479c16e68fd18d18972e670296ce1f6d005df8f423f44f9f8efcaafc8a148a141f706ddd24a2ded22f85b85c41ffe6168ba887a85f3b514e4f670818bf0f402c245cd167ef5136a72edd19e0536d0ea1863e27a227dd7207aa0d1c3d13526936636574f604bb57492feb534c1d8b15610bcce035a4de2d259103f9e63968f8b4e3f8b1e7120ef31bd390344bfabacf657ff062c8a50f12ffdf045df03d98bbc5f324b7a7eb48e4e656ceb5ee1325a394de51bb7617d6db4cda242c0aba97612dcf23816e08ca41bea80f4b2dc144422ed832c2395b61fdd9437f08fd2a3a1dd2475d61d61a102d1a38292afaded12f26318a6550328f60addb0542ac8e287d7a1c96f3593ca04";

        let blob = hex::decode(&data)
            .expect("Failed to decode sample");
        let message = KrbKdcReq::from_der(&blob).expect("Failed to decode");

        trace!(?message);
    }
}


