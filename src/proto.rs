use tracing::*;

use crate::asn1::{
    constants::{
        encryption_types::EncryptionType,
        message_types::KrbMessageType
    },
    kdc_req::KdcReq,
    krb_kdc_req::KrbKdcReq,
    kdc_req_body::KdcReqBody,
    kerberos_flags::KerberosFlags,
    kerberos_time::KerberosTime,
    kerberos_string::KerberosString,
    principal_name::PrincipalName,
    Ia5String,
    DateTime,
};

use bytes::BytesMut;

use std::time::SystemTime;


#[derive(Debug)]
pub enum KerberosRequest {
    AsReq(KerberosAsReq),
}

#[derive(Debug)]
pub struct KerberosAsReqBuilder {
    client_name: String,
    service_name: String,
    until: SystemTime,
    from: Option<SystemTime>,
}



/*
pub enum KerberosResponse {
    AsRep(KerberosAsRep),
}
*/


#[derive(Debug)]
pub struct KerberosAsReq {
    client_name: String,
    service_name: String,
    until: SystemTime,
    from: Option<SystemTime>,
}

impl KerberosRequest {
    pub fn build_asreq(
        client_name: String,
        service_name: String,
        until: SystemTime,
    ) -> KerberosAsReqBuilder {
        KerberosAsReqBuilder {
            client_name,
            service_name,
            until,
            from: None,
        }
    }

    pub(crate) fn write_to(&self, buf: &mut BytesMut) -> Result<(), ()> {
        let asn_struct = match self {
            KerberosRequest::AsReq(as_req) =>
                KrbKdcReq::AsReq(
                    as_req.to_asn()
                ),
        };

        trace!(?asn_struct);

        let length = asn_struct.encoded_len().unwrap();
        let length = u32::try_from(length).unwrap();

        // We need to fit a u32 in here too because of how krb works.
        buf.resize(4 + length, 0);

        buf.extend_from_slice(&length.to_be_bytes());
        asn_struct.encode_to_slice(&mut buf).unwrap();

        Ok(())
    }
}

impl KerberosAsReqBuilder {
    pub fn build(self) -> KerberosRequest {
        let KerberosAsReqBuilder {
            client_name,
            service_name,
            until,
            from
        } = self;

        KerberosRequest::AsReq(
            KerberosAsReq {
                client_name,
                service_name,
                until,
                from
            }
        )
    }
}

impl KerberosAsReq {

    fn to_asn(&self) -> KdcReq {

        // TODO MAKE THIS RANDOM
        let nonce = 12345;

        KdcReq {
            pvno: 5,
            // I think it's 10 on asreq?
            msg_type: KrbMessageType::KrbAsReq as u8,
            padata: None,
            req_body: KdcReqBody {
                // No flags
                kdc_options: KerberosFlags::Reserved.into(),
                cname: Some(PrincipalName {
                    // Should be some kind of enum probably?
                    name_type: 1,
                    name_string: vec![KerberosString(Ia5String::new(
                        &self.client_name
                    ).unwrap())],
                }),
                realm: KerberosString(Ia5String::new("EXAMPLE.COM").unwrap()),
                sname: Some(PrincipalName {
                    name_type: 2,
                    name_string: vec![KerberosString(Ia5String::new(
                        &self.service_name
                    ).unwrap())],
                }),
                from: self.from
                    .map(|t| KerberosTime::from_system_time(t).unwrap()),
                till:
                        KerberosTime::from_system_time(
                            self.until
                        )
                        .unwrap(),
                rtime: None,
                nonce,
                etype: vec![
                    EncryptionType::AES128_CTS_HMAC_SHA256_128 as i32
                ],
                addresses: None,
                enc_authorization_data: None,
                additional_tickets: None,
            },
        }
    }
}



