use crate::asn1::{
    constants::{
        encryption_types::EncryptionType, message_types::KrbMessageType, pa_data_types::PaDataType,
    },
    kdc_req::KdcReq,
    kdc_req_body::KdcReqBody,
    kerberos_flags::KerberosFlags,
    kerberos_string::KerberosString,
    kerberos_time::KerberosTime,
    krb_kdc_req::KrbKdcReq,
    pa_data::PaData,
    principal_name::PrincipalName,
    Ia5String,
};
use der::{asn1::OctetString, Encode, flagset::FlagSet};

use std::time::SystemTime;

#[derive(Debug)]
pub enum KerberosRequest {
    AsReq(KerberosAsReq),
}

#[derive(Debug)]
pub struct KerberosAsReqBuilder {
    client_name: String,
    service_name: String,
    from: Option<SystemTime>,
    until: SystemTime,
    renew: Option<SystemTime>,
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
    from: Option<SystemTime>,
    until: SystemTime,
    renew: Option<SystemTime>,
}

impl KerberosRequest {
    pub fn build_asreq(
        client_name: String,
        service_name: String,
        from: Option<SystemTime>,
        until: SystemTime,
        renew: Option<SystemTime>,
    ) -> KerberosAsReqBuilder {
        KerberosAsReqBuilder {
            client_name,
            service_name,
            from,
            until,
            renew,
        }
    }

    pub(crate) fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        match self {
            KerberosRequest::AsReq(as_req) => KrbKdcReq::to_der(&KrbKdcReq::AsReq(as_req.to_asn())),
        }
    }
}

impl KerberosAsReqBuilder {
    pub fn build(self) -> KerberosRequest {
        let KerberosAsReqBuilder {
            client_name,
            service_name,
            from,
            until,
            renew,
        } = self;

        KerberosRequest::AsReq(KerberosAsReq {
            client_name,
            service_name,
            from,
            until,
            renew,
        })
    }
}

impl KerberosAsReq {
    fn to_asn(&self) -> KdcReq {
        // TODO MAKE THIS RANDOM
        let nonce = 12345;

        KdcReq {
            pvno: 5,
            msg_type: KrbMessageType::KrbAsReq as u8,
            padata: None,
            req_body: KdcReqBody {
                kdc_options: FlagSet::<KerberosFlags>::new(0b0).expect("Failed to build kdc_options"),
                cname: Some(PrincipalName {
                    // Should be some kind of enum probably?
                    name_type: 1,
                    name_string: vec![KerberosString(Ia5String::new(&self.client_name).unwrap())],
                }),
                realm: KerberosString(Ia5String::new("EXAMPLE.COM").unwrap()),
                sname: Some(PrincipalName {
                    name_type: 2,
                    name_string: vec![
                        KerberosString(Ia5String::new(&self.service_name).unwrap()),
                        KerberosString(Ia5String::new("EXAMPLE.COM").unwrap()),
                    ],
                }),
                from: self.from.map(|t| {
                    KerberosTime::from_system_time(t)
                        .expect("Failed to build KerberosTime from SystemTime")
                }),
                till: KerberosTime::from_system_time(self.until)
                    .expect("Failed to build KerberosTime from SystemTime"),
                rtime: self.renew.map(|t| {
                    KerberosTime::from_system_time(t)
                        .expect("Failed to build KerberosTime from SystemTime")
                }),
                nonce,
                etype: vec![
                    EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                    EncryptionType::AES128_CTS_HMAC_SHA256_128 as i32,
                    EncryptionType::AES256_CTS_HMAC_SHA384_192 as i32,
                ],
                addresses: None,
                enc_authorization_data: None,
                additional_tickets: None,
            },
        }
    }
}
