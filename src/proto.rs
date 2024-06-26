use crate::asn1::{
    constants::{encryption_types::EncryptionType, message_types::KrbMessageType},
    encrypted_data::EncryptedData as KdcEncryptedData,
    kdc_rep::KdcRep,
    kdc_req::KdcReq,
    kdc_req_body::KdcReqBody,
    kerberos_flags::KerberosFlags,
    kerberos_string::KerberosString,
    kerberos_time::KerberosTime,
    krb_kdc_rep::KrbKdcRep,
    krb_kdc_req::KrbKdcReq,
    principal_name::PrincipalName,
    Ia5String,
};
use crate::constants::AES_256_KEY_LEN;
use crate::crypto::{decrypt_aes256_cts_hmac_sha1_96, derive_key_aes256_cts_hmac_sha1_96};
use crate::error::KrbError;
use der::{flagset::FlagSet, Decode, Encode};

use std::time::SystemTime;
use tracing::trace;

#[derive(Debug)]
pub enum KerberosRequest {
    AsReq(KerberosAsReq),
}

#[derive(Debug)]
pub enum KerberosResponse {
    AsRep(KerberosAsRep),
    TgsRep(KerberosTgsRep),
}

#[derive(Debug)]
pub struct KerberosAsReqBuilder {
    client_name: String,
    service_name: String,
    from: Option<SystemTime>,
    until: SystemTime,
    renew: Option<SystemTime>,
}

#[derive(Debug)]
pub struct KerberosAsReq {
    client_name: String,
    service_name: String,
    from: Option<SystemTime>,
    until: SystemTime,
    renew: Option<SystemTime>,
}

pub enum BaseKey {
    Aes256 {
        // Todo zeroizing.
        k: [u8; AES_256_KEY_LEN],
    },
}

#[derive(Debug)]
pub enum EncryptedData {
    Aes256CtsHmacSha196 { kvno: Option<u32>, data: Vec<u8> },
}

#[derive(Debug)]
pub struct KerberosAsRep {
    pub(crate) enc_part: EncryptedData,
}

#[derive(Debug)]
pub struct KerberosTgsRep {}

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

    pub(crate) fn from_der(der: Vec<u8>) -> Result<Self, der::Error> {
        todo!();
    }

    pub(crate) fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        match self {
            KerberosRequest::AsReq(as_req) => KrbKdcReq::to_der(&KrbKdcReq::AsReq(as_req.to_asn())),
        }
    }
}

impl KerberosResponse {
    pub(crate) fn from_der(der: Vec<u8>) -> Result<Self, der::Error> {
        let response: KrbKdcRep = KrbKdcRep::from_der(&der)?;
        trace!(?response);
        let response = match response {
            KrbKdcRep::AsRep(as_rep) => {
                let as_rep = KerberosAsRep::try_from(as_rep).expect("Failed to parse as rep");
                KerberosResponse::AsRep(as_rep)
            }
            KrbKdcRep::TgsRep(_tgs_rep) => KerberosResponse::TgsRep(KerberosTgsRep {}),
        };
        Ok(response)
    }

    pub(crate) fn to_der(&self) -> Result<Vec<u8>, der::Error> {
        todo!();
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
                kdc_options: FlagSet::<KerberosFlags>::new(0b0)
                    .expect("Failed to build kdc_options"),
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
                    // MIT KRB5 claims to support these values, but if they are provided then MIT
                    // KDC's will ignore them.
                    // EncryptionType::AES128_CTS_HMAC_SHA256_128 as i32,
                    // EncryptionType::AES256_CTS_HMAC_SHA384_192 as i32,
                ],
                addresses: None,
                enc_authorization_data: None,
                additional_tickets: None,
            },
        }
    }
}

impl TryFrom<KdcRep> for KerberosAsRep {
    type Error = KrbError;

    fn try_from(rep: KdcRep) -> Result<Self, Self::Error> {
        let KdcRep {
            pvno,
            msg_type,
            padata,
            crealm,
            cname,
            ticket,
            enc_part,
        } = rep;

        // assert the pvno and msg_type
        if pvno != 5 {
            todo!();
        }

        if msg_type != 11 {
            todo!();
        }

        let enc_part = EncryptedData::try_from(enc_part)?;
        trace!(?enc_part);

        Ok(KerberosAsRep { enc_part })
    }
}

impl EncryptedData {
    pub fn derive_key(
        &self,
        passphrase: &[u8],
        realm: &[u8],
        cname: &[u8],
    ) -> Result<BaseKey, KrbError> {
        match self {
            EncryptedData::Aes256CtsHmacSha196 { .. } => {
                // todo! there is some way to get a number of rounds here
                // but I can't obviously see it?
                let iter_count = None;
                derive_key_aes256_cts_hmac_sha1_96(passphrase, realm, cname, iter_count)
                    .map(|k| BaseKey::Aes256 { k })
            }
        }
    }

    pub fn decrypt_data(&self, base_key: &BaseKey, key_usage: i32) -> Result<Vec<u8>, KrbError> {
        match (self, base_key) {
            (EncryptedData::Aes256CtsHmacSha196 { kvno: _, data }, BaseKey::Aes256 { k }) => {
                decrypt_aes256_cts_hmac_sha1_96(&k, &data, key_usage)
            }
        }
    }
}

impl TryFrom<KdcEncryptedData> for EncryptedData {
    type Error = KrbError;

    fn try_from(enc_data: KdcEncryptedData) -> Result<Self, Self::Error> {
        match enc_data.etype {
            18 => {
                // todo! there is some way to get a number of rounds here
                // but I can't obviously see it?
                let kvno = enc_data.kvno;
                let data = enc_data.cipher.into_bytes();
                Ok(EncryptedData::Aes256CtsHmacSha196 { kvno, data })
            }
            _ => Err(KrbError::UnsupportedEncryption),
        }
    }
}
