use crate::asn1::{
    constants::{
        encryption_types::EncryptionType, message_types::KrbMessageType, pa_data_types::PaDataType,
    },
    encrypted_data::EncryptedData as KdcEncryptedData,
    kdc_req::KdcReq,
    kdc_req_body::KdcReqBody,
    kerberos_time::KerberosTime,
    krb_kdc_req::KrbKdcReq,
    pa_data::PaData,
    pa_enc_ts_enc::PaEncTsEnc,
    BitString, OctetString, kerberos_flags::KerberosFlags, kdc_options, ticket_flags::TicketFlags,
};
use crate::error::KrbError;
use der::{Encode, flagset::FlagSet};
use rand::{thread_rng, Rng};

use std::time::{Duration, SystemTime};
use tracing::trace;

use super::{DerivedKey, EncryptedData, Name, Preauth, PreauthData};

#[derive(Debug)]
pub enum KerberosRequest {
    AS(AuthenticationRequest),
    TGS(TicketGrantRequest),
}

#[derive(Debug)]
pub struct TicketGrantRequest {}

#[derive(Debug)]
pub struct AuthenticationRequest {
    pub nonce: u32,
    pub client_name: Name,
    pub service_name: Name,
    pub from: Option<SystemTime>,
    pub until: SystemTime,
    pub renew: Option<SystemTime>,
    pub preauth: Preauth,
    pub etypes: Vec<EncryptionType>,
    pub kdc_options: FlagSet<KerberosFlags>
}

#[derive(Debug)]
pub struct KerberosAuthenticationBuilder {
    client_name: Name,
    service_name: Name,
    from: Option<SystemTime>,
    until: SystemTime,
    renew: Option<SystemTime>,
    preauth: Option<Preauth>,
    etypes: Vec<EncryptionType>,
}

impl KerberosRequest {
    pub fn build_as(
        client_name: Name,
        service_name: Name,
        until: SystemTime,
    ) -> KerberosAuthenticationBuilder {
        let etypes = vec![EncryptionType::AES256_CTS_HMAC_SHA1_96];

        KerberosAuthenticationBuilder {
            client_name,
            service_name,
            from: None,
            until,
            renew: None,
            preauth: None,
            etypes,
        }
    }
}

impl TryInto<KrbKdcReq> for KerberosRequest {
    type Error = KrbError;

    fn try_into(self) -> Result<KrbKdcReq, Self::Error> {
        match self {
            KerberosRequest::AS(AuthenticationRequest {
                nonce,
                client_name,
                service_name,
                from,
                until,
                renew,
                preauth,
                etypes,
                kdc_options
            }) => {
                let padata = if preauth.pa_fx_cookie.is_some() || preauth.enc_timestamp.is_some() {
                    let mut padata_inner = Vec::with_capacity(2);

                    if let Some(fx_cookie) = &preauth.pa_fx_cookie {
                        let padata_value = OctetString::new(fx_cookie.clone())
                            .map_err(|e| KrbError::DerEncodeOctetString(e))?;
                        padata_inner.push(PaData {
                            padata_type: PaDataType::PaFxCookie as u32,
                            padata_value,
                        })
                    }

                    if let Some(enc_data) = &preauth.enc_timestamp {
                        let padata_value = match enc_data {
                            EncryptedData::Aes256CtsHmacSha196 { kvno, data } => {
                                let cipher = OctetString::new(data.clone())
                                    .map_err(|e| KrbError::DerEncodeOctetString(e))?;
                                KdcEncryptedData {
                                    etype: EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                                    kvno: None,
                                    cipher,
                                }
                            }
                        };

                        // Need to encode the padata value now.
                        let padata_value = padata_value
                            .to_der()
                            .and_then(OctetString::new)
                            .map_err(|e| KrbError::DerEncodeOctetString(e))?;

                        padata_inner.push(PaData {
                            padata_type: PaDataType::PaEncTimestamp as u32,
                            padata_value,
                        })
                    }

                    /*
                    padata_inner.push(PaData {
                        padata_type: PaDataType::PadataAsFreshness as u32,
                        padata_value: OctetString::new(&[]).map_err(|_| KrbError::DerEncodeOctetString)?,
                    });

                    padata_inner.push(PaData {
                        padata_type: PaDataType::EncpadataReqEncPaRep as u32,
                        padata_value: OctetString::new(&[]).map_err(|_| KrbError::DerEncodeOctetString)?,
                    });
                    */

                    Some(padata_inner)
                } else {
                    None
                };

                let (cname, realm) = (&client_name).try_into().unwrap();
                let sname = (&service_name).try_into().unwrap();

                Ok(KrbKdcReq::AsReq(KdcReq {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbAsReq as u8,
                    padata,
                    req_body: KdcReqBody {
                        kdc_options,
                        cname: Some(cname),
                        // Per the RFC this is the "servers realm" in an AsReq but also the clients. So it's really
                        // not clear if the sname should have the realm or not or if this can be divergent between
                        // the client and server realm. What a clownshow, completely of their own making by trying
                        // to reuse structures in inconsistent ways. For now, we copy whatever bad behaviour mit
                        // krb does, because it's probably wrong, but it's the reference impl.
                        realm,
                        sname: Some(sname),
                        from: from.map(|t| {
                            KerberosTime::from_system_time(t)
                                .expect("Failed to build KerberosTime from SystemTime")
                        }),
                        till: KerberosTime::from_system_time(until)
                            .expect("Failed to build KerberosTime from SystemTime"),
                        rtime: renew.map(|t| {
                            KerberosTime::from_system_time(t)
                                .expect("Failed to build KerberosTime from SystemTime")
                        }),
                        nonce,
                        etype: etypes.iter().map(|e| *e as i32).collect(),
                        addresses: None,
                        enc_authorization_data: None,
                        additional_tickets: None,
                    },
                }))
            }
            KerberosRequest::TGS(TicketGrantRequest {}) => {
                todo!()
            }
        }
    }
}

impl TryFrom<KrbKdcReq> for KerberosRequest {
    type Error = KrbError;

    fn try_from(req: KrbKdcReq) -> Result<Self, KrbError> {
        match req {
            KrbKdcReq::TgsReq(kdc_req) | KrbKdcReq::AsReq(kdc_req) => {
                KerberosRequest::try_from(kdc_req)
            }
        }
    }
}

impl KerberosAuthenticationBuilder {
    pub fn from(mut self, from: Option<SystemTime>) -> Self {
        self.from = from;
        self
    }

    pub fn renew_until(mut self, renew: Option<SystemTime>) -> Self {
        self.renew = renew;
        self
    }

    pub fn preauth_enc_ts(
        mut self,
        pa_data: &PreauthData,
        epoch_seconds: Duration,
        user_key: &DerivedKey,
    ) -> Result<Self, KrbError> {
        // Major TODO: Can we actually use a reasonable amount of iterations?
        if !pa_data.enc_timestamp {
            return Err(KrbError::PreauthUnsupported);
        }

        // Strip any excess time.
        let usecs = epoch_seconds.subsec_micros();
        let epoch_seconds = Duration::from_secs(epoch_seconds.as_secs());

        let patimestamp = KerberosTime::from_unix_duration(epoch_seconds)
            .map_err(|_| KrbError::PreauthInvalidUnixTs)?;

        let paenctsenc = PaEncTsEnc {
            patimestamp,
            pausec: Some(usecs),
        };

        trace!(?paenctsenc);

        let enc_timestamp = user_key.encrypt_pa_enc_timestamp(&paenctsenc)?;

        // fx cookie always has to be sent.
        let pa_fx_cookie = pa_data.pa_fx_cookie.clone();

        self.preauth = Some(Preauth {
            enc_timestamp: Some(enc_timestamp),
            pa_fx_cookie,
        });

        Ok(self)
    }

    pub fn build(self) -> KerberosRequest {
        let KerberosAuthenticationBuilder {
            client_name,
            service_name,
            from,
            until,
            renew,
            preauth,
            etypes,
        } = self;

        // BUG IN MIT KRB5 - If the value is greater than i32 max you get:
        // Jun 28 03:47:41 3e79497ab6b5 krb5kdc[1](Error): ASN.1 value too large - while dispatching (tcp)
        let nonce: u32 = thread_rng().gen();
        let nonce = nonce & 0x7fff_ffff;

        let preauth = preauth.unwrap_or_default();

        let mut kdc_options = FlagSet::<KerberosFlags>::new(0b0).expect("Failed to build FlagSet");
        kdc_options |= KerberosFlags::Renewable;

        KerberosRequest::AS(AuthenticationRequest {
            nonce,
            client_name,
            service_name,
            from,
            until,
            renew,
            preauth,
            etypes,
            kdc_options,
        })
    }
}

impl TryFrom<KdcReq> for KerberosRequest {
    type Error = KrbError;

    fn try_from(req: KdcReq) -> Result<Self, Self::Error> {
        // assert the pvno and msg_type
        if req.pvno != 5 {
            return Err(KrbError::InvalidPvno);
        }

        let msg_type =
            KrbMessageType::try_from(req.msg_type).map_err(|_| KrbError::InvalidMessageType)?;

        match msg_type {
            KrbMessageType::KrbAsReq => {
                // Filter and use only the finest of etypes.
                let etypes = req
                    .req_body
                    .etype
                    .iter()
                    .filter_map(|etype| {
                        EncryptionType::try_from(*etype)
                            .ok()
                            .and_then(|etype| match etype {
                                EncryptionType::AES256_CTS_HMAC_SHA1_96 => Some(etype),
                                _ => None,
                            })
                    })
                    .collect();

                let preauth = req
                    .padata
                    .map(|pavec| Preauth::try_from(pavec))
                    .transpose()?
                    .unwrap_or_default();
                trace!(?preauth);

                let cname = req.req_body.cname.ok_or(KrbError::MissingClientName)?;
                let realm = req.req_body.realm;

                let client_name: Name = (cname, realm).try_into().unwrap();

                // Is realm from .realm? In the service? Who knows! The krb spec is cooked.
                let service_name: Name = req
                    .req_body
                    .sname
                    .ok_or(KrbError::MissingServiceNameWithRealm)
                    .and_then(|s| s.try_into())?;

                let from = req.req_body.from.map(|t| t.to_system_time());
                let until = req.req_body.till.to_system_time();
                let renew = req.req_body.rtime.map(|t| t.to_system_time());
                let nonce = req.req_body.nonce;
                let kdc_options = req.req_body.kdc_options;

                // addresses,
                // enc_authorization_data,
                // additional_tickets,

                Ok(KerberosRequest::AS(AuthenticationRequest {
                    nonce,
                    client_name,
                    service_name,
                    from,
                    until,
                    renew,
                    etypes,
                    preauth,
                    kdc_options
                }))
            }
            KrbMessageType::KrbTgsReq => {
                todo!();
            }
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}
