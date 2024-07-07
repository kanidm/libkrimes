use crate::asn1::{
    constants::{
        encryption_types::EncryptionType, errors::KrbErrorCode, message_types::KrbMessageType,
        pa_data_types::PaDataType,
    },
    encrypted_data::EncryptedData as KdcEncryptedData,
    etype_info2::ETypeInfo2 as KdcETypeInfo2,
    etype_info2::ETypeInfo2Entry as KdcETypeInfo2Entry,
    kdc_rep::KdcRep,
    kdc_req::KdcReq,
    kdc_req_body::KdcReqBody,
    // kerberos_flags::KerberosFlags,
    kerberos_string::KerberosString,
    kerberos_time::KerberosTime,
    krb_error::KrbError as KdcKrbError,
    krb_error::MethodData,
    krb_kdc_rep::KrbKdcRep,
    krb_kdc_req::KrbKdcReq,
    pa_data::PaData,
    pa_enc_ts_enc::PaEncTsEnc,
    principal_name::PrincipalName,
    realm::Realm,
    tagged_ticket::TaggedTicket,
    BitString,
    Ia5String,
    OctetString,
};
use crate::constants::AES_256_KEY_LEN;
use crate::crypto::{
    decrypt_aes256_cts_hmac_sha1_96, derive_key_aes256_cts_hmac_sha1_96,
    derive_key_external_salt_aes256_cts_hmac_sha1_96, encrypt_aes256_cts_hmac_sha1_96,
};
use crate::error::KrbError;
use der::{Decode, Encode};
use rand::{thread_rng, Rng};

use std::cmp::Ordering;
use std::time::{Duration, SystemTime};
use tracing::trace;

#[derive(Debug)]
pub enum KerberosRequest {
    AsReq(KerberosAsReq),
    // TgsReq(KerberosTgsReq),
}

#[derive(Debug)]
pub enum KerberosResponse {
    AsRep(KerberosAsRep),
    TgsRep(KerberosTgsRep),
    // This is it's own valid state, not an error, so we return it
    // as a valid response instead.
    PaRep(KerberosPaRep),
    ErrRep(KrbErrorCode),
}

#[derive(Debug)]
pub struct KerberosAsReqBuilder {
    client_name: Name,
    service_name: Name,
    from: Option<SystemTime>,
    until: SystemTime,
    renew: Option<SystemTime>,
    preauth: Option<PreAuth>,
    etypes: Vec<EncryptionType>,
}

#[derive(Debug)]
pub struct KerberosAsReq {
    pub nonce: u32,
    pub client_name: Name,
    pub service_name: Name,
    pub from: Option<SystemTime>,
    pub until: SystemTime,
    pub renew: Option<SystemTime>,
    pub preauth: PreAuth,
    pub etypes: Vec<EncryptionType>,
}

#[derive(Debug, Default)]
pub struct PreAuth {
    pub enc_timestamp: Option<EncryptedData>,
    pub pa_fx_cookie: Option<Vec<u8>>,
}

pub enum BaseKey {
    Aes256 {
        // Todo zeroizing.
        k: [u8; AES_256_KEY_LEN],
    },
}

#[derive(Debug)]
pub struct Ticket {
    tkt_vno: i8,
    realm: String,
    service_name: String,
    enc_part: EncryptedData,
}

#[derive(Debug)]
pub enum EncryptedData {
    Aes256CtsHmacSha196 { kvno: Option<u32>, data: Vec<u8> },
}

#[derive(Debug)]
pub struct KerberosAsRep {
    pub(crate) name: Name,
    pub(crate) enc_part: EncryptedData,
    pub(crate) pa_data: Option<PreAuthData>,
    pub(crate) ticket: Ticket,
}

#[derive(Debug)]
pub struct KerberosTgsRep {}

#[derive(Debug)]
pub struct PreAuthData {
    pub(crate) pa_fx_fast: bool,
    pub(crate) enc_timestamp: bool,
    pub(crate) pa_fx_cookie: Option<Vec<u8>>,
    pub(crate) etype_info2: Vec<EtypeInfo2>,
}

#[derive(Debug)]
pub struct KerberosPaRep {
    pub(crate) pa_data: PreAuthData,
    pub(crate) service: Name,
}

#[derive(Debug, Clone)]
pub enum Name {
    Principal {
        name: String,
        realm: String,
    },
    SrvInst {
        service: String,
        realm: String,
    },
    SrvHst {
        service: String,
        host: String,
        realm: String,
    },
    /*
    Uid {
    }
    */
}

#[derive(Debug)]
pub struct EtypeInfo2 {
    // The type of encryption for enc ts.
    etype: EncryptionType,

    salt: Option<String>,

    // For AES HMAC SHA1:
    //   The number of iterations is specified by the string-to-key parameters
    //   supplied.  The parameter string is four octets indicating an unsigned
    //   number in big-endian order.  This is the number of iterations to be
    //   performed.  If the value is 00 00 00 00, the number of iterations to
    //   be performed is 4,294,967,296 (2**32).  (Thus the minimum expressible
    //   iteration count is 1.)
    s2kparams: Option<Vec<u8>>,
}

fn sort_cryptographic_strength(a: &EtypeInfo2, b: &EtypeInfo2) -> Ordering {
    /*
    if a.etype == EncryptionType::AES256_CTS_HMAC_SHA384_192 {
        Ordering::Greater
    } else if b.etype == EncryptionType::AES256_CTS_HMAC_SHA384_192 {
        Ordering::Less
    } else if a.etype == EncryptionType::AES128_CTS_HMAC_SHA256_128 {
        Ordering::Greater
    } else if b.etype == EncryptionType::AES128_CTS_HMAC_SHA256_128 {
        Ordering::Less
    } else
    */
    if a.etype == EncryptionType::AES256_CTS_HMAC_SHA1_96 {
        Ordering::Greater
    } else if b.etype == EncryptionType::AES256_CTS_HMAC_SHA1_96 {
        Ordering::Less
    } else if a.etype == EncryptionType::AES128_CTS_HMAC_SHA1_96 {
        Ordering::Greater
    } else if b.etype == EncryptionType::AES128_CTS_HMAC_SHA1_96 {
        Ordering::Less
    } else {
        // Everything else is trash.
        Ordering::Equal
    }
}

#[derive(Debug)]
enum KerberosErrRep {
    Err(KrbErrorCode),
    Pa(KerberosPaRep),
}

impl KerberosPaRep {
    pub fn new(service: Name) -> Self {
        KerberosPaRep {
            pa_data: PreAuthData {
                pa_fx_fast: false,
                enc_timestamp: true,
                pa_fx_cookie: None,
                etype_info2: vec![EtypeInfo2 {
                    etype: EncryptionType::AES256_CTS_HMAC_SHA1_96,
                    salt: None,
                    s2kparams: None,
                }],
            },
            service,
        }
    }
}

impl KerberosRequest {
    pub fn build_asreq(
        client_name: Name,
        service_name: Name,
        from: Option<SystemTime>,
        until: SystemTime,
        renew: Option<SystemTime>,
    ) -> KerberosAsReqBuilder {
        let etypes = vec![
            EncryptionType::AES256_CTS_HMAC_SHA1_96,
            // MIT KRB5 claims to support these values, but if they are provided then MIT
            // KDC's will ignore them.
            // EncryptionType::AES128_CTS_HMAC_SHA256_128,
            // EncryptionType::AES256_CTS_HMAC_SHA384_192,
        ];

        KerberosAsReqBuilder {
            client_name,
            service_name,
            from,
            until,
            renew,
            preauth: None,
            etypes,
        }
    }
}

impl TryInto<KrbKdcReq> for KerberosRequest {
    type Error = KrbError;

    fn try_into(self) -> Result<KrbKdcReq, Self::Error> {
        match self {
            KerberosRequest::AsReq(as_req) => as_req.try_into().map(KrbKdcReq::AsReq),
        }
    }
}

impl TryFrom<KrbKdcReq> for KerberosRequest {
    type Error = KrbError;

    fn try_from(req: KrbKdcReq) -> Result<Self, Self::Error> {
        match req {
            KrbKdcReq::AsReq(kdc_req) => {
                let as_req: KerberosAsReq =
                    KerberosAsReq::try_from(kdc_req).expect("Failed to parse as req");
                Ok(KerberosRequest::AsReq(as_req))
            }
            KrbKdcReq::TgsReq(kdc_req) => {
                todo!();
            }
        }
    }
}

impl TryFrom<KrbKdcRep> for KerberosResponse {
    type Error = KrbError;

    fn try_from(rep: KrbKdcRep) -> Result<Self, Self::Error> {
        match rep {
            KrbKdcRep::AsRep(kdc_rep) => {
                KerberosAsRep::try_from(kdc_rep).map(KerberosResponse::AsRep)
            }
            KrbKdcRep::TgsRep(kdc_rep) => todo!(),
            KrbKdcRep::ErrRep(err_rep) => {
                let err_rep = KerberosErrRep::try_from(err_rep)?;

                Ok(match err_rep {
                    KerberosErrRep::Pa(pa_rep) => KerberosResponse::PaRep(pa_rep),
                    KerberosErrRep::Err(err_code) => KerberosResponse::ErrRep(err_code),
                })
            }
        }
    }
}

impl TryInto<KrbKdcRep> for KerberosResponse {
    type Error = KrbError;

    fn try_into(self) -> Result<KrbKdcRep, Self::Error> {
        match self {
            KerberosResponse::AsRep(as_rep) => {
                // let asn_as_req = as_req.to_asn()?;
                // KrbKdcReq::to_der(&KrbKdcReq::AsReq(asn_as_req))
                todo!();
            }
            KerberosResponse::TgsRep(tgs_rep) => {
                todo!();
            }
            KerberosResponse::PaRep(pa_rep) => {
                let error_code = KrbErrorCode::KdcErrPreauthRequired as i32;
                // The pre-auth data is stuffed into error_data. Because of course kerberos can't
                // do nice things.
                let etype_padata_vec = vec![KdcETypeInfo2Entry {
                    etype: EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                    salt: None,
                    s2kparams: None,
                }];

                let etype_padata_value = etype_padata_vec
                    .to_der()
                    .and_then(OctetString::new)
                    .map_err(|_| KrbError::DerEncodeOctetString)?;

                let pavec = vec![
                    PaData {
                        padata_type: PaDataType::PaEncTimestamp as u32,
                        padata_value: OctetString::new(&[])
                            .map_err(|err| KrbError::DerEncodeOctetString)?,
                    },
                    PaData {
                        padata_type: PaDataType::PaEtypeInfo2 as u32,
                        padata_value: etype_padata_value,
                    },
                ];

                let error_data = pavec
                    .to_der()
                    .and_then(OctetString::new)
                    .map(Some)
                    .map_err(|_| KrbError::DerEncodeOctetString)?;

                let error_text = Ia5String::new("Preauthentication Required")
                    .map(KerberosString)
                    .ok();

                let stime = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    // We need to stip the fractional part.
                    .map(|t| Duration::from_secs(t.as_secs()))
                    .unwrap_or_default();

                let stime = KerberosTime::from_unix_duration(stime).unwrap();

                let (service_name, service_realm) = (&pa_rep.service).try_into()?;

                let krb_error = KdcKrbError {
                    pvno: 5,
                    msg_type: 30,
                    ctime: None,
                    cusec: None,
                    stime,
                    susec: 0,
                    error_code,
                    crealm: None,
                    cname: None,
                    service_realm,
                    service_name,
                    error_text,
                    error_data,
                };

                Ok(KrbKdcRep::ErrRep(krb_error))
                // todo!();
            }
            KerberosResponse::ErrRep(err_rep) => {
                todo!();
            }
        }
    }
}

impl KerberosAsReqBuilder {
    pub fn add_preauthentication(mut self, preauth: PreAuth) -> Self {
        self.preauth = Some(preauth);
        self
    }

    pub fn build(self) -> KerberosRequest {
        let KerberosAsReqBuilder {
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

        KerberosRequest::AsReq(KerberosAsReq {
            nonce,
            client_name,
            service_name,
            from,
            until,
            renew,
            preauth,
            etypes,
        })
    }
}

impl TryInto<KdcReq> for KerberosAsReq {
    type Error = KrbError;

    fn try_into(self) -> Result<KdcReq, Self::Error> {
        let padata = if self.preauth.pa_fx_cookie.is_some() || self.preauth.enc_timestamp.is_some()
        {
            let mut padata_inner = Vec::with_capacity(4);

            if let Some(fx_cookie) = &self.preauth.pa_fx_cookie {
                let padata_value = OctetString::new(fx_cookie.clone())
                    .map_err(|_| KrbError::DerEncodeOctetString)?;
                padata_inner.push(PaData {
                    padata_type: PaDataType::PaFxCookie as u32,
                    padata_value,
                })
            }

            if let Some(enc_data) = &self.preauth.enc_timestamp {
                let padata_value = match enc_data {
                    EncryptedData::Aes256CtsHmacSha196 { kvno, data } => {
                        let cipher = OctetString::new(data.clone())
                            .map_err(|_| KrbError::DerEncodeOctetString)?;
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
                    .map_err(|_| KrbError::DerEncodeOctetString)?;

                padata_inner.push(PaData {
                    padata_type: PaDataType::PaEncTimestamp as u32,
                    padata_value,
                })
            }

            padata_inner.push(PaData {
                padata_type: PaDataType::PadataAsFreshness as u32,
                padata_value: OctetString::new(&[]).map_err(|_| KrbError::DerEncodeOctetString)?,
            });

            padata_inner.push(PaData {
                padata_type: PaDataType::EncpadataReqEncPaRep as u32,
                padata_value: OctetString::new(&[]).map_err(|_| KrbError::DerEncodeOctetString)?,
            });

            Some(padata_inner)
        } else {
            None
        };

        let (cname, realm) = (&self.client_name).try_into().unwrap();
        let sname = (&self.service_name).try_into().unwrap();

        Ok(KdcReq {
            pvno: 5,
            msg_type: KrbMessageType::KrbAsReq as u8,
            padata,
            req_body: KdcReqBody {
                kdc_options: BitString::from_bytes(&[0x00, 0x80, 0x00, 0x00]).unwrap(),
                cname: Some(cname),
                // Per the RFC this is the "servers realm" in an AsReq but also the clients. So it's really
                // not clear if the sname should have the realm or not or if this can be divergent between
                // the client and server realm. What a clownshow, completely of their own making by trying
                // to reuse structures in inconsistent ways. For now, we copy whatever bad behaviour mit
                // krb does, because it's probably wrong, but it's the reference impl.
                realm,
                sname: Some(sname),
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
                nonce: self.nonce,
                etype: self.etypes.iter().map(|e| *e as i32).collect(),
                addresses: None,
                enc_authorization_data: None,
                additional_tickets: None,
            },
        })
    }
}

impl TryFrom<KdcReq> for KerberosAsReq {
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
                let mut etypes = req
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
                    .map(|pavec| PreAuth::try_from(pavec))
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

                // addresses,
                // enc_authorization_data,
                // additional_tickets,

                Ok(KerberosAsReq {
                    nonce,
                    // client_realm,
                    client_name,
                    service_name,
                    from,
                    until,
                    renew,
                    etypes,
                    preauth,
                })
            }
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}

impl TryFrom<KdcRep> for KerberosAsRep {
    type Error = KrbError;

    fn try_from(rep: KdcRep) -> Result<Self, Self::Error> {
        // assert the pvno and msg_type
        if rep.pvno != 5 {
            return Err(KrbError::InvalidPvno);
        }

        let msg_type =
            KrbMessageType::try_from(rep.msg_type).map_err(|_| KrbError::InvalidMessageType)?;

        match msg_type {
            KrbMessageType::KrbAsRep => {
                let enc_part = EncryptedData::try_from(rep.enc_part)?;
                trace!(?enc_part);

                let pa_data = rep
                    .padata
                    .map(|pavec| PreAuthData::try_from(pavec))
                    .transpose()?;
                trace!(?pa_data);

                let name = (rep.cname, rep.crealm).try_into()?;
                let ticket = Ticket::try_from(rep.ticket)?;

                Ok(KerberosAsRep {
                    name,
                    pa_data,
                    enc_part,
                    ticket,
                })
            }
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}

impl TryFrom<KdcRep> for KerberosTgsRep {
    type Error = KrbError;

    fn try_from(rep: KdcRep) -> Result<Self, Self::Error> {
        // assert the pvno and msg_type
        if rep.pvno != 5 {
            return Err(KrbError::InvalidPvno);
        }

        let msg_type =
            KrbMessageType::try_from(rep.msg_type).map_err(|_| KrbError::InvalidMessageType)?;

        match msg_type {
            KrbMessageType::KrbTgsRep => Ok(KerberosTgsRep {}),
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}

impl TryFrom<KdcKrbError> for KerberosErrRep {
    type Error = KrbError;

    fn try_from(rep: KdcKrbError) -> Result<Self, Self::Error> {
        trace!(?rep);

        // assert the pvno and msg_type
        if rep.pvno != 5 {
            return Err(KrbError::InvalidPvno);
        }

        let msg_type =
            KrbMessageType::try_from(rep.msg_type).map_err(|_| KrbError::InvalidMessageType)?;

        match msg_type {
            KrbMessageType::KrbError => {
                let error_code = KrbErrorCode::try_from(rep.error_code).map_err(|_| {
                    KrbError::InvalidEnumValue(
                        std::any::type_name::<KrbErrorCode>().to_string(),
                        rep.error_code,
                    )
                })?;

                let rep = match error_code {
                    KrbErrorCode::KdcErrPreauthRequired => {
                        let edata = rep.error_data.ok_or(KrbError::MissingPaData)?;

                        let pavec: Vec<PaData> = MethodData::from_der(edata.as_bytes())
                            .map_err(|_| KrbError::DerDecodePaData)?;

                        let pa_data = PreAuthData::try_from(pavec)?;

                        let service = Name::try_from((rep.service_name, rep.service_realm))?;

                        let pa_rep = KerberosPaRep { pa_data, service };

                        KerberosErrRep::Pa(pa_rep)
                    }
                    err_code => KerberosErrRep::Err(err_code),
                };

                Ok(rep)
            }
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}

impl TryFrom<Vec<PaData>> for PreAuthData {
    type Error = KrbError;

    fn try_from(pavec: Vec<PaData>) -> Result<Self, Self::Error> {
        // Per https://www.rfc-editor.org/rfc/rfc4120#section-7.5.2
        // Build up the set of PaRep data
        let mut pa_fx_fast = false;
        let mut enc_timestamp = false;
        let mut pa_fx_cookie = None;
        let mut etype_info2 = Vec::with_capacity(0);

        for PaData {
            padata_type,
            padata_value,
        } in pavec
        {
            let Ok(padt) = padata_type.try_into() else {
                // padatatype that we don't support
                continue;
            };

            match padt {
                PaDataType::PaEncTimestamp => enc_timestamp = true,
                PaDataType::PaEtypeInfo2 => {
                    // this is a sequence of etypeinfo2
                    let einfo2_sequence = KdcETypeInfo2::from_der(padata_value.as_bytes())
                        .map_err(|_| KrbError::DerDecodeEtypeInfo2)?;

                    for einfo2 in einfo2_sequence {
                        let Ok(etype) = EncryptionType::try_from(einfo2.etype) else {
                            // Invalid etype or we don't support it.
                            continue;
                        };

                        // Only proceed with what we support.
                        match etype {
                            EncryptionType::AES256_CTS_HMAC_SHA1_96 => {}
                            _ => continue,
                        };

                        // I think at this point we should ignore any etypes we don't support.
                        let salt = einfo2.salt.map(|s| s.into());
                        let s2kparams = einfo2.s2kparams.map(|v| v.as_bytes().to_vec());

                        etype_info2.push(EtypeInfo2 {
                            etype,
                            salt,
                            s2kparams,
                        });
                    }
                }
                PaDataType::PaFxFast => pa_fx_fast = true,
                PaDataType::PaFxCookie => pa_fx_cookie = Some(padata_value.as_bytes().to_vec()),
                _ => {
                    // Ignore unsupported pa data types.
                }
            };
        }

        // Sort the etype_info by cryptographic strength.
        etype_info2.sort_unstable_by(sort_cryptographic_strength);

        Ok(PreAuthData {
            pa_fx_fast,
            pa_fx_cookie,
            enc_timestamp,
            etype_info2,
        })
    }
}

impl TryFrom<Vec<PaData>> for PreAuth {
    type Error = KrbError;

    fn try_from(pavec: Vec<PaData>) -> Result<Self, Self::Error> {
        let mut preauth = PreAuth::default();

        for PaData {
            padata_type,
            padata_value,
        } in pavec
        {
            let Ok(padt) = padata_type.try_into() else {
                // padatatype that we don't support
                continue;
            };

            match padt {
                PaDataType::PaEncTimestamp => {
                    let enc_timestamp = KdcEncryptedData::from_der(padata_value.as_bytes())
                        .map_err(|_| KrbError::DerDecodePaData)
                        .and_then(EncryptedData::try_from)?;
                    preauth.enc_timestamp = Some(enc_timestamp);
                }
                PaDataType::PaFxCookie => {
                    preauth.pa_fx_cookie = Some(padata_value.as_bytes().to_vec())
                }
                _ => {
                    // Ignore unsupported pa data types.
                }
            };
        }

        Ok(preauth)
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
                // TODO: check the padata.

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

    pub fn decrypt_pa_enc_timestamp(&self, base_key: &BaseKey) -> Result<SystemTime, KrbError> {
        // https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.2
        let data = self.decrypt_data(base_key, 1)?;

        let paenctsenc = PaEncTsEnc::from_der(&data).map_err(|_| KrbError::DerDecodePaEncTsEnc)?;

        trace!(?paenctsenc);

        let stime = paenctsenc.patimestamp.to_system_time();
        let usecs = paenctsenc
            .pausec
            .map(|s| Duration::from_micros(s as u64))
            .unwrap_or_default();

        let stime = stime + usecs;

        Ok(stime)
    }
}

impl TryFrom<KdcEncryptedData> for EncryptedData {
    type Error = KrbError;

    fn try_from(enc_data: KdcEncryptedData) -> Result<Self, Self::Error> {
        let etype: EncryptionType = EncryptionType::try_from(enc_data.etype)
            .map_err(|_| KrbError::UnsupportedEncryption)?;
        match etype {
            EncryptionType::AES256_CTS_HMAC_SHA1_96 => {
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

impl TryFrom<TaggedTicket> for Ticket {
    type Error = KrbError;

    fn try_from(tkt: TaggedTicket) -> Result<Self, Self::Error> {
        let TaggedTicket(tkt) = tkt;

        let tkt_vno = tkt.tkt_vno;
        let realm: String = tkt.realm.into();
        let service_name: String = tkt.sname.into();

        let enc_part = EncryptedData::try_from(tkt.enc_part)?;

        Ok(Ticket {
            tkt_vno,
            realm,
            service_name,
            enc_part,
        })
    }
}

impl KerberosPaRep {
    pub fn perform_enc_timestamp(
        &self,
        passphrase: &str,
        realm: &str,
        cname: &str,
        epoch_seconds: Duration,
    ) -> Result<PreAuth, KrbError> {
        // Major TODO: Can we actually use a reasonable amount of iterations?
        if !self.pa_data.enc_timestamp {
            return Err(KrbError::PreAuthUnsupported);
        }

        // This gets the highest encryption strength item.
        let Some(einfo2) = self.pa_data.etype_info2.last() else {
            return Err(KrbError::PreAuthMissingEtypeInfo2);
        };

        // https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.2
        let key_usage = 1;

        // Strip any excess time.
        let usecs = epoch_seconds.subsec_micros();
        let epoch_seconds = Duration::from_secs(epoch_seconds.as_secs());

        let patimestamp = KerberosTime::from_unix_duration(epoch_seconds)
            .map_err(|_| KrbError::PreAuthInvalidUnixTs)?;

        let paenctsenc = PaEncTsEnc {
            patimestamp,
            pausec: Some(usecs),
        };

        trace!(?paenctsenc);

        let data = paenctsenc
            .to_der()
            .map_err(|_| KrbError::DerEncodePaEncTsEnc)?;

        let enc_timestamp = match einfo2.etype {
            EncryptionType::AES256_CTS_HMAC_SHA1_96 => {
                let iter_count = if let Some(s2kparams) = &einfo2.s2kparams {
                    if s2kparams.len() != 4 {
                        return Err(KrbError::PreAuthInvalidS2KParams);
                    };
                    let mut iter_count = [0u8; 4];
                    iter_count.copy_from_slice(&s2kparams);

                    Some(u32::from_be_bytes(iter_count))
                } else {
                    None
                };

                let base_key = if let Some(external_salt) = &einfo2.salt {
                    derive_key_external_salt_aes256_cts_hmac_sha1_96(
                        passphrase.as_bytes(),
                        external_salt.as_bytes(),
                        iter_count,
                    )?
                } else {
                    derive_key_aes256_cts_hmac_sha1_96(
                        passphrase.as_bytes(),
                        realm.as_bytes(),
                        cname.as_bytes(),
                        iter_count,
                    )?
                };

                let data = encrypt_aes256_cts_hmac_sha1_96(&base_key, &data, key_usage)?;

                EncryptedData::Aes256CtsHmacSha196 { kvno: None, data }
            }
            // Shouldn't be possible, we pre-vet all the etypes.
            _ => return Err(KrbError::UnsupportedEncryption),
        };

        // fx cookie always has to be sent.
        let pa_fx_cookie = self.pa_data.pa_fx_cookie.clone();

        Ok(PreAuth {
            enc_timestamp: Some(enc_timestamp),
            pa_fx_cookie,
        })
    }
}

impl Name {
    pub fn principal(name: &str, realm: &str) -> Self {
        Self::Principal {
            name: name.to_string(),
            realm: realm.to_string(),
        }
    }

    pub fn service_krbtgt(realm: &str) -> Self {
        Self::SrvInst {
            service: "krbtgt".to_string(),
            realm: realm.to_string(),
        }
    }
}

impl TryInto<PrincipalName> for &Name {
    type Error = KrbError;

    fn try_into(self) -> Result<PrincipalName, KrbError> {
        match self {
            Name::Principal { name, realm } => {
                let name_string = vec![
                    KerberosString(Ia5String::new(name).unwrap()),
                    KerberosString(Ia5String::new(realm).unwrap()),
                ];

                Ok(PrincipalName {
                    name_type: 1,
                    name_string,
                })
            }
            Name::SrvInst { service, realm } => {
                let name_string = vec![
                    KerberosString(Ia5String::new(service).unwrap()),
                    KerberosString(Ia5String::new(realm).unwrap()),
                ];

                Ok(PrincipalName {
                    name_type: 2,
                    name_string,
                })
            }
            Name::SrvHst {
                service,
                host,
                realm,
            } => {
                let name_string = vec![
                    KerberosString(Ia5String::new(service).unwrap()),
                    KerberosString(Ia5String::new(host).unwrap()),
                    KerberosString(Ia5String::new(realm).unwrap()),
                ];

                Ok(PrincipalName {
                    name_type: 3,
                    name_string,
                })
            }
        }
    }
}

impl TryInto<(PrincipalName, Realm)> for &Name {
    type Error = KrbError;

    fn try_into(self) -> Result<(PrincipalName, Realm), KrbError> {
        match self {
            Name::Principal { name, realm } => {
                let name_string = vec![KerberosString(Ia5String::new(&name).unwrap())];
                let realm = KerberosString(Ia5String::new(realm).unwrap());

                Ok((
                    PrincipalName {
                        name_type: 1,
                        name_string,
                    },
                    realm,
                ))
            }
            Name::SrvInst { service, realm } => {
                let name_string = vec![KerberosString(Ia5String::new(&service).unwrap())];
                let realm = KerberosString(Ia5String::new(realm).unwrap());

                Ok((
                    PrincipalName {
                        name_type: 2,
                        name_string,
                    },
                    realm,
                ))
            }
            Name::SrvHst {
                service,
                host,
                realm,
            } => {
                let name_string = vec![
                    KerberosString(Ia5String::new(&service).unwrap()),
                    KerberosString(Ia5String::new(&host).unwrap()),
                ];
                let realm = KerberosString(Ia5String::new(realm).unwrap());

                Ok((
                    PrincipalName {
                        name_type: 3,
                        name_string,
                    },
                    realm,
                ))
            }
        }
    }
}

impl TryFrom<PrincipalName> for Name {
    type Error = KrbError;

    fn try_from(princ: PrincipalName) -> Result<Self, Self::Error> {
        let PrincipalName {
            name_type,
            name_string,
        } = princ;
        match name_type {
            1 => {
                let name = name_string.get(0).unwrap().into();
                let realm = name_string.get(1).unwrap().into();
                Ok(Name::Principal { name, realm })
            }
            2 => {
                let service = name_string.get(0).unwrap().into();
                let realm = name_string.get(1).unwrap().into();
                Ok(Name::SrvInst { service, realm })
            }
            3 => {
                let service = name_string.get(0).unwrap().into();
                let host = name_string.get(1).unwrap().into();
                let realm = name_string.get(2).unwrap().into();
                Ok(Name::SrvHst {
                    service,
                    host,
                    realm,
                })
            }
            _ => todo!(),
        }
    }
}

impl TryFrom<(PrincipalName, Realm)> for Name {
    type Error = KrbError;

    fn try_from((princ, realm): (PrincipalName, Realm)) -> Result<Self, Self::Error> {
        let PrincipalName {
            name_type,
            name_string,
        } = princ;

        let realm = realm.into();

        match name_type {
            1 => {
                let name = name_string.get(0).unwrap().into();
                Ok(Name::Principal { name, realm })
            }
            2 => {
                let service = name_string.get(0).unwrap().into();
                Ok(Name::SrvInst { service, realm })
            }
            3 => {
                let service = name_string.get(0).unwrap().into();
                let host = name_string.get(1).unwrap().into();
                Ok(Name::SrvHst {
                    service,
                    host,
                    realm,
                })
            }
            _ => todo!(),
        }
    }
}
