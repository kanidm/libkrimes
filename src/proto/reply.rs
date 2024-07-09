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

use super::{EncryptedData, EtypeInfo2, Name, Preauth, PreauthData, Ticket};

#[derive(Debug)]
pub enum KerberosReply {
    Authentication {
        name: Name,
        enc_part: EncryptedData,
        pa_data: Option<PreauthData>,
        ticket: Ticket,
    },
    TicketGrant {},
    Preauth {
        pa_data: PreauthData,
        service: Name,
    },
    Error {
        code: KrbErrorCode,
        service: Name,
    },
}

pub struct KerberosReplyPreauthBuilder {
    pa_data: PreauthData,
    service: Name,
}

impl KerberosReply {
    pub fn preauth_builder(service: Name, salt: String) -> KerberosReplyPreauthBuilder {
        let aes256_cts_hmac_sha1_96_iter_count: u32 = 0x8000;

        let aes256_cts_hmac_sha1_96_iter_count =
            aes256_cts_hmac_sha1_96_iter_count.to_be_bytes().to_vec();

        KerberosReplyPreauthBuilder {
            pa_data: PreauthData {
                pa_fx_fast: false,
                enc_timestamp: true,
                pa_fx_cookie: None,
                etype_info2: vec![EtypeInfo2 {
                    etype: EncryptionType::AES256_CTS_HMAC_SHA1_96,
                    salt: Some(salt),
                    s2kparams: Some(aes256_cts_hmac_sha1_96_iter_count),
                }],
            },
            service,
        }
    }
}

impl KerberosReplyPreauthBuilder {
    pub fn build(self) -> KerberosReply {
        KerberosReply::Preauth {
            pa_data: self.pa_data,
            service: self.service,
        }
    }
}

impl TryFrom<KrbKdcRep> for KerberosReply {
    type Error = KrbError;

    fn try_from(rep: KrbKdcRep) -> Result<Self, KrbError> {
        match rep {
            KrbKdcRep::AsRep(kdc_rep) | KrbKdcRep::TgsRep(kdc_rep) => {
                KerberosReply::try_from(kdc_rep)
            }
            KrbKdcRep::ErrRep(err_rep) => KerberosReply::try_from(err_rep),
        }
    }
}

impl TryFrom<KdcKrbError> for KerberosReply {
    type Error = KrbError;

    fn try_from(rep: KdcKrbError) -> Result<Self, KrbError> {
        // assert the pvno and msg_type
        if rep.pvno != 5 {
            return Err(KrbError::InvalidPvno);
        }

        let service = Name::try_from((rep.service_name, rep.service_realm))?;

        let msg_type =
            KrbMessageType::try_from(rep.msg_type).map_err(|_| KrbError::InvalidMessageType)?;

        if !matches!(msg_type, KrbMessageType::KrbError) {
            return Err(KrbError::InvalidMessageDirection);
        }

        let error_code = KrbErrorCode::try_from(rep.error_code).map_err(|_| {
            KrbError::InvalidEnumValue(
                std::any::type_name::<KrbErrorCode>().to_string(),
                rep.error_code,
            )
        })?;

        match error_code {
            KrbErrorCode::KdcErrPreauthRequired => {
                let edata = rep.error_data.ok_or(KrbError::MissingPaData)?;

                let pavec: Vec<PaData> = MethodData::from_der(edata.as_bytes())
                    .map_err(|_| KrbError::DerDecodePaData)?;

                let pa_data = PreauthData::try_from(pavec)?;

                Ok(KerberosReply::Preauth { pa_data, service })
            }
            code => Ok(KerberosReply::Error { code, service }),
        }
    }
}

impl TryInto<KrbKdcRep> for KerberosReply {
    type Error = KrbError;

    fn try_into(self) -> Result<KrbKdcRep, KrbError> {
        match self {
            KerberosReply::Authentication {
                name,
                enc_part,
                pa_data,
                ticket,
            } => {
                // let asn_as_req = as_req.to_asn()?;
                // KrbKdcReq::to_der(&KrbKdcReq::AsReq(asn_as_req))
                todo!();
            }
            KerberosReply::TicketGrant {} => {
                todo!();
            }
            KerberosReply::Preauth { pa_data, service } => {
                let error_code = KrbErrorCode::KdcErrPreauthRequired as i32;
                // The pre-auth data is stuffed into error_data. Because of course kerberos can't
                // do nice things.
                let etype_padata_vec: Vec<_> = pa_data
                    .etype_info2
                    .iter()
                    .map(|einfo| {
                        let etype = einfo.etype as i32;
                        let salt = einfo
                            .salt
                            .as_ref()
                            .map(|data| KerberosString(Ia5String::new(data).unwrap()));
                        let s2kparams = einfo
                            .s2kparams
                            .as_ref()
                            .map(|data| OctetString::new(data.to_owned()).unwrap());

                        KdcETypeInfo2Entry {
                            etype: einfo.etype as i32,
                            salt,
                            s2kparams,
                        }
                    })
                    .collect();

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

                let (service_name, service_realm) = (&service).try_into()?;

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
            }
            KerberosReply::Error { code, service } => {
                todo!();
            }
        }
    }
}

impl TryFrom<KdcRep> for KerberosReply {
    type Error = KrbError;

    fn try_from(rep: KdcRep) -> Result<Self, KrbError> {
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
                    .map(|pavec| PreauthData::try_from(pavec))
                    .transpose()?;
                trace!(?pa_data);

                let name = (rep.cname, rep.crealm).try_into()?;
                let ticket = Ticket::try_from(rep.ticket)?;

                Ok(KerberosReply::Authentication {
                    name,
                    pa_data,
                    enc_part,
                    ticket,
                })
            }
            KrbMessageType::KrbTgsRep => {
                todo!();
            }
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}
