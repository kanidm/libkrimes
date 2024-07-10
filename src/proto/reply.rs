use crate::asn1::{
    constants::{
        encryption_types::EncryptionType, errors::KrbErrorCode, message_types::KrbMessageType,
        pa_data_types::PaDataType,
    },
    etype_info2::ETypeInfo2Entry as KdcETypeInfo2Entry,
    kdc_rep::KdcRep,
    kerberos_string::KerberosString,
    kerberos_time::KerberosTime,
    krb_error::KrbError as KdcKrbError,
    krb_error::MethodData,
    krb_kdc_rep::KrbKdcRep,
    pa_data::PaData,
    Ia5String, OctetString,
};
use crate::crypto::{
    decrypt_aes256_cts_hmac_sha1_96, derive_key_aes256_cts_hmac_sha1_96,
    derive_key_external_salt_aes256_cts_hmac_sha1_96, encrypt_aes256_cts_hmac_sha1_96,
};
use crate::error::KrbError;
use der::{Decode, Encode};

use std::time::{Duration, SystemTime};
use tracing::trace;

use super::{EncryptedData, EtypeInfo2, Name, PreauthData, Ticket};

#[derive(Debug)]
pub enum KerberosReply {
    AS(AuthenticationReply),
    TGS(TicketGrantReply),
    PA(PreauthReply),
    ERR(ErrorReply),
}

#[derive(Debug)]
pub struct AuthenticationReply {
    pub name: Name,
    pub enc_part: EncryptedData,
    pub pa_data: Option<PreauthData>,
    pub ticket: Ticket,
}

#[derive(Debug)]
pub struct TicketGrantReply {}

#[derive(Debug)]
pub struct PreauthReply {
    pub pa_data: PreauthData,
    pub service: Name,
}

#[derive(Debug)]
pub struct ErrorReply {
    code: KrbErrorCode,
    service: Name,
    error_text: Option<String>,
}

pub struct KerberosReplyPreauthBuilder {
    pa_fx_cookie: Option<Vec<u8>>,
    aes256_cts_hmac_sha1_96_iter_count: u32,
    salt: Option<String>,
    service: Name,
}

pub struct KerberosReplyAuthenticationBuilder {
    aes256_cts_hmac_sha1_96_iter_count: u32,
    salt: Option<String>,
    client: Name,
}

impl KerberosReply {
    pub fn preauth_builder(service: Name) -> KerberosReplyPreauthBuilder {
        let aes256_cts_hmac_sha1_96_iter_count: u32 = 0x8000;
        KerberosReplyPreauthBuilder {
            pa_fx_cookie: None,
            aes256_cts_hmac_sha1_96_iter_count,
            salt: None,
            service,
        }
    }

    pub fn authentication_builder(client: Name) -> KerberosReplyAuthenticationBuilder {
        let aes256_cts_hmac_sha1_96_iter_count: u32 = 0x8000;

        KerberosReplyAuthenticationBuilder {
            aes256_cts_hmac_sha1_96_iter_count,
            salt: None,
            client,
        }
    }

    pub fn error_no_etypes(service: Name) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrEtypeNosupp,
            service,
            error_text: Some(
                "Client and Server do not have overlapping encryption type support.".to_string(),
            ),
        })
    }

    pub fn error_preauth_failed(service: Name) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrPreauthFailed,
            service,
            error_text: Some(
                "Preauthentication Failed - Check your password is correct.".to_string(),
            ),
        })
    }

    pub fn error_client_principal(service: Name) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrPreauthFailed,
            service,
            error_text: Some(
                "Preauthentication Failed - Client Name was not a valid Principal.".to_string(),
            ),
        })
    }

    pub fn error_client_realm(service: Name) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrWrongRealm,
            service,
            error_text: Some("Preauthentication Failed - Check your realm is correct.".to_string()),
        })
    }

    pub fn error_client_username(service: Name) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrCPrincipalUnknown,
            service,
            error_text: Some(
                "Preauthentication Failed - Check your username is correct.".to_string(),
            ),
        })
    }

    pub fn error_as_not_krbtgt(service: Name) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrSvcUnavailable,
            service,
            error_text: Some(
                "Authentication (ASREQ) must only be for service instance `krbtgt@REALM`."
                    .to_string(),
            ),
        })
    }

    pub fn error_no_key(service: Name) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KrbApErrNokey,
            service,
            error_text: Some("No Key Available".to_string()),
        })
    }
}

impl KerberosReplyPreauthBuilder {
    pub fn set_salt(mut self, salt: Option<String>) -> Self {
        self.salt = salt;
        self
    }

    pub fn set_aes256_cts_hmac_sha1_96_iter_count(mut self, iter_count: u32) -> Self {
        self.aes256_cts_hmac_sha1_96_iter_count = iter_count;
        self
    }

    pub fn set_pa_fx_cookie(mut self, cookie: Option<Vec<u8>>) -> Self {
        self.pa_fx_cookie = cookie;
        self
    }

    pub fn build(self) -> KerberosReply {
        let aes256_cts_hmac_sha1_96_iter_count = Some(
            self.aes256_cts_hmac_sha1_96_iter_count
                .to_be_bytes()
                .to_vec(),
        );

        KerberosReply::PA(PreauthReply {
            pa_data: PreauthData {
                pa_fx_fast: false,
                enc_timestamp: true,
                pa_fx_cookie: self.pa_fx_cookie,
                etype_info2: vec![EtypeInfo2 {
                    etype: EncryptionType::AES256_CTS_HMAC_SHA1_96,
                    salt: self.salt,
                    s2kparams: aes256_cts_hmac_sha1_96_iter_count,
                }],
            },
            service: self.service,
        })
    }
}

impl KerberosReplyAuthenticationBuilder {
    pub fn set_salt(mut self, salt: Option<String>) -> Self {
        self.salt = salt;
        self
    }

    pub fn set_aes256_cts_hmac_sha1_96_iter_count(mut self, iter_count: u32) -> Self {
        self.aes256_cts_hmac_sha1_96_iter_count = iter_count;
        self
    }

    pub fn build(self) -> KerberosReply {
        todo!();
        /*
        // We need to encrypt some stuff ...


        // let enc_part = EncASRepPart -> EncKDCRepPart;

        // let ticket_enc_part = EncTicketPart;


        let ticket = Ticket {
            tkt_vno,
            realm,
            service_name,
            enc_part: ticket_enc_part,
        };

        let name = self.client;

        let aes256_cts_hmac_sha1_96_iter_count = Some(
            self.aes256_cts_hmac_sha1_96_iter_count
                .to_be_bytes()
                .to_vec(),
        );

        let pa_data = PreauthData {
            etype_info2: vec![EtypeInfo2 {
                etype: EncryptionType::AES256_CTS_HMAC_SHA1_96,
                salt: self.salt,
                s2kparams: aes256_cts_hmac_sha1_96_iter_count,
            }],
            ..Default::default()
        };

        KerberosReply::Authentication {
            name,
            enc_part,
            pa_data,
            ticket,
        },
        */
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

                Ok(KerberosReply::PA(PreauthReply { pa_data, service }))
            }
            code => {
                let error_text = rep.error_text.as_ref().map(|s| s.into());

                Ok(KerberosReply::ERR(ErrorReply {
                    code,
                    service,
                    error_text,
                }))
            }
        }
    }
}

impl TryInto<KrbKdcRep> for KerberosReply {
    type Error = KrbError;

    fn try_into(self) -> Result<KrbKdcRep, KrbError> {
        match self {
            KerberosReply::AS(AuthenticationReply {
                name,
                enc_part,
                pa_data,
                ticket,
            }) => {
                // let asn_as_req = as_req.to_asn()?;
                // KrbKdcReq::to_der(&KrbKdcReq::AsReq(asn_as_req))
                todo!();
            }
            KerberosReply::TGS(TicketGrantReply {}) => {
                todo!();
            }
            KerberosReply::PA(PreauthReply { pa_data, service }) => {
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
            KerberosReply::ERR(ErrorReply {
                code,
                service,
                error_text,
            }) => {
                let error_code = code as i32;

                let error_text = error_text
                    .as_ref()
                    .and_then(|et| Ia5String::new(&et).map(KerberosString).ok());

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
                    error_data: None,
                };

                Ok(KrbKdcRep::ErrRep(krb_error))
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

                Ok(KerberosReply::AS(AuthenticationReply {
                    name,
                    pa_data,
                    enc_part,
                    ticket,
                }))
            }
            KrbMessageType::KrbTgsRep => {
                todo!();
            }
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}
