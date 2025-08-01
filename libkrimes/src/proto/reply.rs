use super::{
    AuthenticationTimeBound, DerivedKey, EncTicket, EncryptedData, EtypeInfo2, KdcPrimaryKey, Name,
    PreauthData, SessionKey, Ticket, TicketGrantRequest, TicketGrantTimeBound,
    TicketRenewTimeBound,
};
use crate::asn1::{
    authorization_data::AuthorizationData,
    constants::{
        authorization_data_types::AuthorizationDataType, encryption_types::EncryptionType,
        errors::KrbErrorCode, message_types::KrbMessageType, pa_data_types::PaDataType,
    },
    enc_kdc_rep_part::EncKdcRepPart,
    enc_ticket_part::EncTicketPart,
    encryption_key::EncryptionKey as KdcEncryptionKey,
    etype_info2::ETypeInfo2Entry as KdcETypeInfo2Entry,
    kdc_rep::KdcRep,
    kerberos_string::KerberosString,
    kerberos_time::KerberosTime,
    krb_error::{KrbError as KdcKrbError, MethodData},
    krb_kdc_rep::KrbKdcRep,
    pa_data::PaData,
    ticket_flags::TicketFlags,
    transited_encoding::TransitedEncoding,
    Ia5String, OctetString,
};
use crate::constants::PBKDF2_SHA1_ITER;
use crate::error::KrbError;
use crate::proto::as_rep::{AuthenticationReply, KerberosReplyAuthenticationBuilder};
use crate::proto::ms_pac::AdWin2kPac;
use der::{Decode, Encode};
use std::time::{Duration, SystemTime};
use tracing::{error, trace};

#[derive(Debug)]
pub enum KerberosReply {
    AS(AuthenticationReply),
    TGS(TicketGrantReply),
    PA(PreauthReply),
    ERR(ErrorReply),
}

#[derive(Debug)]
pub struct TicketGrantReply {
    pub client_name: Name,
    pub enc_part: EncryptedData,
    pub ticket: EncTicket,
}

#[derive(Debug)]
pub struct PreauthReply {
    pub pa_data: PreauthData,
    pub service: Name,
    pub stime: SystemTime,
}

#[derive(Debug)]
pub struct ErrorReply {
    code: KrbErrorCode,
    service: Name,
    error_text: Option<String>,
    stime: SystemTime,
}

pub struct KerberosReplyPreauthBuilder {
    pa_fx_cookie: Option<Vec<u8>>,
    aes256_cts_hmac_sha1_96_iter_count: u32,
    salt: Option<String>,
    service: Name,
    stime: SystemTime,
}

pub struct KerberosReplyTicketGrantBuilder {
    nonce: i32,
    service_name: Name,
    sub_session_key: Option<SessionKey>,

    pac: Option<AdWin2kPac>,

    time_bounds: TicketGrantTimeBound,

    ticket: Ticket,

    flags: TicketFlags,
}

pub struct KerberosReplyTicketRenewBuilder {
    nonce: i32,
    service_name: Name,
    sub_session_key: Option<SessionKey>,

    time_bounds: TicketRenewTimeBound,

    ticket: Ticket,
}

impl KerberosReply {
    pub fn preauth_builder(service: Name, stime: SystemTime) -> KerberosReplyPreauthBuilder {
        let aes256_cts_hmac_sha1_96_iter_count: u32 = PBKDF2_SHA1_ITER;
        KerberosReplyPreauthBuilder {
            pa_fx_cookie: None,
            aes256_cts_hmac_sha1_96_iter_count,
            salt: None,
            service,
            stime,
        }
    }

    pub fn authentication_builder(
        client: Name,
        server: Name,
        time_bounds: AuthenticationTimeBound,
        nonce: i32,
    ) -> KerberosReplyAuthenticationBuilder {
        KerberosReplyAuthenticationBuilder::new(client, server, time_bounds, nonce)
    }

    pub fn ticket_renew_builder(
        ticket_grant_request: TicketGrantRequest,
        time_bounds: TicketRenewTimeBound,
    ) -> KerberosReplyTicketRenewBuilder {
        let TicketGrantRequest {
            nonce,
            service_name,
            from: _,
            until: _,
            renew: _,
            etypes: _,
            sub_session_key,
            client_time: _,
            ticket,
        } = ticket_grant_request;

        KerberosReplyTicketRenewBuilder {
            nonce,
            service_name,

            sub_session_key,

            time_bounds,

            ticket,
        }
    }

    pub fn ticket_grant_builder(
        ticket_grant_request: TicketGrantRequest,
        time_bounds: TicketGrantTimeBound,
    ) -> KerberosReplyTicketGrantBuilder {
        let TicketGrantRequest {
            nonce,
            service_name,
            from: _,
            until: _,
            renew: _,
            etypes: _,
            sub_session_key,
            client_time: _,
            ticket,
        } = ticket_grant_request;

        let mut flags = TicketFlags::none();
        if time_bounds.renew_until().is_some() {
            flags |= TicketFlags::Renewable;
        }

        // From is what the client requested.
        // Now is the kdc time.
        // ticket.start_time is when the ticket began.

        KerberosReplyTicketGrantBuilder {
            nonce,
            service_name,

            sub_session_key,

            pac: None,

            time_bounds,
            ticket,

            flags,
        }
    }

    pub fn error_request_invalid(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KrbErrGeneric,
            service,
            error_text: Some(
                "The Kerberos Client sent a malformed and invalid request.".to_string(),
            ),
            stime,
        })
    }

    pub fn error_request_failed_validation(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KrbErrGeneric,
            service,
            error_text: Some(
                "The Kerberos Client sent a request that was cryptographically invalid."
                    .to_string(),
            ),
            stime,
        })
    }

    pub fn error_no_etypes(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrEtypeNosupp,
            service,
            error_text: Some(
                "Client and Server do not have overlapping encryption type support.".to_string(),
            ),
            stime,
        })
    }

    pub fn error_preauth_failed(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrPreauthFailed,
            service,
            error_text: Some(
                "Preauthentication Failed - Check your password is correct.".to_string(),
            ),
            stime,
        })
    }

    pub fn error_client_principal(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrPreauthFailed,
            service,
            error_text: Some(
                "Preauthentication Failed - Client Name was not a valid Principal.".to_string(),
            ),
            stime,
        })
    }

    pub fn error_client_realm(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrWrongRealm,
            service,
            error_text: Some("Preauthentication Failed - Check your realm is correct.".to_string()),
            stime,
        })
    }

    pub fn error_client_username(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrCPrincipalUnknown,
            service,
            error_text: Some(
                "Preauthentication Failed - Check your username is correct.".to_string(),
            ),
            stime,
        })
    }

    pub fn error_service_name(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrSPrincipalUnknown,
            service,
            error_text: Some("Ticket Request Failed - Service Name not found.".to_string()),
            stime,
        })
    }

    pub fn error_as_not_krbtgt(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrSvcUnavailable,
            service,
            error_text: Some(
                "Authentication (ASREQ) must only be for service instance `krbtgt@REALM`."
                    .to_string(),
            ),
            stime,
        })
    }

    pub fn error_no_key(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KrbApErrNokey,
            service,
            error_text: Some("No Key Available".to_string()),
            stime,
        })
    }

    pub fn error_clock_skew(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KrbApErrSkew,
            service,
            error_text: Some("Clock Skew too great".to_string()),
            stime,
        })
    }

    pub fn error_cannot_postdate(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrCannotPostdate,
            service,
            error_text: Some("Ticket not elegible for postdating".to_string()),
            stime,
        })
    }

    pub fn error_never_valid(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrNeverValid,
            service,
            error_text: Some("Requested ticket start time is later than end time".to_string()),
            stime,
        })
    }

    pub fn error_renew_denied(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrPolicy,
            service,
            error_text: Some("Requested ticket is unable to be renewed".to_string()),
            stime,
        })
    }

    pub fn error_inappropiate_checksum(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KrbApErrInappCksum,
            service,
            error_text: Some("Inappropriate type of checksum in message".to_string()),
            stime,
        })
    }

    pub fn error_unsupported_checksum(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KdcErrSumtypeNosupp,
            service,
            error_text: Some("KDC has no support for checksum type".to_string()),
            stime,
        })
    }

    pub fn error_internal(service: Name, stime: SystemTime) -> KerberosReply {
        KerberosReply::ERR(ErrorReply {
            code: KrbErrorCode::KrbErrGeneric,
            service,
            error_text: Some("Internal Server Error".to_string()),
            stime,
        })
    }
}

impl KerberosReplyPreauthBuilder {
    pub fn set_key_params(mut self, dk: &DerivedKey) -> Self {
        match dk {
            DerivedKey::Aes256CtsHmacSha196 { i, s, .. } => {
                self.salt = Some(s.clone());
                self.aes256_cts_hmac_sha1_96_iter_count = *i;
                self
            }
        }
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
                // pa_fx_fast: false,
                enc_timestamp: true,
                pa_fx_cookie: self.pa_fx_cookie,
                etype_info2: vec![EtypeInfo2 {
                    etype: EncryptionType::AES256_CTS_HMAC_SHA1_96,
                    salt: self.salt,
                    s2kparams: aes256_cts_hmac_sha1_96_iter_count,
                }],
            },
            service: self.service,
            stime: self.stime,
        })
    }
}

impl KerberosReplyTicketGrantBuilder {
    pub fn build(mut self, service_key: &DerivedKey) -> Result<KerberosReply, KrbError> {
        let service_session_key = SessionKey::new();
        let service_session_key: KdcEncryptionKey = service_session_key.try_into()?;

        let (cname, crealm) = (&self.ticket.client_name).try_into()?;
        let (server_name, server_realm) = (&self.service_name).try_into()?;

        let auth_time = KerberosTime::from_system_time(self.ticket.auth_time)
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;
        let start_time = Some(
            KerberosTime::from_system_time(self.time_bounds.start_time())
                .map_err(|_| KrbError::DerEncodeKerberosTime)?,
        );
        let end_time = KerberosTime::from_system_time(self.time_bounds.end_time())
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;

        let renew_till = if let Some(renew_until) = self.time_bounds.renew_until() {
            self.flags |= TicketFlags::Renewable;
            Some(
                KerberosTime::from_system_time(renew_until)
                    .map_err(|_| KrbError::DerEncodeKerberosTime)?,
            )
        } else {
            None
        };

        // TGS_REP The ciphertext is encrypted with the sub-session key
        // from the authenticator.
        // If absent, the session key is used (with no kvno).
        // 5.4.2 reads as though the the clients version number is used here for kvno?

        // KeyUsage == 8 for session key, or == 9 for subkey.
        // let enc_part = EncTGSRepPart == EncKDCRepPart;

        let enc_kdc_rep_part = EncKdcRepPart {
            key: service_session_key.clone(),
            // Not 100% clear on this field.
            last_req: Vec::with_capacity(0),
            nonce: self.nonce,
            key_expiration: None,
            flags: self.flags,
            auth_time,
            start_time,
            end_time,
            renew_till,
            server_realm,
            server_name,
            client_addresses: None,
        };

        // Encrypt this with the original tickets sub_session_key so that they
        // can decrypt this and get the service_session_key out.
        let enc_part = if let Some(sub_session_key) = self.sub_session_key {
            sub_session_key.encrypt_tgs_rep_part(enc_kdc_rep_part, true)?
        } else {
            self.ticket
                .session_key
                .encrypt_tgs_rep_part(enc_kdc_rep_part, false)?
        };

        // An MS-PAC is required for Samba to work.
        let authorization_data = if let Some(pac) = self.pac {
            // Need to work out the signatures here.

            let pac_data_inner =
                OctetString::new(pac.to_bytes()).map_err(|_| KrbError::DerEncodeOctetString)?;

            let pac_data = AuthorizationData {
                ad_type: AuthorizationDataType::AdWin2kPac.into(),
                ad_data: pac_data_inner,
            }
            .to_der()
            .and_then(OctetString::new)
            .map_err(|_| KrbError::DerEncodeOctetString)?;

            Some(vec![AuthorizationData {
                ad_type: AuthorizationDataType::AdIfRelevant.into(),
                ad_data: pac_data,
            }])
        } else {
            None
        };

        let transited = TransitedEncoding {
            tr_type: 1,
            // Since no transit has occured, we record an empty str.
            contents: OctetString::new(b"").map_err(|_| KrbError::DerEncodeOctetString)?,
        };

        // EncTicketPart
        // Encrypted to the key of the service - this is what the ticket holder
        // forwards to the service to that it is aware of it's service session key.
        let ticket_inner = EncTicketPart {
            flags: self.flags,
            key: service_session_key,
            crealm,
            cname,
            transited,
            auth_time,
            start_time,
            end_time,
            renew_till,
            client_addresses: None,
            authorization_data,
        };

        let ticket_enc_part = service_key.encrypt_tgs(ticket_inner)?;

        let ticket = EncTicket {
            tkt_vno: 5,
            service: self.service_name,
            enc_part: ticket_enc_part,
        };

        let client_name = self.ticket.client_name;

        Ok(KerberosReply::TGS(TicketGrantReply {
            client_name,
            enc_part,
            ticket,
        }))
    }
}

impl KerberosReplyTicketRenewBuilder {
    pub fn build(self, primary_key: &KdcPrimaryKey) -> Result<KerberosReply, KrbError> {
        let (cname, crealm) = (&self.ticket.client_name).try_into()?;
        let (server_name, server_realm) = (&self.service_name).try_into()?;

        let auth_time = KerberosTime::from_system_time(self.ticket.auth_time)
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;
        let start_time = Some(
            KerberosTime::from_system_time(self.time_bounds.start_time())
                .map_err(|_| KrbError::DerEncodeKerberosTime)?,
        );
        let end_time = KerberosTime::from_system_time(self.time_bounds.end_time())
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;
        let renew_till = Some(
            KerberosTime::from_system_time(self.time_bounds.renew_until())
                .map_err(|_| KrbError::DerEncodeKerberosTime)?,
        );

        let session_key: KdcEncryptionKey = self.ticket.session_key.clone().try_into()?;

        // TGS_REP The ciphertext is encrypted with the sub-session key
        // from the authenticator.
        // If absent, the session key is used (with no kvno).
        // 5.4.2 reads as though the the clients version number is used here for kvno?

        // KeyUsage == 8 for session key, or == 9 for subkey.
        // let enc_part = EncTGSRepPart == EncKDCRepPart;

        let enc_kdc_rep_part = EncKdcRepPart {
            key: session_key.clone(),
            // Not 100% clear on this field.
            last_req: Vec::with_capacity(0),
            nonce: self.nonce,
            key_expiration: None,
            flags: self.ticket.flags,
            auth_time,
            start_time,
            end_time,
            renew_till,
            server_realm,
            server_name,
            client_addresses: None,
        };

        let enc_part = if let Some(sub_session_key) = self.sub_session_key {
            sub_session_key.encrypt_tgs_rep_part(enc_kdc_rep_part, true)?
        } else {
            self.ticket
                .session_key
                .encrypt_tgs_rep_part(enc_kdc_rep_part, false)?
        };

        let authorization_data = None;

        let transited = TransitedEncoding {
            tr_type: 1,
            // Since no transit has occured, we record an empty str.
            contents: OctetString::new(b"").map_err(|_| KrbError::DerEncodeOctetString)?,
        };

        // EncTicketPart
        // Encrypted to the key of the service
        let ticket_inner = EncTicketPart {
            flags: self.ticket.flags,
            key: session_key,
            crealm,
            cname,
            transited,
            auth_time,
            start_time,
            end_time,
            renew_till,
            client_addresses: None,
            authorization_data,
        };

        let ticket_enc_part = primary_key.encrypt_tgs(ticket_inner)?;

        let ticket = EncTicket {
            tkt_vno: 5,
            service: self.service_name,
            enc_part: ticket_enc_part,
        };

        let client_name = self.ticket.client_name;

        Ok(KerberosReply::TGS(TicketGrantReply {
            client_name,
            enc_part,
            ticket,
        }))
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
            error!(?rep.error_code, "Unable to encode error code");
            KrbError::DerEncodeKrbErrorCode
        })?;

        let stime = rep.stime.to_system_time();
        let microsecs = Duration::from_micros(rep.susec as u64);

        let stime = stime + microsecs;

        match error_code {
            KrbErrorCode::KdcErrPreauthRequired => {
                let edata = rep.error_data.ok_or(KrbError::MissingPaData)?;

                let pavec: Vec<PaData> = MethodData::from_der(edata.as_bytes())
                    .map_err(|_| KrbError::DerDecodePaData)?;

                let pa_data = PreauthData::try_from(pavec)?;

                Ok(KerberosReply::PA(PreauthReply {
                    pa_data,
                    service,
                    stime,
                }))
            }
            code => {
                let error_text = rep.error_text.as_ref().map(|s| s.to_string());

                Ok(KerberosReply::ERR(ErrorReply {
                    code,
                    service,
                    error_text,
                    stime,
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
                let pa_data: Option<Vec<PaData>> = match pa_data {
                    Some(data) => {
                        let etype_padata_vec = data
                            .etype_info2
                            .iter()
                            .map(|einfo| {
                                let salt = einfo
                                    .salt
                                    .as_ref()
                                    .map(Ia5String::new)
                                    .transpose()
                                    .map_err(|_| KrbError::DerEncodeKerberosString)?
                                    .map(KerberosString);
                                let s2kparams = einfo
                                    .s2kparams
                                    .as_ref()
                                    .map(|data| OctetString::new(data.to_owned()))
                                    .transpose()
                                    .map_err(|_| KrbError::DerEncodeOctetString)?;
                                Ok(KdcETypeInfo2Entry {
                                    etype: einfo.etype as i32,
                                    salt,
                                    s2kparams,
                                })
                            })
                            .collect::<Result<Vec<_>, KrbError>>()?;

                        let etype_padata_value = etype_padata_vec
                            .to_der()
                            .and_then(OctetString::new)
                            .map_err(|_| KrbError::DerEncodeOctetString)?;

                        let pavec = vec![PaData {
                            padata_type: PaDataType::PaEtypeInfo2 as u32,
                            padata_value: etype_padata_value,
                        }];
                        Some(pavec)
                    }
                    None => None,
                };

                let as_rep = KdcRep {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbAsRep as u8,
                    padata: pa_data,
                    crealm: (&name).try_into()?,
                    cname: (&name).try_into()?,
                    ticket: ticket.try_into()?,
                    enc_part: enc_part.try_into()?,
                };

                Ok(KrbKdcRep::AsRep(as_rep))
            }
            KerberosReply::TGS(TicketGrantReply {
                client_name,
                enc_part,
                ticket,
            }) => {
                let tgs_rep = KdcRep {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbTgsRep as u8,
                    padata: None,
                    crealm: (&client_name).try_into()?,
                    cname: (&client_name).try_into()?,
                    ticket: ticket.try_into()?,
                    enc_part: enc_part.try_into()?,
                };

                Ok(KrbKdcRep::TgsRep(tgs_rep))
            }
            KerberosReply::PA(PreauthReply {
                pa_data,
                service,
                stime,
            }) => {
                let error_code = KrbErrorCode::KdcErrPreauthRequired as i32;
                // The pre-auth data is stuffed into error_data. Because of course kerberos can't
                // do nice things.
                let etype_padata_vec = pa_data
                    .etype_info2
                    .iter()
                    .map(|einfo| {
                        let salt = einfo
                            .salt
                            .as_ref()
                            .map(Ia5String::new)
                            .transpose()
                            .map_err(|_| KrbError::DerEncodeKerberosString)?
                            .map(KerberosString);

                        let s2kparams = einfo
                            .s2kparams
                            .as_ref()
                            .map(|data| OctetString::new(data.to_owned()))
                            .transpose()
                            .map_err(|_| KrbError::DerEncodeOctetString)?;
                        Ok(KdcETypeInfo2Entry {
                            etype: einfo.etype as i32,
                            salt,
                            s2kparams,
                        })
                    })
                    .collect::<Result<Vec<KdcETypeInfo2Entry>, KrbError>>()?;

                let etype_padata_value = etype_padata_vec
                    .to_der()
                    .and_then(OctetString::new)
                    .map_err(|_| KrbError::DerEncodeOctetString)?;

                let pavec = vec![
                    PaData {
                        padata_type: PaDataType::PaEncTimestamp as u32,
                        padata_value: OctetString::new([])
                            .map_err(|_| KrbError::DerEncodeOctetString)?,
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

                let stime = stime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    // We need to stip the fractional part.
                    .map(|t| Duration::from_secs(t.as_secs()))
                    .unwrap_or_default();

                let stime = KerberosTime::from_unix_duration(stime)
                    .map_err(|_| KrbError::DerEncodeKerberosTime)?;

                let (service_name, service_realm) = (&service).try_into()?;

                let krb_error = KdcKrbError {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbError as u8,
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
                stime,
            }) => {
                let error_code = code as i32;

                let error_text = error_text
                    .as_ref()
                    .and_then(|et| Ia5String::new(&et).map(KerberosString).ok());

                let stime = stime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    // We need to stip the fractional part.
                    .map(|t| Duration::from_secs(t.as_secs()))
                    .unwrap_or_default();

                let stime = KerberosTime::from_unix_duration(stime)
                    .map_err(|_| KrbError::DerEncodeKerberosTime)?;

                let (service_name, service_realm) = (&service).try_into()?;

                let krb_error = KdcKrbError {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbError as u8,
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

                let pa_data = rep.padata.map(PreauthData::try_from).transpose()?;
                trace!(?pa_data);

                let name = (rep.cname, rep.crealm).try_into()?;
                let ticket = EncTicket::try_from(rep.ticket)?;

                Ok(KerberosReply::AS(AuthenticationReply {
                    name,
                    pa_data,
                    enc_part,
                    ticket,
                }))
            }
            KrbMessageType::KrbTgsRep => {
                let enc_part = EncryptedData::try_from(rep.enc_part)?;
                trace!(?enc_part);

                let client_name = (rep.cname, rep.crealm).try_into()?;

                let ticket = EncTicket::try_from(rep.ticket)?;

                Ok(KerberosReply::TGS(TicketGrantReply {
                    client_name,
                    enc_part,
                    ticket,
                }))
            }
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}
