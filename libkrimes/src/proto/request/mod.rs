mod as_req;

use crate::error::KrbError;
use crate::{
    asn1::{
        ap_options::{ApFlags, ApOptions},
        ap_req::{ApReq, ApReqInner},
        authenticator::{Authenticator, AuthenticatorInner},
        authorization_data::AuthorizationData,
        constants::{
            encryption_types::EncryptionType, message_types::KrbMessageType,
            pa_data_types::PaDataType,
        },
        encrypted_data::EncryptedData as KdcEncryptedData,
        encryption_key::EncryptionKey,
        kdc_req::KdcReq,
        kdc_req_body::KdcReqBody,
        kerberos_flags::KerberosFlags,
        kerberos_time::KerberosTime,
        krb_kdc_req::KrbKdcReq,
        pa_data::PaData,
        tagged_ticket::TaggedTicket,
        ticket_flags::TicketFlags,
        OctetString,
    },
    cksum::ChecksumBuilder,
};
pub use as_req::{AuthenticationRequest, AuthenticationRequestBuilder};
use der::{asn1::Any, Encode};
use rand::{rng, Rng};

use super::{EncTicket, EncryptedData, KdcPrimaryKey, Name, Preauth, SessionKey, Ticket};
use std::time::SystemTime;
use tracing::trace;

#[derive(Debug)]
pub enum KerberosRequest {
    AS(Box<AuthenticationRequest>),
    TGS(Box<TicketGrantRequestUnverified>),
}

#[derive(Debug)]
pub struct TicketGrantRequestUnverified {
    pub preauth: Preauth,
    // pub(crate) req_body: Vec<u8>,
    pub(crate) req_body: Any,
}

#[derive(Debug)]
pub struct TicketGrantRequest {
    pub(crate) nonce: i32,
    pub(crate) service_name: Name,
    pub(crate) etypes: Vec<EncryptionType>,
    pub(crate) sub_session_key: Option<SessionKey>,
    pub(crate) client_time: SystemTime,
    pub(crate) from: Option<SystemTime>,
    pub(crate) until: SystemTime,
    pub(crate) renew: Option<SystemTime>,

    pub(crate) ticket: Ticket,
}

#[derive(Debug)]
pub struct ApReqBuilder {
    client_name: Name,
    ticket: EncTicket,
    session_key: SessionKey,
}

#[derive(Debug)]
pub struct TicketGrantRequestBuilder {
    service_name: Name,
    client_time: SystemTime,
    from: Option<SystemTime>,
    until: SystemTime,
    renew: Option<SystemTime>,
    // preauth: Option<Preauth>,
    etypes: Vec<EncryptionType>,
    ap_req_builder: Option<ApReqBuilder>,
}

impl KerberosRequest {
    pub fn build_as(
        client_name: &Name,
        service_name: Name,
        until: SystemTime,
    ) -> AuthenticationRequestBuilder {
        AuthenticationRequestBuilder::new(client_name.clone(), service_name, until)
    }

    pub fn build_tgs(
        service_name: Name,
        now: SystemTime,
        until: SystemTime,
    ) -> TicketGrantRequestBuilder {
        let etypes = vec![EncryptionType::AES256_CTS_HMAC_SHA1_96];

        TicketGrantRequestBuilder {
            service_name,
            from: None,
            until,
            renew: None,
            // preauth: None,
            etypes,
            ap_req_builder: None,
            client_time: now,
        }
    }
}

impl TicketGrantRequestBuilder {
    pub fn from(mut self, from: Option<SystemTime>) -> Self {
        self.from = from;
        self
    }

    pub fn renew_until(mut self, renew: Option<SystemTime>) -> Self {
        self.renew = renew;
        self
    }

    pub fn preauth_ap_req(
        mut self,
        client: &Name,
        ticket: &EncTicket,
        session_key: &SessionKey,
    ) -> Result<Self, KrbError> {
        let ap_req_builder: ApReqBuilder = ApReqBuilder {
            client_name: client.clone(),
            ticket: ticket.clone(),
            session_key: session_key.clone(),
        };
        self.ap_req_builder = Some(ap_req_builder);
        Ok(self)
    }

    pub fn build(self) -> Result<KerberosRequest, KrbError> {
        let TicketGrantRequestBuilder {
            service_name,
            from,
            until,
            renew,
            // preauth: _,
            etypes,
            ap_req_builder,
            client_time,
        } = self;

        let ap_req_builder = ap_req_builder.ok_or(
            // This will be removed soon
            KrbError::MissingPaData,
        )?;

        // BUG IN MIT KRB5 - If the value is greater than i32 max you get:
        // Jun 28 03:47:41 3e79497ab6b5 krb5kdc[1](Error): ASN.1 value too large - while dispatching (tcp)
        // Heimdal for whatever reason will happily send negative values, so no idea
        // how they get away with it when we don't ....
        let nonce: i32 = rng().random();
        let nonce = nonce.abs();

        // So far we don't use preauth-here
        // let preauth = preauth.unwrap_or_default();

        let mut kdc_options = KerberosFlags::none();
        kdc_options |= KerberosFlags::Renewable;
        kdc_options |= KerberosFlags::Canonicalize;

        let (_, realm) = (&service_name).try_into()?;
        let sname = (&service_name).try_into()?;

        let req_body = KdcReqBody {
            kdc_options,
            cname: None,
            realm,
            sname: Some(sname),
            from: from
                .map(|t| {
                    KerberosTime::from_system_time(t).map_err(|_| KrbError::DerEncodeKerberosTime)
                })
                .transpose()?,
            till: KerberosTime::from_system_time(until)
                .map_err(|_| KrbError::DerEncodeKerberosTime)?,
            rtime: renew
                .map(|t| {
                    KerberosTime::from_system_time(t).map_err(|_| KrbError::DerEncodeKerberosTime)
                })
                .transpose()?,
            nonce,
            etype: etypes.iter().map(|e| *e as i32).collect(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        let req_body = Any::encode_from(&req_body).map_err(|_| KrbError::DerEncodeAny)?;

        //  The checksum in the authenticator is to be computed over the KDC-REQ-BODY encoding.
        let checksum_builder =
            ChecksumBuilder::HmacSha196Aes256(ap_req_builder.session_key.clone());
        let checksum = checksum_builder.compute_kdc_req_body(&req_body)?;

        // The encrypted authenticator is included in the AP-REQ; it certifies
        // to a server that the sender has recent knowledge of the encryption
        // key in the accompanying ticket, to help the server detect replays.
        // It also assists in the selection of a "true session key" to use with
        // the particular session. It is encrypted in the ticket's session key,
        // with a key usage value of 11 in normal application exchanges, or 7
        // when used as the PA-TGS-REQ PA-DATA field of a TGS-REQ exchange (see
        // Section 5.4.1)
        let (client_name, client_realm) = (&ap_req_builder.client_name).try_into()?;
        let subkey: Option<EncryptionKey> = None;
        let sequence_number: Option<u32> = None;
        let authorization_data: Option<AuthorizationData> = None;
        let authenticator: Authenticator = Authenticator::new(
            client_name,
            client_realm,
            client_time,
            Some(checksum),
            subkey,
            sequence_number,
            authorization_data,
        )?;
        let authenticator: EncryptedData = ap_req_builder
            .session_key
            .encrypt_ap_req_authenticator(&authenticator)?;
        let authenticator: KdcEncryptedData = match authenticator {
            EncryptedData::Aes256CtsHmacSha196 { kvno, data } => {
                let cipher =
                    OctetString::new(data.clone()).map_err(|_| KrbError::DerEncodeOctetString)?;
                KdcEncryptedData {
                    etype: EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                    kvno,
                    cipher,
                }
            }
        };

        let ap_options: ApOptions = ApFlags::none();

        let ticket: TaggedTicket = ap_req_builder.ticket.try_into()?;
        let ap_req: ApReq = ApReq::new(ap_options, ticket, authenticator);

        let preauth = Preauth {
            tgs_req: Some(ap_req),
            ..Default::default()
        };

        Ok(KerberosRequest::TGS(Box::new(
            TicketGrantRequestUnverified { preauth, req_body },
        )))
    }
}

impl TicketGrantRequestUnverified {
    pub fn validate(
        &self,
        primary_key: &KdcPrimaryKey,
        realm: &str,
    ) -> Result<TicketGrantRequest, KrbError> {
        trace!(?self, "Validating ap-req");

        // Destructure the ticket grant to make it easier to handle.
        let TicketGrantRequestUnverified {
            preauth:
                Preauth {
                    tgs_req,
                    // pa_fx_fast: _,
                    enc_timestamp: _,
                    pa_fx_cookie: _,
                },
            req_body,
        } = self;

        let Some(ap_req) = tgs_req else {
            return Err(KrbError::TgsMissingPaApReq);
        };

        let ap_req: &ApReqInner = ap_req.as_ref();

        if ap_req.pvno != 5 || ap_req.msg_type != 14 {
            return Err(KrbError::TgsInvalidPaApReq);
        };

        let ap_req_ticket = &ap_req.ticket.0;
        let ap_req_authenticator = EncryptedData::try_from(ap_req.authenticator.clone())?;
        // let ap_req_options = ap_req.ap_options;

        trace!(?ap_req_ticket, "ticket");
        trace!(?ap_req_authenticator, "authenticator");

        // Decrypt the ticket. This should be the TGT and contains the session
        // key used for encryption of the authenticator.
        if ap_req_ticket.realm.as_str() != realm {
            return Err(KrbError::TgsNotForRealm);
        }

        let ap_req_ticket_service_name =
            Name::try_from((&ap_req_ticket.sname, &ap_req_ticket.realm))?;

        if !ap_req_ticket_service_name.is_service_krbtgt(realm) {
            tracing::error!(?ap_req_ticket_service_name, "TgsTicketIsNotTgt");
            return Err(KrbError::TgsTicketIsNotTgt);
        }

        let ap_req_ticket_enc = EncryptedData::try_from(ap_req_ticket.enc_part.clone())?;

        let enc_ticket_part = ap_req_ticket_enc.decrypt_enc_tgt(primary_key)?;

        trace!(?enc_ticket_part, "enc-ticket-part");

        // Get the session Key.

        let session_key = SessionKey::try_from(enc_ticket_part.key)?;

        // Decrypt the authenticator
        let authenticator = session_key.decrypt_ap_req_authenticator(ap_req_authenticator)?;

        let authenticator: AuthenticatorInner = authenticator.into();

        trace!(?authenticator, "authenticator");

        let Some(his_checksum) = authenticator.cksum else {
            return Err(KrbError::TgsAuthMissingChecksum);
        };

        let checksum_builder: ChecksumBuilder =
            (his_checksum.checksum_type, Some(session_key.clone())).try_into()?;
        let checksum = checksum_builder.compute_kdc_req_body(req_body)?;

        // Validate that the checksum matches what our authenticator contains.
        if checksum != his_checksum {
            tracing::debug!(?checksum, ?his_checksum);
            return Err(KrbError::TgsAuthChecksumFailure);
        }

        let req_body = req_body
            .decode_as::<KdcReqBody>()
            .map_err(|_| KrbError::DerDecodeKdcReqBody)?;

        trace!(?req_body);

        let Some(service_princ) = req_body.sname else {
            return Err(KrbError::TgsKdcReqMissingServiceName);
        };

        // ==================================================================
        //
        // WARNING WARNING WARNING WARNING
        //
        // Below this line is where we now trust that the inputs are valid and checksummed
        // so that we can proceed with the release of the TGS to the KDC.

        let sub_session_key = authenticator
            .subkey
            .map(SessionKey::try_from)
            // Invert the Option<Result> to Result<Option>
            .transpose()?;

        let nonce = req_body.nonce;

        let ticket = {
            let client_name = Name::try_from((enc_ticket_part.cname, enc_ticket_part.crealm))?;
            let auth_time = enc_ticket_part.auth_time.to_system_time();

            let flags = enc_ticket_part.flags;

            let start_time = enc_ticket_part
                .start_time
                .map(|t| t.to_system_time())
                .ok_or(KrbError::TgsKdcMissingStartTime)?;

            let end_time = enc_ticket_part.end_time.to_system_time();
            let renew_until = enc_ticket_part.renew_till.map(|t| t.to_system_time());

            Ticket {
                flags,
                client_name,
                session_key,
                start_time,
                end_time,
                renew_until,
                auth_time,
            }
        };

        let service_name = Name::try_from((service_princ, req_body.realm))?;

        let from = req_body.from.map(|t| t.to_system_time());
        let until = req_body.till.to_system_time();
        let renew = req_body.rtime.map(|t| t.to_system_time());
        let client_time = authenticator.ctime.to_system_time();

        let etypes = req_body
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

        Ok(TicketGrantRequest {
            nonce,
            service_name,
            client_time,
            from,
            until,
            renew,
            etypes,
            sub_session_key,
            ticket,
        })
    }
}

impl TicketGrantRequest {
    pub fn service_name(&self) -> &Name {
        &self.service_name
    }

    pub fn client_time(&self) -> &SystemTime {
        &self.client_time
    }

    /// This is the time the client requested the ticket grant to start at. This value
    /// MUST be validated within the bounds of the ticket validity.
    pub fn requested_start_time(&self) -> Option<SystemTime> {
        self.from
    }

    /// This is the time the client requested the ticket grant to end at. This value
    /// MUST be validated within the bounds of the ticket validity.
    pub fn requested_end_time(&self) -> SystemTime {
        self.until
    }

    /// This is the time the client requested the ticket grant to be renewable until.
    /// This value MUST be validated within the bounds of the tickets renewable validity.
    pub fn requested_renew_until(&self) -> Option<SystemTime> {
        self.renew
    }

    /// The cryptographically verified ticket granting ticket that this KDC or a trusted
    /// KDC issued to the client.
    pub fn ticket_granting_ticket(&self) -> &Ticket {
        &self.ticket
    }

    pub fn ticket_flags(&self) -> &TicketFlags {
        &self.ticket.flags
    }

    pub fn etypes(&self) -> &[EncryptionType] {
        &self.etypes
    }
}

impl TryInto<KrbKdcReq> for &KerberosRequest {
    type Error = KrbError;

    fn try_into(self) -> Result<KrbKdcReq, Self::Error> {
        match self {
            KerberosRequest::AS(
                /*
                AuthenticationRequest {
                    nonce,
                    client_name,
                    service_name,
                    from,
                    until,
                    renew,
                    preauth,
                    etypes,
                    kdc_options,
                }
                */
                auth_req,
            ) => {
                let padata = if auth_req.preauth.pa_fx_cookie.is_some()
                    || auth_req.preauth.enc_timestamp.is_some()
                {
                    let mut padata_inner = Vec::with_capacity(2);

                    if let Some(fx_cookie) = &auth_req.preauth.pa_fx_cookie {
                        let padata_value = OctetString::new(fx_cookie.clone())
                            .map_err(|_| KrbError::DerEncodeOctetString)?;
                        padata_inner.push(PaData {
                            padata_type: PaDataType::PaFxCookie as u32,
                            padata_value,
                        })
                    }

                    if let Some(enc_data) = &auth_req.preauth.enc_timestamp {
                        let padata_value = match enc_data {
                            EncryptedData::Aes256CtsHmacSha196 { kvno: _, data } => {
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

                let (cname, realm) = (&auth_req.client_name).try_into()?;
                let sname = (&auth_req.service_name).try_into()?;

                let req_body = KdcReqBody {
                    kdc_options: auth_req.kdc_options,
                    cname: Some(cname),
                    // Per the RFC this is the "servers realm" in an AsReq but also the clients. So it's really
                    // not clear if the sname should have the realm or not or if this can be divergent between
                    // the client and server realm. What a clownshow, completely of their own making by trying
                    // to reuse structures in inconsistent ways. For now, we copy whatever bad behaviour mit
                    // krb does, because it's probably wrong, but it's the reference impl.
                    realm,
                    sname: Some(sname),
                    from: auth_req
                        .from
                        .map(|t| {
                            KerberosTime::from_system_time(t)
                                .map_err(|_| KrbError::DerEncodeKerberosTime)
                        })
                        .transpose()?,
                    till: KerberosTime::from_system_time(auth_req.until)
                        .map_err(|_| KrbError::DerEncodeKerberosTime)?,
                    rtime: auth_req
                        .renew
                        .map(|t| {
                            KerberosTime::from_system_time(t)
                                .map_err(|_| KrbError::DerEncodeKerberosTime)
                        })
                        .transpose()?,
                    nonce: auth_req.nonce,
                    etype: auth_req.etypes.iter().map(|e| *e as i32).collect(),
                    addresses: None,
                    enc_authorization_data: None,
                    additional_tickets: None,
                };

                let req_body = Any::encode_from(&req_body).map_err(|_| KrbError::DerEncodeAny)?;

                Ok(KrbKdcReq::AsReq(KdcReq {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbAsReq as u8,
                    padata,
                    req_body,
                }))
            }
            KerberosRequest::TGS(unverified_tgs_req) => {
                let padata = if unverified_tgs_req.preauth.tgs_req.is_some() {
                    let mut padata_inner = Vec::with_capacity(1);

                    if let Some(ap_req) = &unverified_tgs_req.preauth.tgs_req {
                        let padata_value = ap_req
                            .to_der()
                            .and_then(OctetString::new)
                            .map_err(|_| KrbError::DerEncodeApReq)?;
                        padata_inner.push(PaData {
                            padata_type: PaDataType::PaTgsReq as u32,
                            padata_value,
                        });
                    }

                    Some(padata_inner)
                } else {
                    None
                };

                Ok(KrbKdcReq::TgsReq(KdcReq {
                    pvno: 5,
                    msg_type: KrbMessageType::KrbTgsReq as u8,
                    padata,
                    req_body: unverified_tgs_req.req_body.clone(),
                }))
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
                let req_body = req
                    .req_body
                    .decode_as::<KdcReqBody>()
                    .map_err(|_| KrbError::DerDecodeKdcReqBody)?;

                // Filter and use only the finest of etypes.
                let etypes = req_body
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
                    .map(Preauth::try_from)
                    .transpose()?
                    .unwrap_or_default();
                trace!(?preauth);

                trace!(?req_body);

                let realm = &req_body.realm;
                let cname = &req_body.cname.ok_or(KrbError::MissingClientName)?;
                let sname = &req_body
                    .sname
                    .ok_or(KrbError::MissingServiceNameWithRealm)?;

                let client_name: Name = (cname, realm).try_into()?;
                let service_name: Name = (sname, realm).try_into()?;

                let from = req_body.from.map(|t| t.to_system_time());
                let until = req_body.till.to_system_time();
                let renew = req_body.rtime.map(|t| t.to_system_time());
                let nonce = req_body.nonce;
                let kdc_options = req_body.kdc_options;

                // addresses,
                // enc_authorization_data,
                // additional_tickets,

                Ok(KerberosRequest::AS(Box::new(AuthenticationRequest {
                    nonce,
                    client_name,
                    service_name,
                    from,
                    until,
                    renew,
                    etypes,
                    preauth,
                    kdc_options,
                })))
            }
            KrbMessageType::KrbTgsReq => {
                trace!(?req);

                // IMPORTANT! At this point, since we don't yet have the session key, req_body
                // shouldn't be parsed. We need to process padata first to get the tgs and
                // relevant info *before* we can proceed, as we need to checksum the bytes
                // of the req_body.
                //
                // There is a MAJOR RISK that at this point, we will fail to checksum, since
                // our current design forces us to recanonicalise req_body to checksum it!!!
                //
                // We might be able to avoid this by the use of pa-fx-fast but that has it's
                // own bag of complexity ...
                let preauth = req
                    .padata
                    .map(Preauth::try_from)
                    .transpose()?
                    .unwrap_or_default();
                trace!(?preauth);

                Ok(KerberosRequest::TGS(Box::new(
                    TicketGrantRequestUnverified {
                        preauth,
                        req_body: req.req_body,
                    },
                )))
            }
            _ => Err(KrbError::InvalidMessageDirection),
        }
    }
}
