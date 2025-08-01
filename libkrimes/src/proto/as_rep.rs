use super::{
    AuthenticationTimeBound, DerivedKey, EncTicket, EncTicketPart, EncryptedData, KdcEncryptionKey,
    KdcPrimaryKey, KerberosTime, KrbError, LastRequestItem, Name, PreauthData, SessionKey,
    TicketFlags,
};
use crate::asn1::enc_kdc_rep_part::EncKdcRepPart;
use crate::asn1::{last_req::LastReqItem, transited_encoding::TransitedEncoding, OctetString};
use crate::constants::PBKDF2_SHA1_ITER;
use crate::proto::reply::KerberosReply;
use std::time::SystemTime;

#[derive(Debug)]
pub struct AuthenticationReply {
    pub(crate) name: Name,
    pub(crate) enc_part: EncryptedData,
    pub(crate) pa_data: Option<PreauthData>,
    pub(crate) ticket: EncTicket,
}

pub struct KerberosReplyAuthenticationBuilder {
    pub(crate) aes256_cts_hmac_sha1_96_iter_count: u32,
    pub(crate) salt: Option<String>,
    pub(crate) client: Name,
    pub(crate) server: Name,
    pub(crate) nonce: i32,
    pub(crate) time_bounds: AuthenticationTimeBound,
    pub(crate) flags: TicketFlags,
}

impl KerberosReplyAuthenticationBuilder {
    pub fn new(
        client: Name,
        server: Name,
        time_bounds: AuthenticationTimeBound,
        nonce: i32,
    ) -> Self {
        let aes256_cts_hmac_sha1_96_iter_count: u32 = PBKDF2_SHA1_ITER;
        let mut flags = TicketFlags::none();
        if time_bounds.renew_until().is_some() {
            flags |= TicketFlags::Renewable;
        }

        Self {
            aes256_cts_hmac_sha1_96_iter_count,
            salt: None,
            client,
            server,
            nonce,
            time_bounds,
            flags,
        }
    }

    pub fn set_salt(mut self, salt: Option<String>) -> Self {
        self.salt = salt;
        self
    }

    pub fn set_aes256_cts_hmac_sha1_96_iter_count(mut self, iter_count: u32) -> Self {
        self.aes256_cts_hmac_sha1_96_iter_count = iter_count;
        self
    }

    pub fn build(
        self,
        user_key: &DerivedKey,
        primary_key: &KdcPrimaryKey,
    ) -> Result<KerberosReply, KrbError> {
        // Build and encrypt the reply.
        let session_key = SessionKey::new();
        let session_key: KdcEncryptionKey = session_key.try_into()?;

        let (cname, crealm) = (&self.client).try_into()?;
        let (server_name, server_realm) = (&self.server).try_into()?;

        let auth_time = KerberosTime::from_system_time(self.time_bounds.auth_time())
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;
        let start_time = Some(
            KerberosTime::from_system_time(self.time_bounds.start_time())
                .map_err(|_| KrbError::DerEncodeKerberosTime)?,
        );
        let end_time = KerberosTime::from_system_time(self.time_bounds.end_time())
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;
        let renew_till = self
            .time_bounds
            .renew_until()
            .map(KerberosTime::from_system_time)
            .transpose()
            .map_err(|_| KrbError::DerEncodeKerberosTime)?;

        let last_req: Vec<LastRequestItem> = vec![LastRequestItem::None(SystemTime::UNIX_EPOCH)];
        let last_req = last_req
            .iter()
            .map(|i| i.try_into())
            .collect::<Result<Vec<LastReqItem>, KrbError>>()?;

        let enc_kdc_rep_part = EncKdcRepPart {
            key: session_key.clone(),
            last_req,
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

        let (etype_info2, enc_part) = user_key.encrypt_as_rep_part(enc_kdc_rep_part)?;

        let transited = TransitedEncoding {
            tr_type: 1,
            // Since no transit has occured, we record an empty str.
            contents: OctetString::new(b"").map_err(|_| KrbError::DerEncodeOctetString)?,
        };

        let ticket_inner = EncTicketPart {
            flags: self.flags,
            key: session_key,
            crealm,
            cname,
            transited,
            auth_time,
            start_time,
            end_time,
            renew_till,
            client_addresses: None,
            authorization_data: None,
        };

        let ticket_enc_part = primary_key.encrypt_tgt(ticket_inner)?;

        let ticket = EncTicket {
            tkt_vno: 5,
            service: self.server,
            enc_part: ticket_enc_part,
        };

        let name = self.client;

        let pa_data = Some(PreauthData {
            etype_info2: vec![etype_info2],
            ..Default::default()
        });

        Ok(KerberosReply::AS(AuthenticationReply {
            name,
            enc_part,
            pa_data,
            ticket,
        }))
    }
}
