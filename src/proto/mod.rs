mod reply;
mod request;

pub use self::reply::{AuthenticationReply, KerberosReply, PreauthReply, TicketGrantReply};
pub use self::request::{AuthenticationRequest, KerberosRequest, TicketGrantRequest};

use crate::asn1::authenticator::Authenticator;
use crate::asn1::checksum::Checksum;
use crate::asn1::ap_req::ApReq;
use crate::asn1::constants::PrincipalNameType;
use crate::asn1::kdc_req_body::KdcReqBody;
use crate::asn1::{
    constants::{encryption_types::EncryptionType, pa_data_types::PaDataType},
    enc_kdc_rep_part::EncKdcRepPart,
    encrypted_data::EncryptedData as KdcEncryptedData,
    encryption_key::EncryptionKey as KdcEncryptionKey,
    etype_info2::ETypeInfo2 as KdcETypeInfo2,
    kerberos_string::KerberosString,
    pa_data::PaData,
    pa_enc_ts_enc::PaEncTsEnc,
    principal_name::PrincipalName,
    realm::Realm,
    tagged_enc_kdc_rep_part::TaggedEncKdcRepPart,
    tagged_ticket::TaggedTicket as Asn1Ticket,
    ticket_flags::TicketFlags,
    Ia5String, OctetString,
};
use crate::constants::{AES_256_KEY_LEN, RFC_PKBDF2_SHA1_ITER};
use crate::crypto::{
    checksum_hmac_sha1_96_aes256, decrypt_aes256_cts_hmac_sha1_96,
    derive_key_aes256_cts_hmac_sha1_96, encrypt_aes256_cts_hmac_sha1_96,
};
use crate::error::KrbError;
use der::{flagset::FlagSet, Decode, Encode};

use std::cmp::Ordering;
use std::fmt;
use std::time::{Duration, SystemTime};
use tracing::trace;

use crate::KerberosTcpCodec;
use futures::SinkExt;
use futures::StreamExt;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

// Zeroize blocked on https://github.com/RustCrypto/block-ciphers/issues/426
// use zeroize::Zeroizing;

#[derive(Debug, Default)]
pub struct Preauth {
    tgs_req: Option<ApReq>,
    pa_fx_fast: Option<PaFxFastRequest>,
    enc_timestamp: Option<EncryptedData>,
    pa_fx_cookie: Option<Vec<u8>>,
}

#[derive(Clone)]
pub enum DerivedKey {
    Aes256CtsHmacSha196 {
        k: [u8; AES_256_KEY_LEN],
        i: u32,
        s: String,
    },
}

impl DerivedKey {
    pub fn k(&self) -> Vec<u8> {
        match self {
            DerivedKey::Aes256CtsHmacSha196 { k, .. } => k.to_vec(),
        }
    }

    pub fn new_aes256_cts_hmac_sha1_96(passphrase: &str, salt: &str) -> Result<Self, KrbError> {
        // let iter_count = PKBDF2_SHA1_ITER;
        let iter_count = RFC_PKBDF2_SHA1_ITER;

        derive_key_aes256_cts_hmac_sha1_96(passphrase.as_bytes(), salt.as_bytes(), iter_count).map(
            |k| DerivedKey::Aes256CtsHmacSha196 {
                k,
                i: iter_count,
                s: salt.to_string(),
            },
        )
    }

    // Used to derive a key for the user. We have to do this to get the correct
    // etype from the enc data as pa_data may have many etype_info2 and the spec
    // doesn't call it an error to have multiple ... yay for confusing poorly
    // structured protocols.
    pub fn from_encrypted_reply(
        encrypted_data: &EncryptedData,
        pa_data_etype_info2: Option<&[EtypeInfo2]>,
        realm: &str,
        username: &str,
        passphrase: &str,
    ) -> Result<Self, KrbError> {
        // If only Krb had put the *parameters* with the encrypted data, like any other
        // sane ecosystem.
        match encrypted_data {
            EncryptedData::Aes256CtsHmacSha196 { .. } => {
                // Find if we have an etype info?

                let maybe_etype_info2 = pa_data_etype_info2
                    .iter()
                    .map(|slice| slice.iter())
                    .flatten()
                    .filter(|etype_info2| {
                        matches!(&etype_info2.etype, EncryptionType::AES256_CTS_HMAC_SHA1_96)
                    })
                    .next();

                let (salt, iter_count) = if let Some(etype_info2) = maybe_etype_info2 {
                    let salt = etype_info2.salt.as_ref().cloned();

                    let iter_count = if let Some(s2kparams) = &etype_info2.s2kparams {
                        if s2kparams.len() != 4 {
                            return Err(KrbError::PreauthInvalidS2KParams);
                        };
                        let mut iter_count = [0u8; 4];
                        iter_count.copy_from_slice(&s2kparams);

                        Some(u32::from_be_bytes(iter_count))
                    } else {
                        None
                    };

                    (salt, iter_count)
                } else {
                    (None, None)
                };

                let salt = salt.unwrap_or_else(|| format!("{}{}", realm, username));

                let iter_count = iter_count.unwrap_or(RFC_PKBDF2_SHA1_ITER);

                derive_key_aes256_cts_hmac_sha1_96(
                    passphrase.as_bytes(),
                    salt.as_bytes(),
                    iter_count,
                )
                .map(|k| DerivedKey::Aes256CtsHmacSha196 {
                    k,
                    i: iter_count,
                    s: salt,
                })
            }
        }
    }

    // This is used in pre-auth timestamp as there is no kvno as I can see?
    pub fn from_etype_info2(
        etype_info2: &EtypeInfo2,
        realm: &str,
        username: &str,
        passphrase: &str,
    ) -> Result<Self, KrbError> {
        let salt = etype_info2
            .salt
            .as_ref()
            .cloned()
            .unwrap_or_else(|| format!("{}{}", realm, username));

        match &etype_info2.etype {
            EncryptionType::AES256_CTS_HMAC_SHA1_96 => {
                // Iter count is from the s2kparams
                let iter_count = if let Some(s2kparams) = &etype_info2.s2kparams {
                    if s2kparams.len() != 4 {
                        return Err(KrbError::PreauthInvalidS2KParams);
                    };
                    let mut iter_count = [0u8; 4];
                    iter_count.copy_from_slice(&s2kparams);

                    u32::from_be_bytes(iter_count)
                } else {
                    // Assume the insecure default rfc value.
                    RFC_PKBDF2_SHA1_ITER
                };

                derive_key_aes256_cts_hmac_sha1_96(
                    passphrase.as_bytes(),
                    salt.as_bytes(),
                    iter_count,
                )
                .map(|k| DerivedKey::Aes256CtsHmacSha196 {
                    k,
                    i: iter_count,
                    s: salt,
                })
            }
            _ => Err(KrbError::UnsupportedEncryption),
        }
    }

    pub fn encrypt_pa_enc_timestamp(
        &self,
        paenctsenc: &PaEncTsEnc,
    ) -> Result<EncryptedData, KrbError> {
        let data = paenctsenc
            .to_der()
            .map_err(|_| KrbError::DerEncodePaEncTsEnc)?;

        // https://www.rfc-editor.org/rfc/rfc4120#section-5.2.7.2
        let key_usage = 1;

        match self {
            DerivedKey::Aes256CtsHmacSha196 { k, .. } => {
                encrypt_aes256_cts_hmac_sha1_96(k, &data, key_usage)
                    .map(|data| EncryptedData::Aes256CtsHmacSha196 { kvno: None, data })
            }
        }
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("DerivedKey");
        match self {
            DerivedKey::Aes256CtsHmacSha196 { i, s, .. } => builder
                .field("k", &"Aes256HmacSha1")
                .field("i", i)
                .field("s", s),
        }
        .finish()
    }
}

#[derive(Clone)]
pub enum SessionKey {
    Aes256CtsHmacSha196 { k: [u8; AES_256_KEY_LEN] },
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("SessionKey");
        match self {
            SessionKey::Aes256CtsHmacSha196 { .. } => builder.field("k", &"Aes256"),
        }
        .finish()
    }
}

impl SessionKey {
    fn encrypt_ap_req_authenticator(
        &self,
        authenticator: &Authenticator,
    ) -> Result<EncryptedData, KrbError> {
        let data = authenticator
            .to_der()
            .map_err(|e| KrbError::DerEncodeAuthenticator(e))?;

        let key_usage = 7;
        match self {
            SessionKey::Aes256CtsHmacSha196 { k } => {
                encrypt_aes256_cts_hmac_sha1_96(k, &data, key_usage)
                    .map(|data| EncryptedData::Aes256CtsHmacSha196 { kvno: None, data })
            }
        }
    }

    fn checksum_kdc_req_body(&self, req_body: &KdcReqBody) -> Result<Checksum, KrbError> {
        let req_body = req_body
            .to_der()
            .map_err(|e| KrbError::DerEncodeKdcReqBody(e))?;
        self.checksum(req_body.as_slice(), 6)
    }

    fn checksum(&self, data: &[u8], key_usage: i32) -> Result<Checksum, KrbError> {
        match self {
            SessionKey::Aes256CtsHmacSha196 { k } => {
                let checksum = checksum_hmac_sha1_96_aes256(data, k, key_usage)?;
                let checksum = OctetString::new(checksum).expect("Failed to create OctetString");
                let checksum = Checksum {
                    checksum_type: 16, // RFC 3962
                    checksum,
                };
                Ok(checksum)
            }
        }
    }
}

pub enum KdcPrimaryKey {
    Aes256 { k: [u8; AES_256_KEY_LEN] },
}

impl fmt::Debug for KdcPrimaryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("KdcPrimaryKey");
        match self {
            KdcPrimaryKey::Aes256 { .. } => builder.field("k", &"Aes256"),
        }
        .finish()
    }
}

impl TryFrom<&[u8]> for KdcPrimaryKey {
    type Error = KrbError;

    fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
        if key.len() == AES_256_KEY_LEN {
            let mut k = [0u8; AES_256_KEY_LEN];
            k.copy_from_slice(key);
            Ok(KdcPrimaryKey::Aes256 { k })
        } else {
            tracing::error!(key_len = %key.len(), expected = %AES_256_KEY_LEN);
            Err(KrbError::InvalidEncryptionKey)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ticket {
    tkt_vno: i8,
    service: Name,
    pub enc_part: EncryptedData,
}

// pub struct LastRequest

#[derive(Debug)]
pub struct KdcReplyPart {
    pub(crate) key: SessionKey,
    // Last req shows "last login" and probably isn't important for our needs.
    // last_req: (),
    pub(crate) nonce: u32,
    pub(crate) key_expiration: Option<SystemTime>,
    pub(crate) flags: FlagSet<TicketFlags>,
    pub(crate) auth_time: SystemTime,
    pub(crate) start_time: Option<SystemTime>,
    pub(crate) end_time: SystemTime,
    pub(crate) renew_until: Option<SystemTime>,
    pub(crate) server: Name,
    // Shows the addresses the ticket may be used from. Mostly these are broken
    // by nat, and so aren't used. These are just to display that there are limits
    // to the client, the enforced addrs are in the ticket.
    // client_addresses: Vec<HostAddress>,
}

#[derive(Debug, Clone)]
pub enum EncryptedData {
    Aes256CtsHmacSha196 { kvno: Option<u32>, data: Vec<u8> },
}

#[derive(Debug, Default)]
pub struct PreauthData {
    pub(crate) pa_fx_fast: bool,
    pub(crate) enc_timestamp: bool,
    pub(crate) pa_fx_cookie: Option<Vec<u8>>,
    pub(crate) etype_info2: Vec<EtypeInfo2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Name {
    Principal {
        name: String,
        realm: String,
    },
    SrvInst {
        service: String,
        instance: Vec<String>,
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

#[derive(Debug, Clone)]
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

impl TryFrom<Vec<PaData>> for PreauthData {
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

        Ok(PreauthData {
            pa_fx_fast,
            pa_fx_cookie,
            enc_timestamp,
            etype_info2,
        })
    }
}

impl TryFrom<Vec<PaData>> for Preauth {
    type Error = KrbError;

    fn try_from(pavec: Vec<PaData>) -> Result<Self, Self::Error> {
        let mut preauth = Preauth::default();

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
                PaDataType::PaTgsReq => {
                    // 5.2.7.1 - The padata_value contains an encoded AP-REQ
                    let ap_req = ApReq::from_der(padata_value.as_bytes())
                        .map_err(|_| KrbError::DerDecodePaData)?;

                    preauth.tgs_req = Some(ap_req);
                }
                PaDataType::PaEncTimestamp => {
                    let enc_timestamp = KdcEncryptedData::from_der(padata_value.as_bytes())
                        .map_err(|_| KrbError::DerDecodePaData)
                        .and_then(EncryptedData::try_from)?;
                    preauth.enc_timestamp = Some(enc_timestamp);
                }
                PaDataType::PaFxCookie => {
                    preauth.pa_fx_cookie = Some(padata_value.as_bytes().to_vec())
                }
                PaDataType::PaFxFast => {
                    let pa_fx_data = PaFxFastRequest::from_der(padata_value.as_bytes())
                        .map_err(|_| KrbError::DerDecodePaData)
                        .and_then(EncryptedData::try_from)?;
                    preauth.pa_fix_data = Some(pa_fx_data);
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
    fn decrypt_data(&self, base_key: &DerivedKey, key_usage: i32) -> Result<Vec<u8>, KrbError> {
        match (self, base_key) {
            (
                EncryptedData::Aes256CtsHmacSha196 { kvno: _, data },
                DerivedKey::Aes256CtsHmacSha196 { k, .. },
            ) => decrypt_aes256_cts_hmac_sha1_96(&k, &data, key_usage),
        }
    }

    pub fn decrypt_enc_kdc_rep(&self, base_key: &DerivedKey) -> Result<KdcReplyPart, KrbError> {
        // RFC 4120 The key usage value for encrypting this field is 3 in an AS-REP
        // message, using the client's long-term key or another key selected
        // via pre-authentication mechanisms.
        let data = self.decrypt_data(base_key, 3)?;

        let tagged_kdc_enc_part = TaggedEncKdcRepPart::from_der(&data).map_err(|e| {
            println!("{:#?}", e);
            KrbError::DerDecodeEncKdcRepPart
        })?;

        // RFC states we should relax the tag check on these.

        let kdc_enc_part = match tagged_kdc_enc_part {
            TaggedEncKdcRepPart::EncTgsRepPart(part) | TaggedEncKdcRepPart::EncAsRepPart(part) => {
                part
            }
        };

        KdcReplyPart::try_from(kdc_enc_part)
    }

    pub fn decrypt_pa_enc_timestamp(&self, base_key: &DerivedKey) -> Result<SystemTime, KrbError> {
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

impl TryInto<KdcEncryptedData> for EncryptedData {
    type Error = KrbError;

    fn try_into(self) -> Result<KdcEncryptedData, KrbError> {
        match self {
            EncryptedData::Aes256CtsHmacSha196 { kvno, data } => Ok(KdcEncryptedData {
                etype: EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                kvno,
                cipher: OctetString::new(data).map_err(|e| {
                    println!("{:#?}", e);
                    KrbError::UnsupportedEncryption // TODO
                })?,
            }),
        }
    }
}

impl TryFrom<Asn1Ticket> for Ticket {
    type Error = KrbError;

    fn try_from(tkt: Asn1Ticket) -> Result<Self, Self::Error> {
        let Asn1Ticket(tkt) = tkt;

        let service = Name::try_from((tkt.sname, tkt.realm))?;
        let enc_part = EncryptedData::try_from(tkt.enc_part)?;
        let tkt_vno = tkt.tkt_vno;

        Ok(Ticket {
            tkt_vno,
            service,
            enc_part,
        })
    }
}

impl TryInto<Asn1Ticket> for Ticket {
    type Error = KrbError;

    fn try_into(self) -> Result<Asn1Ticket, KrbError> {
        let t = crate::asn1::tagged_ticket::Ticket {
            tkt_vno: self.tkt_vno,
            realm: (&self.service).try_into()?,
            sname: (&self.service).try_into()?,
            enc_part: self.enc_part.try_into()?,
        };
        Ok(Asn1Ticket::new(t))
    }
}

impl TryFrom<EncKdcRepPart> for KdcReplyPart {
    type Error = KrbError;

    fn try_from(enc_kdc_rep_part: EncKdcRepPart) -> Result<Self, Self::Error> {
        trace!(?enc_kdc_rep_part);

        let key = SessionKey::try_from(enc_kdc_rep_part.key)?;
        let server = Name::try_from((enc_kdc_rep_part.server_name, enc_kdc_rep_part.server_realm))?;

        let nonce = enc_kdc_rep_part.nonce;
        // let flags = enc_kdc_rep_part.flags.bits();
        let flags = enc_kdc_rep_part.flags;

        let key_expiration = enc_kdc_rep_part.key_expiration.map(|t| t.to_system_time());
        let start_time = enc_kdc_rep_part.start_time.map(|t| t.to_system_time());
        let renew_until = enc_kdc_rep_part.renew_till.map(|t| t.to_system_time());
        let auth_time = enc_kdc_rep_part.auth_time.to_system_time();
        let end_time = enc_kdc_rep_part.end_time.to_system_time();

        Ok(KdcReplyPart {
            key,
            nonce,
            key_expiration,
            flags,
            auth_time,
            start_time,
            end_time,
            renew_until,
            server,
        })
    }
}

impl TryFrom<KdcEncryptionKey> for SessionKey {
    type Error = KrbError;

    fn try_from(kdc_key: KdcEncryptionKey) -> Result<Self, Self::Error> {
        let key_type = EncryptionType::try_from(kdc_key.key_type)
            .map_err(|_| KrbError::UnsupportedEncryption)?;
        match key_type {
            EncryptionType::AES256_CTS_HMAC_SHA1_96 => {
                if kdc_key.key_value.as_bytes().len() == AES_256_KEY_LEN {
                    let mut k = [0u8; AES_256_KEY_LEN];
                    k.copy_from_slice(kdc_key.key_value.as_bytes());
                    Ok(SessionKey::Aes256CtsHmacSha196 { k })
                } else {
                    Err(KrbError::InvalidEncryptionKey)
                }
            }
            _ => Err(KrbError::UnsupportedEncryption),
        }
    }
}

impl Name {
    pub fn principal(name: &str, realm: &str) -> Self {
        Self::Principal {
            name: name.to_string(),
            realm: realm.to_string(),
        }
    }

    pub fn service(name: &str, hostname: &str, realm: &str) -> Self {
        Self::SrvHst {
            service: name.to_string(),
            host: hostname.to_string(),
            realm: realm.to_string(),
        }
    }

    pub fn service_krbtgt(realm: &str) -> Self {
        /*
         * RFC4120, section 7.3, Name of the TGS
         * The principal identifier of the ticket-granting service shall be
         * composed of three parts: the realm of the KDC issuing the TGS ticket,
         * and a two-part name of type NT-SRV-INST, with the first part "krbtgt"
         * and the second part the name of the realm that will accept the TGT.
         *
         * For example, a TGT issued by the ATHENA.MIT.EDU realm to be used to
         * get tickets from the ATHENA.MIT.EDU KDC has a principal identifier of
         * "ATHENA.MIT.EDU" (realm), ("krbtgt", "ATHENA.MIT.EDU") (name).
         *
         * A TGT issued by the ATHENA.MIT.EDU realm to be used to get tickets from the
         * MIT.EDU realm has a principal identifier of "ATHENA.MIT.EDU" (realm),
         * ("krbtgt", "MIT.EDU") (name).
         */
        Self::SrvInst {
            service: "krbtgt".to_string(),
            instance: vec![realm.to_string()],
            realm: realm.to_string(),
        }
    }

    pub fn is_service_krbtgt(&self, check_realm: &str) -> bool {
        match self {
            Self::SrvInst {
                service,
                instance,
                realm,
            } => service == "krbtgt" && check_realm == realm && instance.is_empty(),
            _ => false,
        }
    }

    /// If the name is a PRINCIPAL then return it's name and realm compontents. If
    /// not, then an error is returned.
    pub fn principal_name(&self) -> Result<(&str, &str), KrbError> {
        trace!(principal_name = ?self);
        match self {
            Name::Principal { name, realm } => Ok((name.as_str(), realm.as_str())),
            _ => Err(KrbError::NameNotPrincipal),
        }
    }
}

impl TryInto<Realm> for &Name {
    type Error = KrbError;

    fn try_into(self) -> Result<Realm, KrbError> {
        match self {
            Name::Principal { name: _, realm } => {
                let realm = KerberosString(Ia5String::new(realm).unwrap());
                Ok(realm)
            }
            Name::SrvInst {
                service: _,
                instance: _,
                realm,
            } => {
                let realm = KerberosString(Ia5String::new(realm).unwrap());
                Ok(realm)
            }
            Name::SrvHst {
                service: _,
                host: _,
                realm,
            } => {
                let realm = KerberosString(Ia5String::new(realm).unwrap());
                Ok(realm)
            }
        }
    }
}

impl TryInto<PrincipalName> for &Name {
    type Error = KrbError;

    fn try_into(self) -> Result<PrincipalName, KrbError> {
        match self {
            Name::Principal { name, realm: _ } => {
                let name_string = vec![KerberosString(Ia5String::new(name).unwrap())];

                Ok(PrincipalName {
                    name_type: PrincipalNameType::NtPrincipal as i32,
                    name_string,
                })
            }
            Name::SrvInst {
                service,
                instance,
                realm: _,
            } => {
                let primary: Vec<KerberosString> =
                    vec![KerberosString(Ia5String::new(&service).unwrap())];
                let instance: Vec<KerberosString> = instance
                    .iter()
                    .map(|x| KerberosString(Ia5String::new(x).unwrap()))
                    .collect();
                let name_string: Vec<KerberosString> =
                    vec![primary, instance].into_iter().flatten().collect();

                Ok(PrincipalName {
                    name_type: PrincipalNameType::NtSrvInst as i32,
                    name_string,
                })
            }
            Name::SrvHst {
                service,
                host,
                realm: _,
            } => {
                let name_string = vec![
                    KerberosString(Ia5String::new(service).unwrap()),
                    KerberosString(Ia5String::new(host).unwrap()),
                ];

                Ok(PrincipalName {
                    name_type: PrincipalNameType::NtSrvHst as i32,
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
                        name_type: PrincipalNameType::NtPrincipal as i32,
                        name_string,
                    },
                    realm,
                ))
            }
            Name::SrvInst {
                service,
                instance,
                realm,
            } => {
                let primary: Vec<KerberosString> =
                    vec![KerberosString(Ia5String::new(&service).unwrap())];
                let instance: Vec<KerberosString> = instance
                    .iter()
                    .map(|x| KerberosString(Ia5String::new(x).unwrap()))
                    .collect();
                let name_string: Vec<KerberosString> =
                    vec![primary, instance].into_iter().flatten().collect();
                let realm = KerberosString(Ia5String::new(realm).unwrap());
                Ok((
                    PrincipalName {
                        name_type: PrincipalNameType::NtSrvInst as i32,
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
                        name_type: PrincipalNameType::NtSrvHst as i32,
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

        let name_type: PrincipalNameType = name_type
            .try_into()
            .map_err(|_| KrbError::InvalidPrincipalNameType(name_type))?;

        trace!(?name_type, ?name_string);

        match name_type {
            PrincipalNameType::NtPrincipal => {
                let name = name_string.get(0).unwrap().into();
                let realm = name_string.get(1).unwrap().into();
                Ok(Name::Principal { name, realm })
            }
            PrincipalNameType::NtSrvInst => {
                let (service, instance) = name_string.split_first().unwrap();
                let service: String = service.into();
                let mut instance: Vec<String> = instance.iter().map(|x| x.into()).collect();
                let realm: String = instance.pop().unwrap();
                Ok(Name::SrvInst {
                    service,
                    instance,
                    realm,
                })
            }
            PrincipalNameType::NtSrvHst => {
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
        let name_type: PrincipalNameType = name_type
            .try_into()
            .map_err(|_| KrbError::InvalidPrincipalNameType(name_type))?;

        match name_type {
            PrincipalNameType::NtPrincipal => {
                let name = name_string.get(0).unwrap().into();
                Ok(Name::Principal { name, realm })
            }
            PrincipalNameType::NtSrvInst => {
                let (service, instance) = name_string.split_first().unwrap();
                Ok(Name::SrvInst {
                    service: service.into(),
                    instance: instance.iter().map(|x| x.into()).collect(),
                    realm,
                })
            }
            PrincipalNameType::NtSrvHst => {
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

impl Preauth {
    pub fn enc_timestamp(&self) -> Option<&EncryptedData> {
        self.enc_timestamp.as_ref()
    }
}

pub async fn get_tgt(
    principal: &str,
    realm: &str,
    password: &str,
) -> Result<(Name, Ticket, KdcReplyPart), KrbError> {
    let stream = TcpStream::connect("127.0.0.1:55000")
        .await
        .expect("Unable to connect to localhost:55000");

    let mut krb_stream = Framed::new(stream, KerberosTcpCodec::default());

    let now = SystemTime::now();
    let client_name = Name::principal(principal, realm);
    let as_req = KerberosRequest::build_as(
        &client_name,
        Name::service_krbtgt(realm),
        now + Duration::from_secs(3600),
    )
    .renew_until(Some(now + Duration::from_secs(86400 * 7)))
    .build();

    // Write a request
    krb_stream
        .send(as_req)
        .await
        .expect("Failed to transmit request");

    let response = krb_stream
        .next()
        .await
        .unwrap()
        .map_err(|e| KrbError::IoError(e))?;

    let (name, ticket, kdc_reply): (Name, Ticket, KdcReplyPart) = match response {
        KerberosReply::AS(AuthenticationReply {
            name,
            enc_part,
            pa_data,
            ticket,
        }) => {
            let etype_info = pa_data
                .as_ref()
                .map(|pa_inner| pa_inner.etype_info2.as_slice());

            let base_key = DerivedKey::from_encrypted_reply(
                &enc_part, etype_info, realm, principal, password,
            )?;

            let kdc_reply = enc_part.decrypt_enc_kdc_rep(&base_key)?;
            (name, ticket, kdc_reply)
        }
        _ => unreachable!(),
    };

    Ok((name, ticket, kdc_reply))
}

#[cfg(test)]
mod tests {
    use crate::asn1::kdc_req_body::KdcReqBody;

    use super::SessionKey;
    use assert_hex::assert_eq_hex;
    use der::Decode;

    #[tokio::test]
    async fn test_ap_req_authenticator_checksum() {
        let kdc_req_body = "3072a0050303000081a20d1b0b4558414d504c452e434f4da3253023a003020103a11c301a1b04686f73741b127065707065722e6578616d706c652e636f6da511180f32303234313031313131303335395aa611180f32303234313031383130303335395aa706020436ce306ba8053003020112";
        let kdc_req_body = hex::decode(kdc_req_body).expect("Failed to decode sample");
        let kdc_req_body: KdcReqBody =
            KdcReqBody::from_der(&kdc_req_body).expect("Failed to DER decode sample");
        let session_key = "167391F64DA06DDE35752AFC110DCF6BFD797BF2B64027C98941ACDBDE3C356B";
        let session_key = hex::decode(session_key).expect("Failed to decode sample");
        let session_key = SessionKey::Aes256CtsHmacSha196 {
            k: session_key
                .try_into()
                .expect("Failed to create session key"),
        };
        let checksum = "E101C395D98466F1FE8B6D79";
        let checksum = hex::decode(checksum).expect("Failed to decode sample");
        let calculated_checksum = session_key
            .checksum_kdc_req_body(&kdc_req_body)
            .expect("Failed to compute checksum");
        let calculated_checksum = calculated_checksum.checksum.as_bytes();

        assert_eq_hex!(checksum, calculated_checksum);
    }
}
