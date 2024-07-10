mod reply;
mod request;

pub use self::reply::KerberosReply;
pub use self::request::{AuthenticationRequest, KerberosRequest};

use crate::asn1::{
    constants::{encryption_types::EncryptionType, pa_data_types::PaDataType},
    encrypted_data::EncryptedData as KdcEncryptedData,
    etype_info2::ETypeInfo2 as KdcETypeInfo2,
    kerberos_string::KerberosString,
    pa_data::PaData,
    pa_enc_ts_enc::PaEncTsEnc,
    principal_name::PrincipalName,
    realm::Realm,
    tagged_ticket::TaggedTicket,
    Ia5String,
};
use crate::constants::AES_256_KEY_LEN;
use crate::crypto::{
    decrypt_aes256_cts_hmac_sha1_96, derive_key_aes256_cts_hmac_sha1_96,
    derive_key_external_salt_aes256_cts_hmac_sha1_96,
};
use crate::error::KrbError;
use der::{Decode, Encode};
use rand::{thread_rng, Rng};

use std::cmp::Ordering;
use std::time::{Duration, SystemTime};
use tracing::trace;

#[derive(Debug, Default)]
pub struct Preauth {
    enc_timestamp: Option<EncryptedData>,
    pa_fx_cookie: Option<Vec<u8>>,
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

#[derive(Debug, Default)]
pub struct PreauthData {
    pub(crate) pa_fx_fast: bool,
    pub(crate) enc_timestamp: bool,
    pub(crate) pa_fx_cookie: Option<Vec<u8>>,
    pub(crate) etype_info2: Vec<EtypeInfo2>,
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
        iter_count: Option<u32>,
    ) -> Result<BaseKey, KrbError> {
        match self {
            EncryptedData::Aes256CtsHmacSha196 { .. } => {
                // TODO: check the padata.
                derive_key_aes256_cts_hmac_sha1_96(passphrase, realm, cname, iter_count)
                    .map(|k| BaseKey::Aes256 { k })
            }
        }
    }

    pub fn derive_salted_key(
        &self,
        passphrase: &[u8],
        salt: &[u8],
        iter_count: Option<u32>,
    ) -> Result<BaseKey, KrbError> {
        match self {
            EncryptedData::Aes256CtsHmacSha196 { .. } => {
                // TODO: check the padata.
                derive_key_external_salt_aes256_cts_hmac_sha1_96(passphrase, salt, iter_count)
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

    pub fn is_service_krbtgt(&self, check_realm: &str) -> bool {
        match self {
            Self::SrvInst { service, realm } => service == "krbtgt" && check_realm == realm,
            _ => false,
        }
    }

    /// If the name is a PRINCIPAL then return it's name and realm compontents. If
    /// not, then an error is returned.
    pub fn principal_name(&self) -> Result<(&str, &str), KrbError> {
        match self {
            Name::Principal { name, realm } => Ok((name.as_str(), realm.as_str())),
            _ => Err(KrbError::NameNotPrincipal),
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

impl Preauth {
    pub fn enc_timestamp(&self) -> Option<&EncryptedData> {
        self.enc_timestamp.as_ref()
    }
}
