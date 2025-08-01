use super::{DerivedKey, EtypeInfo2, Name, PreauthData};
use crate::asn1::constants::{encryption_types::EncryptionType, errors::KrbErrorCode};
use crate::constants::PBKDF2_SHA1_ITER;
use crate::proto::reply::KerberosReply;
use std::time::SystemTime;

#[derive(Debug)]
pub struct PreauthErrorReply {
    pub pa_data: PreauthData,
    pub service: Name,
    pub stime: SystemTime,
}

#[derive(Debug)]
pub struct ErrorReply {
    code: KrbErrorCode,
    service: Name,
    error_text: Option<String>,
    server_time: SystemTime,
}

impl ErrorReply {
    pub fn new(
        code: KrbErrorCode,
        service: Name,
        error_text: Option<String>,
        server_time: SystemTime,
    ) -> Self {
        Self {
            code,
            service,
            error_text,
            server_time,
        }
    }

    pub fn code(&self) -> &KrbErrorCode {
        &self.code
    }

    pub fn service(&self) -> &Name {
        &self.service
    }

    pub fn text(&self) -> &Option<String> {
        &self.error_text
    }

    pub fn server_time(&self) -> &SystemTime {
        &self.server_time
    }
}

pub struct KerberosReplyPreauthBuilder {
    pa_fx_cookie: Option<Vec<u8>>,
    aes256_cts_hmac_sha1_96_iter_count: u32,
    salt: Option<String>,
    service: Name,
    stime: SystemTime,
}

impl KerberosReplyPreauthBuilder {
    pub fn new(service: Name, stime: SystemTime) -> Self {
        let aes256_cts_hmac_sha1_96_iter_count: u32 = PBKDF2_SHA1_ITER;
        Self {
            pa_fx_cookie: None,
            aes256_cts_hmac_sha1_96_iter_count,
            salt: None,
            service,
            stime,
        }
    }

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

        KerberosReply::PA(PreauthErrorReply {
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
