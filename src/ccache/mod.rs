mod cc_file;

#[cfg(feature = "keyring")]
mod cc_keyring;

use crate::asn1::constants::encryption_types::EncryptionType as Asn1EncryptionType;
use crate::asn1::constants::PrincipalNameType;
use crate::asn1::encrypted_data::EncryptedData as Asn1EncryptedData;
use crate::asn1::tagged_ticket::TaggedTicket as Asn1TaggedTicket;
use crate::asn1::tagged_ticket::Ticket as Asn1Ticket;
use crate::error::KrbError;
use crate::proto::{EncTicket, EncryptedData, KdcReplyPart, Name, SessionKey};
use binrw::{binread, binwrite};
use der::asn1::OctetString;
use der::Encode;
use std::env;
use std::time::Duration;
use std::time::SystemTime;
use tracing::error;
use uzers::get_current_uid;

/* TODO:
 *   - Handle cache conf entries. CredentialCache::new() could take a KV pair collection
 *   - Handle multiple credentials. The time offset is global, as the primary name. The
 *     there is a list of credentials, the primary name usually matches the first's
 *     credential 'client' field.
 */

#[binwrite]
#[bw(big)]
#[binread]
struct DataComponent {
    #[bw(try_calc(u32::try_from(value.len())))]
    value_len: u32,
    #[br(count = value_len)]
    value: Vec<u8>,
}

#[binwrite]
#[bw(big)]
#[binread]
struct PrincipalV4 {
    name_type: u32,
    #[bw(try_calc(u32::try_from(components.len())))]
    components_count: u32,
    realm: DataComponent,
    #[br(count = components_count)]
    components: Vec<DataComponent>,
}

#[binwrite]
#[bw(big)]
#[binread]
enum Principal {
    V4(PrincipalV4),
}

#[binwrite]
#[bw(big)]
#[binread]
struct KeyBlockV4 {
    enc_type: u16,
    data: DataComponent,
}

#[binwrite]
#[bw(big)]
#[binread]
enum KeyBlock {
    V4(KeyBlockV4),
}

#[binwrite]
#[bw(big)]
#[binread]
struct Address {
    addr_type: u16,
    data: DataComponent,
}

#[binwrite]
#[bw(big)]
#[binread]
struct Addresses {
    #[bw(try_calc(u32::try_from(addresses.len())))]
    count: u32,
    #[br(count = count)]
    addresses: Vec<Address>,
}

#[binwrite]
#[bw(big)]
#[binread]
struct AuthDataComponent {
    ad_type: u16,
    data: DataComponent,
}

#[binwrite]
#[bw(big)]
#[binread]
struct AuthData {
    #[bw(try_calc(u32::try_from(auth_data.len())))]
    count: u32,
    #[br(count = count)]
    auth_data: Vec<AuthDataComponent>,
}

#[binwrite]
#[bw(big)]
#[binread]
enum Credential {
    V4(CredentialV4),
}

#[binwrite]
#[bw(big)]
#[binread]
struct CredentialV4 {
    client: PrincipalV4,
    server: PrincipalV4,
    keyblock: KeyBlock,
    authtime: u32,
    starttime: u32,
    endtime: u32,
    renew_till: u32,
    is_skey: u8,
    ticket_flags: u32,
    addresses: Addresses,
    authdata: AuthData,
    ticket: DataComponent,
    second_ticket: DataComponent,
}

impl CredentialV4 {
    pub fn new(
        client: &Name,
        ticket: &EncTicket,
        enc_part: &KdcReplyPart,
    ) -> Result<Self, KrbError> {
        let cred: Self = CredentialV4 {
            client: client.try_into()?,
            server: (&enc_part.server).try_into()?,
            keyblock: KeyBlock::V4((&enc_part.key).try_into()?),
            authtime: enc_part
                .auth_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| KrbError::InsufficientData)?
                .as_secs() as u32,
            starttime: if let Some(start_time) = enc_part.start_time {
                start_time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|_| KrbError::InsufficientData)?
                    .as_secs() as u32
            } else {
                0u32
            },
            endtime: enc_part
                .end_time
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| KrbError::InsufficientData)?
                .as_secs() as u32,
            renew_till: if let Some(till) = enc_part.renew_until {
                till.duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|_| KrbError::InsufficientData)?
                    .as_secs() as u32
            } else {
                0u32
            },
            is_skey: 0u8,
            ticket_flags: enc_part.flags.bits().reverse_bits(),
            addresses: Addresses { addresses: vec![] },
            authdata: AuthData { auth_data: vec![] },
            ticket: DataComponent {
                value: match &ticket.enc_part {
                    EncryptedData::Aes256CtsHmacSha196 { kvno: _, data } => {
                        let t = Asn1Ticket {
                            tkt_vno: 5,
                            realm: (&enc_part.server).try_into()?,
                            sname: (&enc_part.server).try_into()?,
                            enc_part: Asn1EncryptedData {
                                etype: Asn1EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                                kvno: Some(1), // TODO Why?
                                cipher: OctetString::new(data.clone())
                                    .map_err(|_| KrbError::DerEncodeOctetString)?,
                            },
                        };
                        let tt = Asn1TaggedTicket::new(t);
                        tt.to_der().map_err(|e| {
                            println!("{e:#?}");
                            KrbError::DerEncodeEncTicketPart
                        })?
                    }
                },
            },
            second_ticket: DataComponent { value: vec![] },
        };
        Ok(cred)
    }
}

impl TryFrom<&Name> for PrincipalV4 {
    type Error = KrbError;

    fn try_from(name: &Name) -> Result<Self, Self::Error> {
        match name {
            Name::Principal { name, realm } => {
                let p: PrincipalV4 = PrincipalV4 {
                    name_type: PrincipalNameType::NtPrincipal as u32,
                    realm: DataComponent {
                        value: realm.as_bytes().into(),
                    },
                    components: vec![DataComponent {
                        value: name.as_bytes().into(),
                    }],
                };
                Ok(p)
            }
            Name::SrvInst {
                service,
                instance,
                realm,
            } => {
                let mut components: Vec<DataComponent> = vec![];
                components.push(DataComponent {
                    value: service.as_bytes().into(),
                });
                let iv: Vec<DataComponent> = instance
                    .iter()
                    .map(|x| DataComponent {
                        value: x.as_bytes().into(),
                    })
                    .collect();
                components.extend(iv);

                let p: PrincipalV4 = PrincipalV4 {
                    name_type: PrincipalNameType::NtSrvInst as u32,
                    realm: DataComponent {
                        value: realm.as_bytes().into(),
                    },
                    components,
                };
                Ok(p)
            }
            _ => Err(KrbError::PrincipalNameInvalidType),
        }
    }
}

impl TryInto<Name> for PrincipalV4 {
    type Error = KrbError;

    fn try_into(self) -> Result<Name, Self::Error> {
        let name_type: i32 = self.name_type as i32;
        let name_type: PrincipalNameType = name_type.try_into().map_err(|err| {
            error!(?err, ?name_type, "invalid principal name type");
            KrbError::PrincipalNameInvalidType
        })?;

        match name_type {
            PrincipalNameType::NtPrincipal => {
                let n: Name = Name::Principal {
                    name: self
                        .components
                        .iter()
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())
                        .collect::<Vec<String>>()
                        .join(""),
                    realm: String::from_utf8_lossy(self.realm.value.as_slice()).to_string(),
                };
                Ok(n)
            }
            PrincipalNameType::NtSrvInst => {
                let n: Name = Name::SrvInst {
                    service: self
                        .components
                        .first()
                        .ok_or(KrbError::NameNotPrincipal)
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())?,
                    instance: self
                        .components
                        .get(1..)
                        .ok_or(KrbError::NameNotPrincipal)?
                        .iter()
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())
                        .collect::<Vec<String>>(),
                    realm: String::from_utf8_lossy(self.realm.value.as_slice()).to_string(),
                };
                Ok(n)
            }
            _ => Err(KrbError::PrincipalNameInvalidType),
        }
    }
}

impl TryFrom<&SessionKey> for KeyBlockV4 {
    type Error = KrbError;

    fn try_from(value: &SessionKey) -> Result<Self, Self::Error> {
        match value {
            SessionKey::Aes256CtsHmacSha196 { k } => Ok(KeyBlockV4 {
                enc_type: 0x12,
                data: DataComponent { value: k.to_vec() },
            }),
        }
    }
}

fn parse_ccache_name(ccache: Option<&str>) -> String {
    let uid = get_current_uid().to_string();

    match ccache {
        Some(c) => c.to_string(),
        None => match env::var("KRB5CCNAME") {
            Ok(val) => val,
            _ => "FILE:/tmp/krb5cc_%{uid}".to_string(),
        },
    }
    .replace("%{uid}", uid.as_str())
}

pub fn store(
    name: &Name,
    ticket: &EncTicket,
    kdc_reply_part: &KdcReplyPart,
    clock_skew: Option<Duration>,
    ccache_name: Option<&str>,
) -> Result<(), KrbError> {
    let ccache_name = parse_ccache_name(ccache_name);

    if ccache_name.starts_with("FILE:") {
        return cc_file::store(
            name,
            ticket,
            kdc_reply_part,
            clock_skew,
            ccache_name.as_str(),
        );
    }

    #[cfg(feature = "keyring")]
    if ccache_name.starts_with("KEYRING:") {
        return cc_keyring::store(
            name,
            ticket,
            kdc_reply_part,
            clock_skew,
            ccache_name.as_str(),
        );
    }

    Err(KrbError::UnsupportedCredentialCacheType)
}

pub fn destroy(ccache_name: Option<&str>) -> Result<(), KrbError> {
    let ccache_name = parse_ccache_name(ccache_name);
    if ccache_name.starts_with("FILE:") {
        return cc_file::destroy(ccache_name.as_str());
    }

    #[cfg(feature = "keyring")]
    if ccache_name.starts_with("KEYRING:") {
        return cc_keyring::destroy(ccache_name.as_str());
    }

    Err(KrbError::UnsupportedCredentialCacheType)
}

#[cfg(test)]
mod tests {
    use tracing::warn;

    use super::*;
    use std::process::Command;
    #[cfg(feature = "keyring")]
    use std::process::Stdio;

    #[tokio::test]
    async fn test_ccache_file_store() -> Result<(), KrbError> {
        let _ = tracing_subscriber::fmt::try_init();
        if std::env::var("CI").is_ok() {
            // Skip this test in CI, as it requires a KDC running on localhost
            warn!("Skipping test_ccache_file_store in CI");
            return Ok(());
        }

        let (name, ticket, kdc_reply_part) =
            crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password").await?;

        let path = "/tmp/krb5cc_krime";
        let ccache_name = format!("FILE:{path}");
        super::store(
            &name,
            &ticket,
            &kdc_reply_part,
            None,
            Some(ccache_name.as_str()),
        )?;
        assert!(std::fs::exists(path).expect("Unable to check if file exists"));

        // TODO load and compare

        // Test MIT can parse the created ccache
        let output = Command::new("klist")
            .arg("-c")
            .arg(ccache_name.as_str())
            .output()
            .expect("Unable to execute command klist");
        assert!(output.status.success());

        let output = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
        assert!(output.contains("testuser@EXAMPLE.COM"));

        super::destroy(Some(ccache_name.as_str()))?;
        assert!(!std::fs::exists(path).expect("Unable to check if file exists"));

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "keyring")]
    async fn test_ccache_keyring_store() -> Result<(), KrbError> {
        if std::env::var("CI").is_ok() {
            // Skip this test in CI, as it requires a KDC running on localhost
            warn!("Skipping get_tgt in CI");
            return Ok(());
        }

        let ccache_name = "KEYRING:session:abc";
        let (name, ticket, kdc_reply_part) =
            crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password").await?;
        super::store(&name, &ticket, &kdc_reply_part, None, Some(ccache_name))?;

        let (name, ticket, kdc_reply_part) =
            crate::proto::get_tgt("testuser2", "EXAMPLE.COM", "password").await?;
        super::store(&name, &ticket, &kdc_reply_part, None, Some(ccache_name))?;

        let output = Command::new("klist")
            .stderr(Stdio::null())
            .arg("-c")
            .arg(ccache_name)
            .arg("-A")
            .output()
            .expect("Unable to execute command klist");
        assert!(output.status.success());

        let output = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
        assert!(output.contains("testuser@EXAMPLE.COM"));
        assert!(output.contains("testuser2@EXAMPLE.COM"));

        super::destroy(Some(ccache_name))?;

        let output = Command::new("klist")
            .stderr(Stdio::null())
            .arg("-c")
            .arg(ccache_name)
            .arg("-A")
            .output()
            .expect("Unable to execute command klist");
        assert!(output.status.success());

        let output = String::from_utf8_lossy(output.stdout.as_slice()).to_string();
        assert!(!output.contains("testuser@EXAMPLE.COM"));
        assert!(output.contains("testuser2@EXAMPLE.COM"));

        Ok(())
    }
}
