mod cc_dir;
mod cc_file;

#[cfg(feature = "keyring")]
mod cc_keyring;

use crate::asn1::constants::encryption_types::EncryptionType as Asn1EncryptionType;
use crate::asn1::constants::PrincipalNameType;
use crate::asn1::encrypted_data::EncryptedData as Asn1EncryptedData;
use crate::asn1::tagged_ticket::TaggedTicket as Asn1TaggedTicket;
use crate::asn1::tagged_ticket::Ticket as Asn1Ticket;
use crate::asn1::ticket_flags::TicketFlags;
use crate::client::conf::KerberosConfig;
use crate::error::KrbError;
use crate::proto::KerberosCredentials;
use crate::proto::{EncTicket, EncryptedData, KdcReplyPart, Name, SessionKey};
use binrw::{binread, binwrite};
use chrono::prelude::DateTime;
use chrono::Utc;
use crypto_glue::der::{asn1::OctetString, Encode};
use std::env;
use std::fmt;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tracing::{debug, error, trace};
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
#[derive(Debug)]
struct DataComponent {
    #[bw(try_calc(u32::try_from(value.len())))]
    value_len: u32,
    #[br(count = value_len)]
    value: Vec<u8>,
}

impl fmt::Display for DataComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.value {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct PrincipalV4 {
    name_type: u32,
    #[bw(try_calc(u32::try_from(components.len())))]
    components_count: u32,
    realm: DataComponent,
    #[br(count = components_count)]
    components: Vec<DataComponent>,
}

impl fmt::Display for PrincipalV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name: Name = self.try_into().map_err(|_| fmt::Error)?;
        write!(f, "{}", name)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
enum Principal {
    V4(PrincipalV4),
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::V4(v4) => {
                let name: Name = v4.try_into().map_err(|_| fmt::Error)?;
                write!(f, "{name}")
            }
        }
    }
}

#[binwrite]
#[bw(big)]
#[binread]
struct KeyBlockV4 {
    enc_type: u16,
    data: DataComponent,
}

impl fmt::Debug for KeyBlockV4 {
    #[cfg(not(feature = "developer"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBlockV4")
            .field("enc_type", &self.enc_type)
            .field("data", &"<SECRET>")
            .finish()
    }
    #[cfg(feature = "developer")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBlockV4")
            .field("enc_type", &self.enc_type)
            .field("data", &self.data)
            .finish()
    }
}

impl fmt::Display for KeyBlockV4 {
    #[cfg(not(feature = "developer"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] <SECRET>", self.enc_type)
    }
    #[cfg(feature = "developer")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.enc_type, self.data)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
enum KeyBlock {
    V4(KeyBlockV4),
}

impl fmt::Display for KeyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyBlock::V4(v4) => write!(f, "{}", v4),
        }
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct Address {
    addr_type: u16,
    data: DataComponent,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] ", self.addr_type)?;
        for v in &self.data.value {
            write!(f, "{:02X}", v)?;
        }
        writeln!(f)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct Addresses {
    #[bw(try_calc(u32::try_from(addresses.len())))]
    count: u32,
    #[br(count = count)]
    addresses: Vec<Address>,
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct AuthDataComponent {
    ad_type: u16,
    data: DataComponent,
}

impl fmt::Display for AuthDataComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.ad_type)?;
        for v in &self.data.value {
            write!(f, "{:02X}", v)?;
        }
        writeln!(f)
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct AuthData {
    #[bw(try_calc(u32::try_from(auth_data.len())))]
    count: u32,
    #[br(count = count)]
    auth_data: Vec<AuthDataComponent>,
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
enum Credential {
    V4(CredentialV4),
}

impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credential::V4(v4) => write!(f, "{}", v4),
        }
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
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

impl fmt::Display for CredentialV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Client: {}", self.client)?;
        writeln!(f, "Server: {}", self.server)?;
        writeln!(f, "Key: {}", self.keyblock)?;

        let d = UNIX_EPOCH + Duration::from_secs(self.authtime.into());
        let d = DateTime::<Utc>::from(d);
        writeln!(f, "Authentication time: {}", d)?;

        let d = UNIX_EPOCH + Duration::from_secs(self.starttime.into());
        let d = DateTime::<Utc>::from(d);
        writeln!(f, "Start time; {}", d)?;

        let d = UNIX_EPOCH + Duration::from_secs(self.endtime.into());
        let d = DateTime::<Utc>::from(d);
        writeln!(f, "End time: {}", d)?;

        let d = UNIX_EPOCH + Duration::from_secs(self.renew_till.into());
        let d = DateTime::<Utc>::from(d);
        writeln!(f, "Renew until: {}", d)?;

        writeln!(f, "Is SKEY: {}", self.is_skey)?;

        let t = TicketFlags::from_bits(self.ticket_flags);
        writeln!(f, "Ticket flags: {}", t)?;

        writeln!(f, "Addresses:")?;
        for addr in &self.addresses.addresses {
            writeln!(f, "  {}", addr)?;
        }

        writeln!(f, "Authorization data:")?;
        for a in &self.authdata.auth_data {
            writeln!(f, "  {}", a)?;
        }

        writeln!(f, "Ticket: {}", self.ticket)?;
        writeln!(f, "Second Ticket: {}", self.second_ticket)?;

        Ok(())
    }
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
                    EncryptedData::Aes256CtsHmacSha196 { kvno, data } => {
                        let t = Asn1Ticket {
                            tkt_vno: 5,
                            realm: (&enc_part.server).try_into()?,
                            sname: (&enc_part.server).try_into()?,
                            enc_part: Asn1EncryptedData {
                                etype: Asn1EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                                kvno: *kvno,
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
                    EncryptedData::Opaque { etype, kvno, data } => {
                        let t = Asn1Ticket {
                            tkt_vno: 5,
                            realm: (&enc_part.server).try_into()?,
                            sname: (&enc_part.server).try_into()?,
                            enc_part: Asn1EncryptedData {
                                etype: *etype,
                                kvno: *kvno,
                                cipher: OctetString::new(data.clone())
                                    .map_err(|_| KrbError::DerEncodeOctetString)?,
                            },
                        };
                        let tt = Asn1TaggedTicket::new(t);
                        tt.to_der().map_err(|e| {
                            error!(?e, "DerEncodeEncTicketPart");
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

impl TryInto<Name> for &PrincipalV4 {
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
            PrincipalNameType::NtSrvHst => {
                let n: Name = Name::SrvHst {
                    service: self
                        .components
                        .first()
                        .ok_or(KrbError::NameNotPrincipal)
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())?,
                    host: self
                        .components
                        .get(1..)
                        .ok_or(KrbError::NameNotServiceHost)?
                        .iter()
                        .map(|x| String::from_utf8_lossy(x.value.as_slice()).to_string())
                        .collect::<Vec<String>>()
                        .join("/"),
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

#[cfg(feature = "keyring")]
fn default_ccache_name() -> String {
    "KEYRING:persistent:%{uid}".to_string()
}

#[cfg(not(feature = "keyring"))]
fn default_ccache_name() -> String {
    "FILE:/tmp/krb5cc_%{uid}".to_string()
}

fn parse_ccache_name(ccache: Option<&str>) -> Result<String, KrbError> {
    let uid = get_current_uid().to_string();

    let ccache_name = match ccache {
        Some(c) => c.to_string(),
        None => match env::var("KRB5CCNAME") {
            Ok(val) => val,
            _ => {
                let config = KerberosConfig::from_defaults().map_err(|e| {
                    error!("Failed to read config: {:?}", e);
                    KrbError::ConfigError(e)
                })?;
                match config.libdefaults("default_ccache_name") {
                    Some(v) => v,
                    _ => default_ccache_name(),
                }
            }
        },
    }
    .replace("%{uid}", uid.as_str());
    Ok(ccache_name)
}

pub trait CredentialCache {
    fn cc_type(&self) -> &'static str;
    fn name(&self) -> Result<String, KrbError>;
    fn full_name(&self) -> Result<String, KrbError> {
        Ok(format!("{}:{}", self.cc_type(), self.name()?))
    }
    fn init(&mut self, name: &Name, clock_skew: Option<Duration>) -> Result<(), KrbError>;
    fn destroy(&mut self) -> Result<(), KrbError>;
    fn store(&mut self, credentials: &KerberosCredentials) -> Result<(), KrbError>;
    fn principal(&self) -> Result<Name, KrbError>;
    fn dump(&self) -> Result<(), KrbError>;
}

pub trait CredentialCacheCollection {
    fn cc_type(&self) -> &'static str;
    fn name(&self) -> Result<String, KrbError>;
    fn full_name(&self) -> Result<String, KrbError> {
        Ok(format!("{}:{}", self.cc_type(), self.name()?))
    }

    fn primary(&self) -> Result<Box<dyn CredentialCache>, KrbError>;
    fn new_unique(&self) -> Result<Box<dyn CredentialCache>, KrbError>;
    fn switch(&mut self, ccache: &dyn CredentialCache) -> Result<(), KrbError>;
    fn subsidiaries(&self) -> Result<Vec<Box<dyn CredentialCache>>, KrbError>;

    fn find(&self, name: &Name) -> Result<Box<dyn CredentialCache>, KrbError> {
        for cc in self.subsidiaries()? {
            if &cc.principal()? == name {
                return Ok(cc);
            }
        }
        Err(KrbError::CredentialCacheNotFound)
    }
    fn destroy(&mut self) -> Result<(), KrbError> {
        // Destroy the primary subsidiary. The primary key ramain stale.
        let mut cc = self.primary()?;
        cc.destroy()
    }

    fn try_iter(&self) -> Result<std::vec::IntoIter<Box<dyn CredentialCache>>, KrbError> {
        Ok(self.subsidiaries()?.into_iter())
    }
}

pub enum ResolvedCredentialCache {
    Collection(Box<dyn CredentialCacheCollection>),
    Subsidiary(Box<dyn CredentialCache>),
}

pub fn resolve(ccache_name: Option<&str>) -> Result<ResolvedCredentialCache, KrbError> {
    let ccache_name = parse_ccache_name(ccache_name)?;
    trace!(?ccache_name, "Resolving credential cache");

    if ccache_name.starts_with("FILE:") {
        return cc_file::resolve(ccache_name.as_str());
    }

    if ccache_name.starts_with("DIR:") {
        return cc_dir::resolve(ccache_name.as_str());
    }

    #[cfg(feature = "keyring")]
    if ccache_name.starts_with("KEYRING:") {
        return cc_keyring::resolve(ccache_name.as_str());
    }

    debug!(?ccache_name, "Unsupported credential cache type");
    Err(KrbError::UnsupportedCredentialCacheType)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Returns true when the environment cannot run KDC/MIT-dependent tests, in
    /// which case tests should early-return Ok(()) to avoid failing in CI or
    /// minimal environments.
    pub(super) fn skip_env() -> bool {
        if std::env::var("CI").is_ok() {
            tracing::warn!("Skipping ccache integration test in CI");
            return true;
        }
        if which::which("klist").is_err() {
            tracing::warn!("Skipping ccache integration test: klist not on PATH");
            return true;
        }
        false
    }

    /// Run `klist -c <ccache_name>` and return stdout. Asserts success.
    pub(super) fn klist(ccache_name: &str) -> String {
        let output = Command::new("klist")
            .arg("-c")
            .arg(ccache_name)
            .output()
            .expect("Unable to execute command klist");
        assert!(
            output.status.success(),
            "klist failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(output.stdout.as_slice()).to_string()
    }

    #[cfg(feature = "keyring")]
    pub(super) fn klist_all(ccache_name: &str) -> String {
        let output = Command::new("klist")
            .arg("-c")
            .arg(ccache_name)
            .arg("-A")
            .output()
            .expect("Unable to execute command klist");
        assert!(
            output.status.success(),
            "klist failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        String::from_utf8_lossy(output.stdout.as_slice()).to_string()
    }

    #[tokio::test]
    async fn test_resolve_file_is_subsidiary() -> Result<(), KrbError> {
        let ResolvedCredentialCache::Subsidiary(cc) =
            resolve(Some("FILE:/tmp/krime_resolve_test"))?
        else {
            panic!("FILE: must resolve to a Subsidiary");
        };
        assert_eq!(cc.cc_type(), "FILE");
        assert_eq!(cc.name()?, "/tmp/krime_resolve_test");
        assert_eq!(cc.full_name()?, "FILE:/tmp/krime_resolve_test");
        Ok(())
    }

    #[tokio::test]
    async fn test_resolve_dir_collection_vs_subsidiary() -> Result<(), KrbError> {
        // DIR:<dir> -> collection
        let dir = format!("/tmp/krime_resolve_dir_{}", std::process::id());
        let residual = format!("DIR:{dir}");
        let ResolvedCredentialCache::Collection(cccol) = resolve(Some(residual.as_str()))? else {
            panic!("DIR:<dir> must resolve to a Collection");
        };
        assert_eq!(cccol.cc_type(), "DIR");

        // DIR::<dir>/<sub> -> subsidiary
        let residual = format!("DIR::{dir}/s1");
        let ResolvedCredentialCache::Subsidiary(cc) = resolve(Some(residual.as_str()))? else {
            panic!("DIR::<dir>/<sub> must resolve to a Subsidiary");
        };
        assert_eq!(cc.cc_type(), "DIR");
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn test_resolve_unsupported_type() {
        let res = resolve(Some("BOGUS:/tmp/whatever"));
        if let Err(err) = res {
            assert!(matches!(err, KrbError::UnsupportedCredentialCacheType));
        } else {
            panic!("BOGUS:/tmp/whatever must fail with KrbError::UnsupportedCredentialCacheType")
        }
    }

    /// Full round-trip used by every cache type:
    /// init -> store -> principal() matches -> MIT klist sees the TGT -> destroy.
    pub(super) async fn store_and_verify_roundtrip(ccache_name: &str) -> Result<(), KrbError> {
        let creds = crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password").await?;

        let mut ccache = match crate::ccache::resolve(Some(ccache_name))? {
            ResolvedCredentialCache::Subsidiary(ccache) => ccache,
            ResolvedCredentialCache::Collection(cccol) => cccol.primary()?,
        };

        ccache.init(&creds.name, None)?;
        ccache.store(&creds)?;

        assert_eq!(ccache.principal()?, creds.name);

        let output = klist(ccache_name);
        assert!(
            output.contains("testuser@EXAMPLE.COM"),
            "klist output missing default principal: {output}"
        );
        assert!(
            output.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
            "klist output missing krbtgt service principal: {output}"
        );

        ccache.destroy()?;
        Ok(())
    }
}
