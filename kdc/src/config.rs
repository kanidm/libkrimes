use libkrimes::cldap::CldapConfigBuilder;
use libkrimes::error::KrbError;
use libkrimes::proto::{DerivedKey, KdcPrimaryKey, Name};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use tracing::error;

fn default_kvno() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
pub struct UserPrincipal {
    pub name: String,
    pub password: String,
    #[serde(default = "default_kvno")]
    pub kvno: u32,
}

#[derive(Debug, Deserialize)]
pub struct ServicePrincipal {
    pub hostname: String,
    pub srvname: String,
    pub password: String,
    #[serde(default = "default_kvno")]
    pub kvno: u32,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub realm: String,
    pub address: String,
    pub cldap: Option<CldapConfigBuilder>,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub primary_key: Vec<u8>,
    pub user: Vec<UserPrincipal>,
    pub service: Vec<ServicePrincipal>,
}

impl Config {
    pub fn parse<P: AsRef<Path>>(path: P) -> io::Result<Config> {
        let mut contents = String::new();
        let mut f = fs::File::open(&path)?;
        f.read_to_string(&mut contents)?;

        toml::from_str(&contents).map_err(|err| {
            error!(?err);
            io::Error::other("toml parse failure")
        })
    }
}

#[derive(Debug, Clone)]
pub struct PrincipalRecord {
    pub service: bool,
    pub base_key: DerivedKey,
}

#[derive(Debug)]
pub struct ServerState {
    pub realm: String,
    pub primary_key: KdcPrimaryKey,
    pub allowed_clock_skew: Duration,

    pub ticket_granting_ticket_lifetime: Duration,
    pub service_granting_ticket_lifetime: Duration,

    pub ticket_min_lifetime: Duration,
    pub ticket_max_renew_time: Option<Duration>,

    pub principals: BTreeMap<Name, PrincipalRecord>,
}

impl TryFrom<&Config> for ServerState {
    type Error = KrbError;

    fn try_from(cr: &Config) -> Result<Self, Self::Error> {
        let Config {
            realm,
            address: _,
            cldap: _,
            primary_key,
            user,
            service,
        } = cr;

        let primary_key = KdcPrimaryKey::try_from(primary_key.as_slice())?;

        let principals = user
            .iter()
            .map(
                |UserPrincipal {
                     name,
                     password,
                     kvno,
                 }| {
                    let salt = format!("{realm}{name}");

                    let base_key =
                        DerivedKey::new_aes256_cts_hmac_sha1_96(password, &salt, None, *kvno)?;

                    let princ_name = Name::principal(name, realm);

                    Ok((
                        princ_name,
                        PrincipalRecord {
                            service: false,
                            base_key,
                        },
                    ))
                },
            )
            .chain(service.iter().map(
                |ServicePrincipal {
                     srvname,
                     hostname,
                     password,
                     kvno,
                 }| {
                    let name = format!("{srvname}/{hostname}");
                    let salt = format!("{realm}{name}");

                    let princ_name = Name::service(srvname, hostname, realm);

                    let base_key =
                        DerivedKey::new_aes256_cts_hmac_sha1_96(password, &salt, None, *kvno)?;

                    Ok((
                        princ_name,
                        PrincipalRecord {
                            service: true,
                            base_key,
                        },
                    ))
                },
            ))
            .collect::<Result<_, KrbError>>()?;

        let allowed_clock_skew = Duration::from_secs(300);

        // Short tickets are good, but not too short.
        let ticket_min_lifetime = Duration::from_secs(60);
        // Should be short-ish to promote frequent renewals.
        let ticket_granting_ticket_lifetime = Duration::from_secs(900);
        // You can renew for up to a week. We may change this ....
        let ticket_max_renew_time = Some(Duration::from_secs(86400 * 7));

        // This needs to be *long* because TGS can't be renewed, and most
        // applications absolutely *lose their mind* when this expires rapidly.
        //
        // For example, finder on macos with SMB just disconnects you soon after this
        // expires, doesn't try to get a new TGS and open a new session to continue
        // the connection or make a new connection.
        //
        // The only way to make this work is for the TGS to be looooooooooongggggggg.
        // I'm really not sure what value should be because if it's too long then that
        // allows an attacker a long-term access to the service. If it's too short,
        // then things break.
        //
        // Likely we need to ensure that there is a way to kill sessions on the SMB side
        // when we expire an account. Thought needed to what this value should be ...
        let service_granting_ticket_lifetime = Duration::from_secs(3600 * 8);

        Ok(ServerState {
            realm: realm.clone(),
            primary_key,
            principals,
            allowed_clock_skew,
            ticket_min_lifetime,
            ticket_max_renew_time,

            ticket_granting_ticket_lifetime,
            service_granting_ticket_lifetime,
        })
    }
}

#[derive(Clone, Debug)]
pub enum CoreAction {
    Shutdown,
}

#[derive(Clone, Debug)]
pub enum TaskName {
    KdcTcp,
    CldapUdp,
}

impl Display for TaskName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TaskName::KdcTcp => "Key Distribution Center (TCP)",
                TaskName::CldapUdp => "CLDAP (UDP)",
            }
        )
    }
}
