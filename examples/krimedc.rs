use clap::{Parser, Subcommand};
use futures::{SinkExt, StreamExt};
use libkrime::proto::{AuthenticationRequest, KerberosReply, KerberosRequest};
use libkrime::KdcTcpCodec;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, trace};

async fn process_authentication(
    auth_req: AuthenticationRequest,
    server_state: &ServerState,
) -> Result<KerberosReply, KerberosReply> {
    // Got any etypes?
    if auth_req.etypes.is_empty() {
        return Err(KerberosReply::error_no_etypes(auth_req.service_name));
    }

    // The service name must be krbtgt for this realm.
    if !auth_req
        .service_name
        .is_service_krbtgt(server_state.realm.as_str())
    {
        return Err(KerberosReply::error_as_not_krbtgt(auth_req.service_name));
    }

    let Ok((cname, crealm)) = auth_req.client_name.principal_name() else {
        return Err(KerberosReply::error_client_principal(auth_req.service_name));
    };

    // Is the client for our realm?
    if crealm != server_state.realm.as_str() {
        return Err(KerberosReply::error_client_realm(auth_req.service_name));
    };

    // Is the client in our user db?
    let Some(user_record) = server_state.users.get(cname) else {
        return Err(KerberosReply::error_client_username(auth_req.service_name));
    };

    let Some(pre_enc_timestamp) = auth_req.preauth.enc_timestamp() else {
        let parep = KerberosReply::preauth_builder(auth_req.service_name).build();

        // Request pre-auth.
        return Ok(parep);
    };

    // Start to process and validate the enc timestamp.

    // In theory we should be able to cache the users base key.
    let key = pre_enc_timestamp
        .derive_key(
            user_record.password.as_bytes(),
            crealm.as_bytes(),
            cname.as_bytes(),
            Some(0x8000),
        )
        .map_err(|err| {
            error!(?err, "pre_enc_timestamp.derive_key");
            KerberosReply::error_no_key(auth_req.service_name.clone())
        })?;

    let pa_timestamp = pre_enc_timestamp
        .decrypt_pa_enc_timestamp(&key)
        .map_err(|err| {
            error!(?err, "pre_enc_timestamp.decrypt");
            KerberosReply::error_preauth_failed(auth_req.service_name.clone())
        })?;

    trace!(?pa_timestamp);

    // Check for the timestamp being in a valid range. If not, reject for clock skew.
    todo!()

    // Preauthentication SUCCESS. Now we can issue a ticket.
}

async fn process(socket: TcpStream, info: SocketAddr, server_state: Arc<ServerState>) {
    let mut kdc_stream = Framed::new(socket, KdcTcpCodec::default());

    while let Some(Ok(kdc_req)) = kdc_stream.next().await {
        match kdc_req {
            KerberosRequest::AS(auth_req) => {
                let reply = match process_authentication(auth_req, &server_state).await {
                    Ok(rep) => rep,
                    Err(krb_err) => krb_err,
                };

                if let Err(err) = kdc_stream.send(reply).await {
                    error!(?err, "error writing response, disconnecting");
                    break;
                }
                continue;
            }
            KerberosRequest::TGS(_) => {
                todo!();
            }
        }
    }
    debug!("closing client");
}

#[derive(Debug, clap::Parser)]
#[clap(about = "The Worlds Worst KDC - A Krime, If You Please")]
struct OptParser {
    // Apparently globals can't be required?
    // #[clap(global = true)]
    // config: PathBuf,
    #[clap(subcommand)]
    command: Opt,
}

#[derive(Debug, Subcommand)]
#[clap(about = "The Worlds Worst KDC - A Krime, If You Please")]
enum Opt {
    Run { config: PathBuf },
    // KeyTab { }
}

#[derive(Debug, Deserialize)]
struct UserPrincipal {
    password: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    realm: String,
    address: SocketAddr,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    primary_key: Vec<u8>,

    user: BTreeMap<String, UserPrincipal>,
    // services: BTreeMap<String, Service>,
}

impl From<Config> for ServerState {
    fn from(cr: Config) -> ServerState {
        let Config {
            realm,
            address,
            primary_key,
            user,
        } = cr;

        ServerState {
            realm,
            primary_key,
            users: user,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ServerState {
    realm: String,
    // address: SocketAddr,
    primary_key: Vec<u8>,

    users: BTreeMap<String, UserPrincipal>,
    // services: BTreeMap<String, Service>,
}

async fn main_run(config: Config) -> io::Result<()> {
    let listener = TcpListener::bind(&config.address).await?;

    info!("started krimedc on {}", config.address);

    let server_state = Arc::new(ServerState::from(config));

    loop {
        let (socket, info) = listener.accept().await?;
        let state = server_state.clone();
        tokio::spawn(async move { process(socket, info, state).await });
    }
}

fn parse_config<P: AsRef<Path>>(path: P) -> io::Result<Config> {
    let p: &Path = path.as_ref();
    let mut contents = String::new();
    let mut f = fs::File::open(&path)?;
    f.read_to_string(&mut contents)?;

    toml::from_str(&contents).map_err(|err| {
        error!(?err);
        io::Error::new(io::ErrorKind::Other, "toml parse failure")
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let opt = OptParser::parse();

    tracing_subscriber::fmt::init();

    match opt.command {
        Opt::Run { config } => {
            let cfg = parse_config(&config)?;
            main_run(cfg).await
        }
    }
}
