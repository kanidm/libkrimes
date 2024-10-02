use clap::{Parser, Subcommand};
use futures::{SinkExt, StreamExt};
use libkrime::proto::{
    AuthenticationRequest, DerivedKey, KdcPrimaryKey, KerberosReply, KerberosRequest,
};
use libkrime::KdcTcpCodec;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, trace};

#[instrument(level = "trace", skip_all)]
async fn process_authentication(
    auth_req: AuthenticationRequest,
    server_state: &ServerState,
) -> Result<KerberosReply, KerberosReply> {
    let stime = SystemTime::now();

    // Got any etypes?
    if auth_req.etypes.is_empty() {
        return Err(KerberosReply::error_no_etypes(auth_req.service_name, stime));
    }

    // The service name must be krbtgt for this realm.
    if !auth_req
        .service_name
        .is_service_krbtgt(server_state.realm.as_str())
    {
        return Err(KerberosReply::error_as_not_krbtgt(
            auth_req.service_name,
            stime,
        ));
    }

    let Ok((cname, crealm)) = auth_req.client_name.principal_name() else {
        return Err(KerberosReply::error_client_principal(
            auth_req.service_name,
            stime,
        ));
    };

    // Is the client for our realm?
    if crealm != server_state.realm.as_str() {
        return Err(KerberosReply::error_client_realm(
            auth_req.service_name,
            stime,
        ));
    };

    // Is the client in our user db?
    let Some(user_record) = server_state.users.get(cname) else {
        return Err(KerberosReply::error_client_username(
            auth_req.service_name,
            stime,
        ));
    };

    let Some(pre_enc_timestamp) = auth_req.preauth.enc_timestamp() else {
        info!("ENC-TS Preauth not present, returning pre-auth parameters.");
        let parep = KerberosReply::preauth_builder(auth_req.service_name, stime)
            .set_key_params(&user_record.base_key)
            .build();

        // Request pre-auth.
        return Ok(parep);
    };
    info!("ENC-TS Preauth present.");

    // Start to process and validate the enc timestamp.

    let pa_timestamp = pre_enc_timestamp
        .decrypt_pa_enc_timestamp(&user_record.base_key)
        .map_err(|err| {
            error!(?err, "pre_enc_timestamp.decrypt");
            KerberosReply::error_preauth_failed(auth_req.service_name.clone(), stime)
        })?;

    trace!(?pa_timestamp, ?stime);

    let abs_offset = if pa_timestamp > stime {
        pa_timestamp.duration_since(stime)
    } else {
        stime.duration_since(pa_timestamp)
    }
    // This error shouldn't be possible. The error condition on duration_since is
    // when the right side of the term is actually *before* the left. Our if
    // condition should guard against thin.
    // However, let's do the right thing and check it anyway.
    .map_err(|kdc_err| {
        error!(?kdc_err);
        KerberosReply::error_internal(auth_req.service_name.clone(), stime)
    })?;

    trace!(?abs_offset);

    // Check for the timestamp being in a valid range. If not, reject for clock skew.
    if abs_offset > Duration::from_secs(300) {
        error!(?abs_offset, "clock skew");
        // ClockSkew
        return Err(KerberosReply::error_clock_skew(
            auth_req.service_name.clone(),
            stime,
        ));
    }

    // Preauthentication SUCCESS. Now we can consider issuing a ticket.

    trace!("PREAUTH SUCCESS");

    let builder = KerberosReply::authentication_builder(
        auth_req.client_name,
        auth_req.service_name.clone(),
        stime,
        auth_req.nonce,
    );

    builder
        .build(&user_record.base_key, &server_state.primary_key)
        .map_err(|kdc_err| {
            error!(?kdc_err);
            KerberosReply::error_internal(auth_req.service_name.clone(), stime)
        })
}

async fn process(socket: TcpStream, info: SocketAddr, server_state: Arc<ServerState>) {
    let mut kdc_stream = Framed::new(socket, KdcTcpCodec::default());
    trace!(?info, "connection from");

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

        let primary_key = KdcPrimaryKey::try_from(primary_key.as_slice()).unwrap();

        let users = user
            .into_iter()
            .map(|(n, u)| {
                let salt = format!("{}{}", realm, n);

                let base_key = DerivedKey::new_aes256_cts_hmac_sha1_96(&u.password, &salt).unwrap();

                (n, UserRecord { base_key })
            })
            .collect();

        ServerState {
            realm,
            primary_key,
            users,
        }
    }
}

#[derive(Debug)]
struct UserRecord {
    base_key: DerivedKey,
}

#[derive(Debug)]
struct ServerState {
    realm: String,
    // address: SocketAddr,
    primary_key: KdcPrimaryKey,

    users: BTreeMap<String, UserRecord>,
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
