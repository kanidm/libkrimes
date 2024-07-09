use clap::{Parser, Subcommand};
use futures::{SinkExt, StreamExt};
use libkrime::proto::{KerberosReply, KerberosRequest};
use libkrime::KdcTcpCodec;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, trace};

async fn process(socket: TcpStream, info: SocketAddr) {
    let mut kdc_stream = Framed::new(socket, KdcTcpCodec::default());

    let mut pre_auth_req_issued = false;

    while let Some(Ok(kdc_req)) = kdc_stream.next().await {
        trace!(?kdc_req);
        match kdc_req {
            KerberosRequest::Authentication {
                nonce,
                client_name,
                service_name,
                from,
                until,
                renew,
                preauth,
                etypes,
            } => {
                // Got any etypes?
                if etypes.is_empty() {
                    // Return err
                    todo!();
                }

                let Some(pre_enc_timestamp) = preauth.enc_timestamp() else {
                    if pre_auth_req_issued {
                        // Errror, we already told you we need pre auth.
                        todo!();
                    } else {
                        let parep =
                            KerberosReply::preauth_builder(service_name, "abcdefgh".to_string())
                                .build();

                        if let Err(err) = kdc_stream.send(parep).await {
                            error!(?err, "error writing response, disconnecting");
                            break;
                        }
                    }
                    continue;
                };

                // Start to process and validate the enc timestamp.

                // In theory we should be able to store the users base key.
                let key = pre_enc_timestamp
                    .derive_salted_key(b"password", b"abcdefgh", Some(0x8000))
                    .unwrap();

                let pa_timestamp = pre_enc_timestamp.decrypt_pa_enc_timestamp(&key).unwrap();

                trace!(?pa_timestamp);
            }
            KerberosRequest::TicketGrant {} => {
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
    primary_key: String,
    preauth_key: String,

    user: BTreeMap<String, UserPrincipal>,
    // services: BTreeMap<String, Service>,
}

async fn main_run(config: Config) -> io::Result<()> {
    let listener = TcpListener::bind(config.address).await?;

    info!("started krimedc on {}", config.address);

    loop {
        let (socket, info) = listener.accept().await?;
        tokio::spawn(async move { process(socket, info).await });
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
