use futures::{SinkExt, StreamExt};
use libkrime::proto::{KerberosReply, KerberosRequest};
use libkrime::KdcTcpCodec;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, trace};
use clap::{Parser, Subcommand};
use std::io;
use std::path::PathBuf;

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
pub struct OptParser {
    #[clap(global = true)]
    config: PathBuf,
    #[clap(subcommand)]
    command: Opt,
}

#[derive(Debug, Subcommand)]
#[clap(about = "The Worlds Worst KDC - A Krime, If You Please")]
pub enum Opt {
    Run {},
    // KeyTab { }
}

async fn main_run() -> io::Result<()> {
    let addr = "127.0.0.1:55000";

    let listener = TcpListener::bind(addr).await?;

    info!("started krimedc on {}", "127.0.0.1:55000");

    loop {
        let (socket, info) = listener.accept().await?;
        tokio::spawn(async move { process(socket, info).await });
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let opt = OptParser::parse();

    tracing_subscriber::fmt::init();

    match opt.command {
        Opt::Run {
        } => {
            todo!();
        }
    }

}

