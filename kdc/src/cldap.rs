use crate::config::{CoreAction, TaskName};
use libkrimes::cldap::{CldapConfig, CldapConfigBuilder};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tokio_util::codec::BytesCodec;
use tokio_util::udp::UdpFramed;
use tracing::{error, info};

async fn cldap_udp_acceptor(
    sock: UdpSocket,
    cfg: &'static CldapConfig,
    mut rx: broadcast::Receiver<CoreAction>,
) {
    info!("Started task {}", TaskName::CldapUdp);

    let sock = Arc::new(sock);
    let mut codec = UdpFramed::new(sock.clone(), BytesCodec::new());

    loop {
        tokio::select! {
        Ok(action) = rx.recv() => {
            match action {
                CoreAction::Shutdown => break,
            }
        }
        frame = codec.next() => {
                if let Some(frame) = frame {
                    match frame {
                        Ok((msg, addr)) => {
                            tokio::spawn(libkrimes::cldap::process(cfg, sock.clone(), addr, msg));
                        },
                        Err(e) => {
                            error!("LDAP codec error, no LDAP message: {:?}", e)
                        }
                    }
                }
            }
        }
    }

    info!("Stopped task {}", TaskName::CldapUdp);
}

pub(crate) async fn create_cldap_server(
    cfg: &CldapConfigBuilder,
    rx: broadcast::Receiver<CoreAction>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    let cfg = cfg.build().expect("TODO");
    let cfg = Box::new(cfg);
    let cfg: &'static CldapConfig = Box::leak(cfg);

    if cfg.address().starts_with(":::") {
        let port = cfg.address().replacen(":::", "", 1);
        error!("Address '{}' looks like an attempt to wildcard bind with IPv6 on port {} - please try using '[::]:{}'", cfg.address(), port, port);
    }

    let address = cfg.address().parse::<SocketAddr>().map_err(|e| {
        error!("Could not parse address {} -> {:?}", cfg.address(), e);
    })?;

    let sock = UdpSocket::bind(address).await.map_err(|e| {
        error!("Could not bind to address {} -> {:?}", cfg.address(), e);
    })?;

    let handle = tokio::spawn(cldap_udp_acceptor(sock, cfg, rx));

    Ok(handle)
}
