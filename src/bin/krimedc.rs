#![deny(warnings)]
#![warn(unused_extern_crates)]
// Enable some groups of clippy lints.
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
// Specific lints to enforce.
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![allow(clippy::unreachable)]

use clap::{Parser, Subcommand};
use futures::{SinkExt, StreamExt};
use libkrime::error::KrbError;
use libkrime::proto::{
    AuthenticationRequest, AuthenticationTimeBound, DerivedKey, KdcPrimaryKey, KerberosReply,
    KerberosRequest, Name, TicketGrantRequest, TicketGrantRequestUnverified, TicketGrantTimeBound,
    TicketRenewTimeBound,
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

#[instrument(level = "info", skip_all)]
async fn process_authentication(
    auth_req: &AuthenticationRequest,
    server_state: &ServerState,
) -> Result<KerberosReply, KerberosReply> {
    let stime = SystemTime::now();

    // Got any etypes?
    if auth_req.etypes.is_empty() {
        return Err(KerberosReply::error_no_etypes(
            auth_req.service_name.clone(),
            stime,
        ));
    }

    // The service name must be krbtgt for this realm.
    if !auth_req
        .service_name
        .is_service_krbtgt(server_state.realm.as_str())
    {
        error!("Request not for KRBTGT");
        return Err(KerberosReply::error_as_not_krbtgt(
            auth_req.service_name.clone(),
            stime,
        ));
    }

    // Is the client for our realm?
    // Is the client in our user db?
    // This look up answer both as the client_name contains realm given how we structure
    // the name enum
    let Some(principal_record) = server_state.principals.get(&auth_req.client_name) else {
        return Err(KerberosReply::error_client_username(
            auth_req.service_name.clone(),
            stime,
        ));
    };

    // Now, if the req is a user princ or a service princ we have to take different paths.
    // This is because user princs demand pre-auth, but service ones don't. Service princs
    // are required to have stronger keys which is why they are exempted.

    if !principal_record.service {
        let Some(pre_enc_timestamp) = auth_req.preauth.enc_timestamp() else {
            info!("ENC-TS Preauth not present, returning pre-auth parameters.");
            let parep = KerberosReply::preauth_builder(auth_req.service_name.clone(), stime)
                // This sets the correct number of iterations based on what the principals
                // key is set to use. We generally bump this value up because the defaults
                // are woefully inadequate.
                .set_key_params(&principal_record.base_key)
                .build();

            trace!(?parep);

            // Request pre-auth.
            return Ok(parep);
        };
        info!("ENC-TS Preauth present.");

        // Start to process and validate the enc timestamp.

        let pa_timestamp = pre_enc_timestamp
            .decrypt_pa_enc_timestamp(&principal_record.base_key)
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
        if abs_offset > server_state.allowed_clock_skew {
            error!(?abs_offset, "clock skew");
            // ClockSkew
            return Err(KerberosReply::error_clock_skew(
                auth_req.service_name.clone(),
                stime,
            ));
        }

        // Preauthentication SUCCESS. Now we can consider issuing a ticket.

        trace!("PREAUTH SUCCESS");
    }

    // This function will perform safe calculations of the time bounds.
    let time_bounds = match AuthenticationTimeBound::from_as_req(
        stime,
        server_state.allowed_clock_skew,
        server_state.ticket_min_lifetime,
        server_state.ticket_granting_ticket_lifetime,
        server_state.ticket_granting_ticket_lifetime,
        server_state.ticket_max_renew_time,
        auth_req,
    ) {
        Ok(time_bounds) => time_bounds,
        Err(time_bound_error) => {
            return Err(time_bound_error.to_kerberos_reply(&auth_req.service_name, stime))
        }
    };

    /*
     * The flags field of the new ticket will have the following options set
     * if they have been requested and if the policy of the local realm
     * allows:  FORWARDABLE, MAY-POSTDATE, POSTDATED, PROXIABLE, RENEWABLE.
     * If the new ticket is postdated (the starttime is in the future), its
     * INVALID flag will also be set.
     */

    // We should not bother with forwarded/proxiable until there is a genuine
    // need for them. If anything we should never add them as these are insecure
    // options.

    let builder = KerberosReply::authentication_builder(
        auth_req.client_name.clone(),
        Name::service_krbtgt(server_state.realm.as_str()),
        time_bounds,
        auth_req.nonce,
    );

    builder
        .build(&principal_record.base_key, &server_state.primary_key)
        .map_err(|kdc_err| {
            error!(?kdc_err);
            KerberosReply::error_internal(auth_req.service_name.clone(), stime)
        })
}

#[instrument(level = "info", skip_all)]
async fn process_ticket_grant(
    tgs_req: &TicketGrantRequestUnverified,
    server_state: &ServerState,
) -> Result<KerberosReply, KerberosReply> {
    let stime = SystemTime::now();

    let tgs_req_valid = tgs_req
        .validate(&server_state.primary_key, &server_state.realm)
        .map_err(|err| {
            error!(?err, "Unable to validate tgs_req");
            let service_name = Name::service_krbtgt(server_state.realm.as_str());
            KerberosReply::error_request_failed_validation(service_name, stime)
        })?;

    trace!(?tgs_req_valid);

    let service_name = tgs_req_valid.service_name().clone().service_hst_normalise();

    trace!(?service_name);

    if service_name.is_service_krbtgt(server_state.realm.as_str()) {
        // This is a renewal request for the users TGT
        return process_ticket_renewal(tgs_req_valid, server_state).await;
    }

    // TODO!!!!!
    // =========
    // At this point we should also be verifying the requesting principals session
    // validity.

    // Is the service in our db?
    let Some(service_record) = server_state.principals.get(&service_name) else {
        error!(?service_name, "Unable to find service name");
        return Err(KerberosReply::error_service_name(service_name, stime));
    };

    let time_bounds = match TicketGrantTimeBound::from_tgs_req(
        stime,
        server_state.allowed_clock_skew,
        server_state.service_granting_ticket_lifetime,
        &tgs_req_valid,
    ) {
        Ok(time_bounds) => time_bounds,
        Err(time_bound_error) => {
            return Err(time_bound_error.to_kerberos_reply(&service_name, stime))
        }
    };

    let builder = KerberosReply::ticket_grant_builder(tgs_req_valid, time_bounds);

    builder.build(&service_record.base_key).map_err(|kdc_err| {
        error!(?kdc_err);
        KerberosReply::error_internal(service_name, stime)
    })
}

#[instrument(level = "info", skip_all)]
async fn process_ticket_renewal(
    tgs_req_valid: TicketGrantRequest,
    server_state: &ServerState,
) -> Result<KerberosReply, KerberosReply> {
    let stime = SystemTime::now();
    let service_name = tgs_req_valid.service_name().clone();

    let time_bounds = match TicketRenewTimeBound::from_tgs_req(
        stime,
        server_state.allowed_clock_skew,
        server_state.ticket_granting_ticket_lifetime,
        &tgs_req_valid,
    ) {
        Ok(time_bounds) => time_bounds,
        Err(time_bound_error) => {
            return Err(time_bound_error.to_kerberos_reply(&service_name, stime))
        }
    };

    let builder = KerberosReply::ticket_renew_builder(tgs_req_valid, time_bounds);

    builder.build(&server_state.primary_key).map_err(|kdc_err| {
        error!(?kdc_err);
        KerberosReply::error_internal(service_name, stime)
    })
}

async fn process(socket: TcpStream, info: SocketAddr, server_state: Arc<ServerState>) {
    let mut kdc_stream = Framed::new(socket, KdcTcpCodec::default());
    trace!(?info, "connection from");

    while let Some(Ok(kdc_req)) = kdc_stream.next().await {
        trace!(?kdc_req);
        match kdc_req {
            KerberosRequest::AS(auth_req) => {
                let reply = match process_authentication(&auth_req, &server_state).await {
                    Ok(rep) => rep,
                    Err(krb_err) => krb_err,
                };

                if let Err(err) = kdc_stream.send(reply).await {
                    error!(?err, "error writing response, disconnecting");
                    break;
                }
                continue;
            }
            KerberosRequest::TGS(tgs_req) => {
                let reply = match process_ticket_grant(&tgs_req, &server_state).await {
                    Ok(rep) => rep,
                    Err(krb_err) => krb_err,
                };

                if let Err(err) = kdc_stream.send(reply).await {
                    error!(?err, "error writing response, disconnecting");
                    break;
                }
                continue;
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
    Run {
        config: PathBuf,
    },
    Keytab {
        config: PathBuf,
        name: String,
        output: PathBuf,
    },
}

fn default_kvno() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
struct UserPrincipal {
    name: String,
    password: String,
    #[serde(default = "default_kvno")]
    kvno: u32,
}

#[derive(Debug, Deserialize)]
struct ServicePrincipal {
    hostname: String,
    srvname: String,
    password: String,
    #[serde(default = "default_kvno")]
    kvno: u32,
}

#[derive(Debug, Deserialize)]
struct Config {
    realm: String,
    address: SocketAddr,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    primary_key: Vec<u8>,

    user: Vec<UserPrincipal>,

    service: Vec<ServicePrincipal>,
}

impl TryFrom<Config> for ServerState {
    type Error = KrbError;

    fn try_from(cr: Config) -> Result<Self, Self::Error> {
        let Config {
            realm,
            address: _,
            primary_key,
            user,
            service,
        } = cr;

        let primary_key = KdcPrimaryKey::try_from(primary_key.as_slice())?;

        let principals = user
            .into_iter()
            .map(
                |UserPrincipal {
                     name,
                     password,
                     kvno,
                 }| {
                    let salt = format!("{}{}", realm, name);

                    let base_key =
                        DerivedKey::new_aes256_cts_hmac_sha1_96(&password, &salt, None, kvno)?;

                    let princ_name = Name::principal(&name, &realm);

                    Ok((
                        princ_name,
                        PrincipalRecord {
                            service: false,
                            base_key,
                        },
                    ))
                },
            )
            .chain(service.into_iter().map(
                |ServicePrincipal {
                     srvname,
                     hostname,
                     password,
                     kvno,
                 }| {
                    let name = format!("{srvname}/{hostname}");
                    let salt = format!("{}{}", realm, name);

                    let princ_name = Name::service(&srvname, &hostname, &realm);

                    let base_key =
                        DerivedKey::new_aes256_cts_hmac_sha1_96(&password, &salt, None, kvno)?;

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
            realm,
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

#[derive(Debug, Clone)]
struct PrincipalRecord {
    service: bool,
    base_key: DerivedKey,
}

#[derive(Debug)]
struct ServerState {
    realm: String,
    primary_key: KdcPrimaryKey,
    allowed_clock_skew: Duration,

    ticket_granting_ticket_lifetime: Duration,
    service_granting_ticket_lifetime: Duration,

    ticket_min_lifetime: Duration,
    ticket_max_renew_time: Option<Duration>,

    principals: BTreeMap<Name, PrincipalRecord>,
}

async fn main_run(config: Config) -> io::Result<()> {
    let listener = TcpListener::bind(&config.address).await?;

    info!("started krimedc on {}", config.address);

    let server_state = ServerState::try_from(config)
        .map(Arc::new)
        .map_err(|_err| std::io::Error::new(std::io::ErrorKind::InvalidInput, "data"))?;

    loop {
        let (socket, info) = listener.accept().await?;
        let state = server_state.clone();
        tokio::spawn(async move { process(socket, info, state).await });
    }
}

async fn keytab_extract_run(name: String, output: PathBuf, config: Config) -> io::Result<()> {
    use libkrime::keytab::{Keytab, KeytabEntry};

    let server_state = ServerState::try_from(config)
        .map(Arc::new)
        .map_err(|_err| std::io::Error::new(std::io::ErrorKind::InvalidInput, "data"))?;

    let principal_name = if let Some((srv, host)) = name.split_once('/') {
        Name::service(srv, host, server_state.realm.as_str())
    } else {
        Name::principal(name.as_str(), server_state.realm.as_str())
    };

    let key: DerivedKey = if principal_name.is_service_krbtgt(&server_state.realm) {
        let (k, kvno) = match server_state.primary_key {
            KdcPrimaryKey::Aes256 { k, kvno } => (k, kvno),
        };

        DerivedKey::Aes256CtsHmacSha196 {
            k,
            i: 0,
            s: String::new(),
            kvno,
        }
    } else {
        let principal_record = server_state
            .principals
            .get(&principal_name)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "no matching principal")
            })?;
        principal_record.base_key.clone()
    };

    let entry = KeytabEntry {
        principal: principal_name,
        timestamp: 0,
        key,
    };

    let ktname = "FILE:".to_owned() + output.to_string_lossy().to_string().as_str();
    let k: Keytab = if output.exists() {
        let mut keytab = libkrime::keytab::load(Some(&ktname)).map_err(|err| {
            error!(?err, "Failed to load keytab file at {}", ktname);
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "keytab")
        })?;
        keytab.push(entry);
        keytab
    } else {
        vec![entry]
    };

    libkrime::keytab::store(Some(&ktname), &k)
        .map_err(|_err| std::io::Error::new(std::io::ErrorKind::InvalidInput, "write"))?;

    Ok(())
}

fn parse_config<P: AsRef<Path>>(path: P) -> io::Result<Config> {
    let mut contents = String::new();
    let mut f = fs::File::open(&path)?;
    f.read_to_string(&mut contents)?;

    toml::from_str(&contents).map_err(|err| {
        error!(?err);
        io::Error::other("toml parse failure")
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
        Opt::Keytab {
            name,
            output,
            config,
        } => {
            let cfg = parse_config(&config)?;
            keytab_extract_run(name, output, cfg).await
        }
    }
}
