use clap::{Parser, Subcommand};
use futures::{SinkExt, StreamExt};
use libkrime::asn1::ticket_flags::TicketFlags;
use libkrime::proto::{
    AuthenticationRequest, AuthenticationTimeBound, DerivedKey, KdcPrimaryKey, KerberosReply,
    KerberosRequest, Name, TicketGrantRequest, TicketGrantRequestUnverified, TicketGrantTimeBound,
};
use libkrime::KdcTcpCodec;
use serde::Deserialize;
use std::cmp;
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
use tracing::{debug, error, info, instrument, trace, warn};

#[instrument(level = "info", skip_all)]
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
        error!("Request not for KRBTGT");
        return Err(KerberosReply::error_as_not_krbtgt(
            auth_req.service_name,
            stime,
        ));
    }

    // Is the client for our realm?
    // Is the client in our user db?
    // This look up answer both as the client_name contains realm given how we structure
    // the name enum
    let Some(principal_record) = server_state.principals.get(&auth_req.client_name) else {
        return Err(KerberosReply::error_client_username(
            auth_req.service_name,
            stime,
        ));
    };

    // Now, if the req is a user princ or a service princ we have to take different paths.
    // This is because user princs demand pre-auth, but service ones don't. Service princs
    // are required to have stronger keys which is why they are exempted.

    if !principal_record.service {
        let Some(pre_enc_timestamp) = auth_req.preauth.enc_timestamp() else {
            info!("ENC-TS Preauth not present, returning pre-auth parameters.");
            let parep = KerberosReply::preauth_builder(auth_req.service_name, stime)
                .set_key_params(&principal_record.base_key)
                .build();

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
        &auth_req,
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
        auth_req.client_name,
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
    tgs_req: TicketGrantRequestUnverified,
    server_state: &ServerState,
) -> Result<KerberosReply, KerberosReply> {
    let tgs_req_valid = tgs_req
        .validate(&server_state.primary_key, &server_state.realm)
        .unwrap();

    trace!(?tgs_req_valid);

    let service_name = tgs_req_valid.service_name().clone().service_hst_normalise();

    trace!(?service_name);

    if service_name.is_service_krbtgt(server_state.realm.as_str()) {
        // This is a renewal request for the users TGT
        return process_ticket_renewal(tgs_req_valid, server_state).await;
    }

    let stime = SystemTime::now();

    // Is the service in our db?
    let Some(service_record) = server_state.principals.get(&service_name) else {
        error!(?service_name, "Unable to find service name");
        return Err(KerberosReply::error_service_name(service_name, stime));
    };

    // IMPORTANT - ticket grants aren't and can't be renewed.
    // https://k5wiki.kerberos.org/wiki/TGS_Requests
    // """
    // For the purposes of this article, a TGS request is considered "normal" if it:
    // * does not have any of the forwarded, proxy, renew, validate, enc-tkt-in-skey, or cname-in-addl-tkt options
    // """

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

    if !tgs_req_valid
        .ticket_flags()
        .contains(TicketFlags::Renewable)
    {
        warn!("Denying renewal of ticket that is not renewable.");

        return Err(KerberosReply::error_renew_denied(service_name, stime));
    }

    let client_tgt = tgs_req_valid.ticket_granting_ticket();

    // We currently default the renew until here to the client tgt, but in
    // future we may be able to make server aware choices to clamp this during
    // the renewal to expire sessions of bad actors.
    let Some(renew_until) = client_tgt.renew_until() else {
        warn!("Denying renewal of ticket that has no renew time.");

        return Err(KerberosReply::error_renew_denied(service_name, stime));
    };

    // Maximal end time for this tgt renewal. Normally clamps to the tgt max life
    let bound_end_time = cmp::min(
        stime + server_state.ticket_granting_ticket_lifetime,
        renew_until,
    );

    let start_time = if let Some(requested_start_time) = tgs_req_valid.requested_start_time() {
        if requested_start_time < stime {
            todo!();
        }

        if requested_start_time > bound_end_time {
            todo!();
        }

        // It's within valid bounds, lets go.

        requested_start_time
    } else {
        // Start from *now*.
        stime
    };

    let end_time = cmp::min(bound_end_time, tgs_req_valid.requested_end_time());

    // Since we're renewing, we need to treat this a bit differently to a tgs req
    let renew_until = match tgs_req_valid.requested_renew_until() {
        Some(requested_renew_until) => {
            // Take the smaller of the values.
            cmp::min(requested_renew_until, renew_until)
        }
        None => renew_until,
    };

    let builder =
        KerberosReply::ticket_renew_builder(tgs_req_valid, start_time, end_time, Some(renew_until));

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
            KerberosRequest::TGS(tgs_req) => {
                let reply = match process_ticket_grant(tgs_req, &server_state).await {
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

#[derive(Debug, Deserialize)]
struct UserPrincipal {
    name: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct ServicePrincipal {
    hostname: String,
    srvname: String,
    password: String,
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

impl From<Config> for ServerState {
    fn from(cr: Config) -> ServerState {
        let Config {
            realm,
            address: _,
            primary_key,
            user,
            service,
        } = cr;

        let primary_key = KdcPrimaryKey::try_from(primary_key.as_slice()).unwrap();

        let principals = user
            .into_iter()
            .map(|UserPrincipal { name, password }| {
                let salt = format!("{}{}", realm, name);

                let base_key = DerivedKey::new_aes256_cts_hmac_sha1_96(&password, &salt).unwrap();

                let princ_name = Name::principal(&name, &realm);

                (
                    princ_name,
                    PrincipalRecord {
                        service: false,
                        base_key,
                    },
                )
            })
            .chain(service.into_iter().map(
                |ServicePrincipal {
                     srvname,
                     hostname,
                     password,
                 }| {
                    let name = format!("{srvname}/{hostname}");
                    let salt = format!("{}{}", realm, name);

                    let princ_name = Name::service(&srvname, &hostname, &realm);

                    let base_key =
                        DerivedKey::new_aes256_cts_hmac_sha1_96(&password, &salt).unwrap();

                    (
                        princ_name,
                        PrincipalRecord {
                            service: true,
                            base_key,
                        },
                    )
                },
            ))
            .collect();

        let allowed_clock_skew = Duration::from_secs(300);

        let ticket_granting_ticket_lifetime = Duration::from_secs(1800);
        let service_granting_ticket_lifetime = Duration::from_secs(300);

        let ticket_min_lifetime = Duration::from_secs(60);

        let ticket_max_renew_time = Some(Duration::from_secs(86400 * 7));

        ServerState {
            realm,
            primary_key,
            principals,
            allowed_clock_skew,
            ticket_min_lifetime,
            ticket_max_renew_time,

            ticket_granting_ticket_lifetime,
            service_granting_ticket_lifetime,
        }
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

    let server_state = Arc::new(ServerState::from(config));

    loop {
        let (socket, info) = listener.accept().await?;
        let state = server_state.clone();
        tokio::spawn(async move { process(socket, info, state).await });
    }
}

async fn keytab_extract_run(name: String, output: PathBuf, config: Config) -> io::Result<()> {
    use libkrime::keytab::*;
    use std::fs::File;

    let server_state = Arc::new(ServerState::from(config));

    let principal_name = if let Some((srv, host)) = name.split_once('/') {
        Name::service(srv, host, server_state.realm.as_str())
    } else {
        Name::principal(name.as_str(), server_state.realm.as_str())
    };

    let Some(principal_record) = server_state.principals.get(&principal_name) else {
        todo!();
    };

    let key = principal_record.base_key.clone();

    let entry = KeytabEntry {
        principal: principal_name.into(),
        timestamp: 0,
        key,
        kvno: 0,
    };

    let kt = Keytab::File(vec![entry]);
    let mut f = File::create(output)?;
    kt.write(&mut f).unwrap();

    Ok(())
}

fn parse_config<P: AsRef<Path>>(path: P) -> io::Result<Config> {
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
