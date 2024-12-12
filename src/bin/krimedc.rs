use clap::{Parser, Subcommand};
use der::flagset::FlagSet;
use futures::{SinkExt, StreamExt};
use libkrime::asn1::kerberos_flags::KerberosFlags;
use libkrime::asn1::ticket_flags::TicketFlags;
use libkrime::proto::{
    AuthenticationRequest, DerivedKey, KdcPrimaryKey, KerberosReply, KerberosRequest, Name,
    TicketGrantRequest, TicketGrantRequestUnverified,
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

    let mut tkt_flags = FlagSet::<TicketFlags>::new(0b0).expect("Failed to build FlagSet");

    /*
     * auth_time
     *
     * This field in the ticket indicates the time of initial authentication
     * for the named principal. It is the time of issue for the original ticket
     * on which this ticket is based. It is included in the ticket to
     * provide additional information to the end service, and to provide
     * the necessary information for implementation of a "hot list"
     * service at the KDC. An end service that is particularly paranoid
     * could refuse to accept tickets for which the initial
     * authentication occurred "too far" in the past.  This field is also
     * returned as part of the response from the KDC.  When it is
     * returned as part of the response to initial authentication
     * (KRB_AS_REP), this is the current time on the Kerberos server.  It
     * is NOT recommended that this time value be used to adjust the
     * workstation's clock, as the workstation cannot reliably determine
     * that such a KRB_AS_REP actually came from the proper KDC in a
     * timely manner.
     */
    let tkt_auth_time = stime;

    /*
     * start_time
     *
     * This field in the ticket specifies the time after which the ticket
     * is valid. Together with endtime, this field specifies the life of
     * the ticket. If the starttime field is absent from the ticket,
     * then the authtime field SHOULD be used in its place to determine
     * the life of the ticket.
     *
     * When building the AS-REP:
     * If the requested starttime is absent (from field in the AS-REQ),
     * indicates a time in the past,
     * or is within the window of acceptable clock skew for the KDC and the
     * POSTDATE option has not been specified, then the starttime of the
     * ticket is set to the authentication server's current time.
     *
     * If it indicates a time in the future beyond the acceptable clock skew, but
     * the POSTDATED option has not been specified, then the error
     * KDC_ERR_CANNOT_POSTDATE is returned.  Otherwise the requested
     * starttime is checked against the policy of the local realm (the
     * administrator might decide to prohibit certain types or ranges of
     * postdated tickets), and if the ticket's starttime is acceptable, it
     * is set as requested, and the INVALID flag is set in the new ticket.
     * The postdated ticket MUST be validated before use by presenting it to
     * the KDC after the starttime has been reached.
     */
    let tkt_start_time = auth_req.from.map_or(Ok(tkt_auth_time), |from| {
        match tkt_auth_time.duration_since(from) {
            Ok(_) => {
                // From is in the past
                Ok(tkt_auth_time)
            }
            Err(diff) => {
                // From is in the future
                if diff.duration() > server_state.allowed_clock_skew {
                    // Beyond clock skew and we refuse to post date
                    return Err(KerberosReply::error_cannot_postdate(
                        auth_req.service_name.clone(),
                        stime,
                    ));
                }
                Ok(tkt_auth_time)
            }
        }
    })?;

    /*
     * end_time
     *
     * In a ticket, this field contains the time after which the ticket will not be
     * honored (its expiration time).  Note that individual services MAY
     * place their own limits on the life of a ticket and MAY reject
     * tickets which have not yet expired.  As such, this is really an
     * upper bound on the expiration time for the ticket.
     *
     * In the AS-REQ, this field contains the expiration date requested by the client in
     * a ticket request.  It is not optional, but if the requested
     * endtime is "19700101000000Z", the requested ticket is to have the
     * maximum endtime permitted according to KDC policy.  Implementation
     * note: This special timestamp corresponds to a UNIX time_t value of
     * zero on most systems.
     *
     * When building the AS-REP:
     * The expiration time of the ticket will be set to the earlier of the
     * requested endtime and a time determined by local policy, possibly by
     * using realm- or principal-specific factors.  For example, the
     * expiration time MAY be set to the earliest of the following:
     * - The expiration time (endtime) requested in the KRB_AS_REQ message.
     * - The ticket's starttime plus the maximum allowable lifetime
     *   associated with the client principal from the authentication
     *   server's database.
     * - The ticket's starttime plus the maximum allowable lifetime
     *   associated with the server principal.
     * - The ticket's starttime plus the maximum lifetime set by the policy
     *   of the local realm.
     *
     * If the requested expiration time minus the starttime (as determined
     * above) is less than a site-determined minimum lifetime, an error
     * message with code KDC_ERR_NEVER_VALID is returned.  If the requested
     * expiration time for the ticket exceeds what was determined as above,
     * and if the 'RENEWABLE-OK' option was requested, then the 'RENEWABLE'
     * flag is set in the new ticket, and the renew-till value is set as if
     * the 'RENEWABLE' option were requested (the field and option names are
     * described fully in Section 5.4.1).
     */
    // TODO hardcoded lifetime, define KDC policy for default ticket lifetime
    let tkt_end_time = if auth_req.until == SystemTime::UNIX_EPOCH {
        tkt_start_time + server_state.ticket_lifetime
    } else {
        cmp::min(
            auth_req.until,
            tkt_start_time + server_state.ticket_lifetime,
        )
    };

    let tkt_duration = tkt_end_time
        .duration_since(tkt_start_time)
        .map_err(|_| KerberosReply::error_never_valid(auth_req.service_name.clone(), stime))?;

    if tkt_duration < server_state.ticket_min_lifetime {
        return Err(KerberosReply::error_never_valid(
            auth_req.service_name.clone(),
            stime,
        ));
    }

    /*
     * renew-till
     *
     * This field is the requested renew-till time sent from a client to
     * the KDC in a ticket request. It is optional.
     *
     * In a ticket, this field is only present in tickets that have the RENEWABLE flag
     * set in the flags field. It indicates the maximum endtime that may
     * be included in a renewal. It can be thought of as the absolute
     * expiration time for the ticket, including all renewals.
     *
     * When building the AS-REP:
     * If the RENEWABLE option has been requested or if the RENEWABLE-OK
     * option has been set and a renewable ticket is to be issued, then the
     * renew-till field MAY be set to the earliest of:
     *
     * - Its requested value.
     * - The starttime of the ticket plus the minimum of the two maximum
     *   renewable lifetimes associated with the principals' database
     *   entries.
     * - The starttime of the ticket plus the maximum renewable lifetime
     *   set by the policy of the local realm.
     */
    let tkt_renew_until = if auth_req.kdc_options.contains(KerberosFlags::RenewableOk)
        || auth_req.kdc_options.contains(KerberosFlags::Renewable)
    {
        tkt_flags |= TicketFlags::Renewable;
        // TODO hardcoded lifetime, create a kdc policy for default renew time
        auth_req.renew.map_or(
            Some(tkt_start_time + server_state.ticket_max_renew_time),
            |t| {
                Some(cmp::min(
                    t,
                    tkt_start_time + server_state.ticket_max_renew_time,
                ))
            },
        )
    } else {
        tkt_flags.retain(|f| f != TicketFlags::Renewable);
        None
    };

    /*
     * The flags field of the new ticket will have the following options set
     * if they have been requested and if the policy of the local realm
     * allows:  FORWARDABLE, MAY-POSTDATE, POSTDATED, PROXIABLE, RENEWABLE.
     * If the new ticket is postdated (the starttime is in the future), its
     * INVALID flag will also be set.
     */

    // We should not bother with forwarded/proxiable until there is a genuine
    // need for them.

    let builder = KerberosReply::authentication_builder(
        auth_req.client_name,
        Name::service_krbtgt(server_state.realm.as_str()),
        tkt_auth_time,
        tkt_start_time,
        tkt_end_time,
        tkt_renew_until,
        auth_req.nonce,
        tkt_flags,
    );

    builder
        .build(&principal_record.base_key, &server_state.primary_key)
        .map_err(|kdc_err| {
            error!(?kdc_err);
            KerberosReply::error_internal(auth_req.service_name.clone(), stime)
        })
}

#[instrument(level = "trace", skip_all)]
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
        // This is a renewal request.
        return process_ticket_renewal(tgs_req_valid, server_state).await;
    }

    let stime = SystemTime::now();

    // Is the service in our db?
    let Some(service_record) = server_state.principals.get(&service_name) else {
        error!(?service_name, "Unable to find service name");
        return Err(KerberosReply::error_service_name(service_name, stime));
    };

    let client_tgt = tgs_req_valid.ticket_granting_ticket();

    let start_time = if let Some(requested_start_time) = tgs_req_valid.requested_start_time() {
        if requested_start_time < client_tgt.start_time() {
            todo!();
        }

        if requested_start_time > client_tgt.end_time() {
            todo!();
        }

        // It's within valid bounds, lets go.

        *requested_start_time
    } else {
        // Start from *now*.
        stime
    };

    let requested_end_time = tgs_req_valid.requested_end_time();
    // Can't be past the tgt end.
    if requested_end_time > client_tgt.end_time() {
        todo!();
    }

    // Some clients send a 0 for the requested end - fill it in with the tgt end time instead.
    let end_time = if *requested_end_time == SystemTime::UNIX_EPOCH {
        // It's 0, just return our tgt end time instead.
        *client_tgt.end_time()
    } else if requested_end_time < &start_time {
        tracing::warn!(?requested_end_time, ?start_time);
        // Mask with the tgt end.
        *client_tgt.end_time()
    } else if requested_end_time > client_tgt.end_time() {
        // Clamp to tgt end time
        *client_tgt.end_time()
    } else {
        *requested_end_time
    };

    let renew_until = match (
        tgs_req_valid.requested_renew_until(),
        client_tgt.renew_until(),
    ) {
        (Some(requested_renew_until), Some(ticket_renew_until)) => {
            if requested_renew_until > ticket_renew_until {
                todo!();
            }

            Some(*requested_renew_until)
        }
        (Some(_), None) => {
            todo!();
        }
        (_, _) => None,
    };

    let tkt_flags = FlagSet::<TicketFlags>::new(0b0).expect("Failed to build FlagSet");

    let builder = KerberosReply::ticket_grant_builder(
        tgs_req_valid,
        tkt_flags,
        start_time,
        end_time,
        renew_until,
    );

    builder.build(&service_record.base_key).map_err(|kdc_err| {
        error!(?kdc_err);
        KerberosReply::error_internal(service_name, stime)
    })
}

#[instrument(level = "trace", skip_all)]
async fn process_ticket_renewal(
    tgs_req_valid: TicketGrantRequest,
    server_state: &ServerState,
) -> Result<KerberosReply, KerberosReply> {
    let stime = SystemTime::now();

    let client_tgt = tgs_req_valid.ticket_granting_ticket();

    let start_time = if let Some(requested_start_time) = tgs_req_valid.requested_start_time() {
        if requested_start_time < client_tgt.start_time() {
            todo!();
        }

        if requested_start_time > client_tgt.end_time() {
            todo!();
        }

        // It's within valid bounds, lets go.

        *requested_start_time
    } else {
        // Start from *now*.
        stime
    };

    let requested_end_time = tgs_req_valid.requested_end_time();
    // Can't be past the tgt end.
    if requested_end_time > client_tgt.end_time() {
        todo!();
    }

    // Some clients send a 0 for the requested end - fill it in with the tgt end time instead.
    let end_time = if *requested_end_time == SystemTime::UNIX_EPOCH {
        // It's 0, just return our tgt end time instead.
        *client_tgt.end_time()
    } else if requested_end_time < &start_time {
        tracing::warn!(?requested_end_time, ?start_time);
        // Mask with the tgt end.
        *client_tgt.end_time()
    } else if requested_end_time > client_tgt.end_time() {
        // Clamp to tgt end time
        *client_tgt.end_time()
    } else {
        *requested_end_time
    };

    let renew_until = match (
        tgs_req_valid.requested_renew_until(),
        client_tgt.renew_until(),
    ) {
        (Some(requested_renew_until), Some(ticket_renew_until)) => {
            if requested_renew_until > ticket_renew_until {
                todo!();
            }

            Some(*requested_renew_until)
        }
        (Some(_), None) => {
            todo!();
        }
        (_, _) => None,
    };

    let tkt_flags = FlagSet::<TicketFlags>::new(0b0).expect("Failed to build FlagSet");

    let service_name = tgs_req_valid.service_name().clone();

    let builder =
        KerberosReply::ticket_renew_builder(tgs_req_valid, start_time, end_time, renew_until);

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

        let ticket_lifetime = Duration::from_secs(3600 * 4);

        let ticket_min_lifetime = Duration::from_secs(60);

        let ticket_max_renew_time = Duration::from_secs(86400);

        ServerState {
            realm,
            primary_key,
            principals,
            allowed_clock_skew,
            ticket_min_lifetime,
            ticket_max_renew_time,
            ticket_lifetime,
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
    // address: SocketAddr,
    primary_key: KdcPrimaryKey,
    allowed_clock_skew: Duration,

    ticket_lifetime: Duration,
    ticket_min_lifetime: Duration,
    ticket_max_renew_time: Duration,

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
