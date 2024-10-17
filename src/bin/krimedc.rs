use clap::{Parser, Subcommand};
use der::flagset::FlagSet;
use futures::{SinkExt, StreamExt};
use libkrime::asn1::kerberos_flags::KerberosFlags;
use libkrime::asn1::ticket_flags::TicketFlags;
use libkrime::proto::{
    AuthenticationRequest, DerivedKey, KdcPrimaryKey, KerberosReply, KerberosRequest, Name,
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
                return Ok(tkt_auth_time);
            }
            Err(diff) => {
                // From is in the future
                if auth_req.kdc_options.contains(KerberosFlags::Postdated) {
                    // TODO Define a policy for allowed postdated tickets
                    tkt_flags |= TicketFlags::Invalid;
                    return Ok(from);
                } else {
                    // TODO hardcoded clock skew
                    if diff.duration() > Duration::from_secs(300) {
                        // Beyond clock skew and no postdated requested
                        return Err(KerberosReply::error_cannot_postdate(
                            auth_req.service_name.clone(),
                            stime,
                        ));
                    }
                };
                return Ok(tkt_auth_time);
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
        tkt_start_time + Duration::from_secs(3600 * 4)
    } else {
        cmp::min(
            auth_req.until,
            tkt_start_time + Duration::from_secs(3600 * 4),
        )
    };
    // TODO hardcoded lifetime, define KDC policy for minimum life time
    let tkt_duration = tkt_end_time
        .duration_since(tkt_start_time)
        .map_err(|_| KerberosReply::error_never_valid(auth_req.service_name.clone(), stime))?;
    if tkt_duration < Duration::from_secs(3600) {
        return Err(KerberosReply::error_never_valid(
            auth_req.service_name.clone(),
            stime,
        ));
    }
    if auth_req.kdc_options.contains(KerberosFlags::RenewableOk) {
        tkt_flags |= TicketFlags::Renewable;
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
        auth_req
            .renew
            .map_or(Some(tkt_start_time + Duration::from_secs(86400 * 7)), |t| {
                Some(cmp::min(t, tkt_start_time + Duration::from_secs(86400 * 7)))
            })
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
    // TODO Enforce valid flags
    //tkt_flags &= TicketFlags::Forwardable
    //    | TicketFlags::MayPostdate
    //    | TicketFlags::Postdated
    //    | TicketFlags::Proxiable
    //    | TicketFlags::Renewable
    //    | TicketFlags::Invalid;

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
            KerberosRequest::TGS(_) => {
                error!("TGS TODO");
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

        let users = user
            .into_iter()
            .map(|UserPrincipal { name, password }| {
                let salt = format!("{}{}", realm, name);

                let base_key = DerivedKey::new_aes256_cts_hmac_sha1_96(&password, &salt).unwrap();

                (name, UserRecord { base_key })
            })
            .collect();

        let services = service
            .into_iter()
            .map(
                |ServicePrincipal {
                     srvname,
                     hostname,
                     password,
                 }| {
                    let name = format!("{srvname}/{hostname}");

                    let salt = format!("{}{}", realm, name);

                    let base_key =
                        DerivedKey::new_aes256_cts_hmac_sha1_96(&password, &salt).unwrap();

                    (name, ServiceRecord { base_key })
                },
            )
            .collect();

        ServerState {
            realm,
            primary_key,
            users,
            services,
        }
    }
}

#[derive(Debug)]
struct UserRecord {
    base_key: DerivedKey,
}

#[derive(Debug)]
struct ServiceRecord {
    base_key: DerivedKey,
}

#[derive(Debug)]
struct ServerState {
    realm: String,
    // address: SocketAddr,
    primary_key: KdcPrimaryKey,

    users: BTreeMap<String, UserRecord>,
    services: BTreeMap<String, ServiceRecord>,
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
    use binrw::BinWrite;
    use libkrime::asn1::constants::encryption_types::EncryptionType;
    use libkrime::keytab::*;
    use std::fs::File;

    let server_state = Arc::new(ServerState::from(config));

    let (key, principal) = if let Some((srv, host)) = name.split_once('/') {
        let Some(srv_record) = server_state.services.get(&name) else {
            todo!();
        };

        let principal = Principal {
            realm: Data {
                value: server_state.realm.as_bytes().to_vec(),
            },
            components: vec![
                Data {
                    value: srv.as_bytes().to_vec(),
                },
                Data {
                    value: host.as_bytes().to_vec(),
                },
            ],
            // NtSrvHst
            name_type: Some(3),
        };

        let key = Data {
            value: srv_record.base_key.k(),
        };

        (key, principal)
    } else {
        let Some(user_record) = server_state.users.get(&name) else {
            todo!();
        };

        let principal = Principal {
            realm: Data {
                value: server_state.realm.as_bytes().to_vec(),
            },
            components: vec![Data {
                value: name.as_bytes().to_vec(),
            }],
            // NtPrinc
            name_type: Some(1),
        };

        let key = Data {
            value: user_record.base_key.k(),
        };

        (key, principal)
    };

    let rdata = RecordData::Entry {
        principal,
        // I think this is NOT 2038 safe and requires a version change ...
        // indicates when the key was emitted to the keytab.
        timestamp: 0,
        // Needs to be 2, nfi why.
        key_version_u8: 2,
        enctype: EncryptionType::AES256_CTS_HMAC_SHA1_96 as _,
        key,
        // Needs to be set?
        key_version_u32: Some(2),
    };

    let record = Record {
        // Is there a way to actually calculate this with binrw?
        rlen: 409_6,
        rdata,
    };

    let kt_v2 = FileKeytabV2 {
        records: vec![record],
    };

    let kt = FileKeytab::V2(kt_v2);

    let mut f = File::create(output)?;

    let keytab = Keytab::File(kt);
    keytab.write(&mut f).unwrap();

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
