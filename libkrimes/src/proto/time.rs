use crate::asn1::kerberos_flags::KerberosFlags;
use crate::asn1::ticket_flags::TicketFlags;
use crate::proto::reply::KerberosReply;
use crate::proto::{AuthenticationRequest, Name, TicketGrantRequest};
use std::cmp;
use std::time::{Duration, SystemTime};

use tracing::{trace, warn};

pub enum TimeBoundError {
    Skew,
    NeverValid,
    FlagsInconsistent,
    RenewalNotAllowed,
}

impl TimeBoundError {
    pub fn to_kerberos_reply(
        &self,
        service_name: &Name,
        current_time: SystemTime,
    ) -> KerberosReply {
        match self {
            TimeBoundError::Skew => {
                KerberosReply::error_clock_skew(service_name.clone(), current_time)
            }
            TimeBoundError::NeverValid => {
                KerberosReply::error_never_valid(service_name.clone(), current_time)
            }
            TimeBoundError::FlagsInconsistent => {
                KerberosReply::error_request_invalid(service_name.clone(), current_time)
            }
            TimeBoundError::RenewalNotAllowed => {
                KerberosReply::error_renew_denied(service_name.clone(), current_time)
            }
        }
    }
}

pub struct AuthenticationTimeBound {
    auth_time: SystemTime,
    start_time: SystemTime,
    end_time: SystemTime,
    renew_until: Option<SystemTime>,
}

impl AuthenticationTimeBound {
    pub fn auth_time(&self) -> SystemTime {
        self.auth_time
    }

    pub fn start_time(&self) -> SystemTime {
        self.start_time
    }

    pub fn end_time(&self) -> SystemTime {
        self.end_time
    }

    pub fn renew_until(&self) -> Option<SystemTime> {
        self.renew_until
    }

    pub fn from_as_req(
        current_time: SystemTime,
        maximum_clock_skew: Duration,
        minimum_ticket_lifetime: Duration,
        default_ticket_lifetime: Duration,
        maximum_ticket_lifetime: Duration,
        maximum_renew_lifetime: Option<Duration>,
        auth_req: &AuthenticationRequest,
    ) -> Result<AuthenticationTimeBound, TimeBoundError> {
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

        let auth_time = current_time;

        let start_time = as_req_start_time(current_time, maximum_clock_skew, auth_req.from)?;

        let end_time = as_req_end_time(
            minimum_ticket_lifetime,
            default_ticket_lifetime,
            maximum_ticket_lifetime,
            start_time,
            auth_req.until,
        )?;

        let renew_until = as_req_renew_until(
            start_time,
            end_time,
            auth_req.renew,
            maximum_renew_lifetime,
            auth_req.kdc_options,
        )?;

        Ok(AuthenticationTimeBound {
            auth_time,
            start_time,
            end_time,
            renew_until,
        })
    }
}

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
fn as_req_start_time(
    current_time: SystemTime,
    maximum_clock_skew: Duration,
    start_time: Option<SystemTime>,
) -> Result<SystemTime, TimeBoundError> {
    let Some(requested_start_time) = start_time else {
        trace!("No requested start time, using current time");
        return Ok(current_time);
    };

    if is_within_allowed_skew(current_time, requested_start_time, maximum_clock_skew) {
        Ok(requested_start_time)
    } else {
        Err(TimeBoundError::Skew)
    }
}

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
fn as_req_end_time(
    minimum_ticket_lifetime: Duration,
    default_ticket_lifetime: Duration,
    maximum_ticket_lifetime: Duration,
    start_time: SystemTime,
    requested_end_time: SystemTime,
) -> Result<SystemTime, TimeBoundError> {
    if requested_end_time == SystemTime::UNIX_EPOCH {
        trace!("Endtime set to unix epoch, granting default ticket lifetime.");
        return Ok(start_time + default_ticket_lifetime);
    }

    match requested_end_time.duration_since(start_time) {
        // The end time is greater or equal to start time.
        Ok(diff) => {
            // Diff is the number of seconds between end to start
            // time - it is the number of seconds of ticket life
            // that has been requested.

            // The end time is the greater of the requested time
            // or the minimum time. This is the "lower" bound.
            let tkt_req_time = cmp::max(diff, minimum_ticket_lifetime);

            // The end time is the lesser of the lower/requested
            // time and the "maximum". This is the "upper" bound.
            let tkt_req_time = cmp::min(tkt_req_time, maximum_ticket_lifetime);

            Ok(start_time + tkt_req_time)
        }
        // The end time is less than the start time.
        Err(_) => Err(TimeBoundError::NeverValid),
    }
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
fn as_req_renew_until(
    start_time: SystemTime,
    end_time: SystemTime,
    requested_renew_until: Option<SystemTime>,
    maximum_renew_lifetime: Option<Duration>,
    kdc_options: KerberosFlags,
) -> Result<Option<SystemTime>, TimeBoundError> {
    let renewal_flags_set = kdc_options.contains(KerberosFlags::RenewableOk)
        || kdc_options.contains(KerberosFlags::Renewable);

    match (
        requested_renew_until,
        maximum_renew_lifetime,
        renewal_flags_set,
    ) {
        (Some(_), _, false) => {
            // Requested a renew until but no flags!
            Err(TimeBoundError::FlagsInconsistent)
        }
        (_, None, _) => {
            // Requested a renew, but it's denied
            Err(TimeBoundError::RenewalNotAllowed)
        }
        (None, Some(maximum_renew_lifetime), _) => {
            // Easy, just default to our renew lifetime.
            Ok(Some(start_time + maximum_renew_lifetime))
        }
        (Some(requested_renew_until), Some(maximum_renew_lifetime), _) => {
            // This is the hard path, we have to validate things.

            if requested_renew_until < end_time {
                // The renewal would never be valid.
                return Err(TimeBoundError::NeverValid);
            }

            // Take the smaller of requested renew until and the maximum window.
            Ok(Some(cmp::min(
                requested_renew_until,
                start_time + maximum_renew_lifetime,
            )))
        }
    }
}

fn is_within_allowed_skew(
    reference_time: SystemTime,
    requested_time: SystemTime,
    maximum_clock_skew: Duration,
) -> bool {
    match reference_time.duration_since(requested_time) {
        // The requested time is equal to or earlier than reference_time
        Ok(diff) => {
            // Difference must be less than maximum clock skew
            diff <= maximum_clock_skew
        }
        // The requested time is greater than the reference time
        Err(diff) => {
            // Difference must be less than maximum clock skew
            diff.duration() <= maximum_clock_skew
        }
    }
}

pub struct TicketGrantTimeBound {
    start_time: SystemTime,
    end_time: SystemTime,
    renew_until: Option<SystemTime>,
}

impl TicketGrantTimeBound {
    pub fn start_time(&self) -> SystemTime {
        self.start_time
    }

    pub fn end_time(&self) -> SystemTime {
        self.end_time
    }

    pub fn renew_until(&self) -> Option<SystemTime> {
        self.renew_until
    }

    pub fn from_tgs_req(
        current_time: SystemTime,
        maximum_clock_skew: Duration,
        maximum_service_ticket_lifetime: Duration,
        tgs_req_valid: &TicketGrantRequest,
    ) -> Result<TicketGrantTimeBound, TimeBoundError> {
        let client_tgt = tgs_req_valid.ticket_granting_ticket();

        // Ensure that current_time is at least equal or greater
        // than the tgt auth_time (when it was issued). This checks
        // for clock step backs.

        let current_time = cmp::max(current_time, client_tgt.auth_time());

        // Due to the authentication checks above, we can assert that:
        // tgt_start_time < tgt_end_time < tgt_renew_until

        let start_time = tgs_req_start_time(
            current_time,
            tgs_req_valid.requested_start_time(),
            maximum_clock_skew,
            client_tgt.start_time(),
            client_tgt.end_time(),
        )?;

        let end_time = tgs_req_end_time(
            start_time,
            tgs_req_valid.requested_end_time(),
            client_tgt.end_time(),
            client_tgt.renew_until(),
            maximum_service_ticket_lifetime,
        )?;

        // Pretty much nothing handles tgs renewals in a sane way, so we have to make this None.
        let renew_until = None;

        Ok(TicketGrantTimeBound {
            start_time,
            end_time,
            renew_until,
        })
    }
}

fn tgs_req_start_time(
    current_time: SystemTime,
    requested_start_time: Option<SystemTime>,
    maximum_clock_skew: Duration,
    client_tgt_start_time: SystemTime,
    client_tgt_end_time: SystemTime,
) -> Result<SystemTime, TimeBoundError> {
    // No requested start time, set to now.
    let requested_start_time = requested_start_time.unwrap_or(current_time);

    let requested_start_time = if requested_start_time == SystemTime::UNIX_EPOCH {
        current_time
    } else {
        requested_start_time
    };

    // The requested start time can't be *less* than the tgt start time.
    let requested_start_time = cmp::min(requested_start_time, client_tgt_start_time);

    // The requested start time needs to be "near" the current time at least.
    if !is_within_allowed_skew(current_time, requested_start_time, maximum_clock_skew) {
        return Err(TimeBoundError::Skew);
    }

    // The requested start_time *must not* exceed the end time.
    if requested_start_time > client_tgt_end_time {
        return Err(TimeBoundError::NeverValid);
    }

    Ok(requested_start_time)
}

fn tgs_req_end_time(
    start_time: SystemTime,
    requested_end_time: SystemTime,
    client_tgt_end_time: SystemTime,
    client_tgt_renew_until: Option<SystemTime>,
    maximum_service_ticket_lifetime: Duration,
) -> Result<SystemTime, TimeBoundError> {
    // Clamp the end time to the maximum allowable.
    let requested_end_time = match requested_end_time.duration_since(start_time) {
        Ok(diff) => {
            if diff > maximum_service_ticket_lifetime {
                // Clamp to the maximum lifetime.
                start_time + maximum_service_ticket_lifetime
            } else {
                // It's less than, so this time is valid.
                requested_end_time
            }
        }
        // Some clients send epoch to mean "just fuck my shit up fam", so
        // we set a reasonable default here.
        Err(_) if requested_end_time == SystemTime::UNIX_EPOCH => {
            start_time + maximum_service_ticket_lifetime
        }
        // The end time was less than start time.
        Err(_) => return Err(TimeBoundError::NeverValid),
    };

    // We bound to either the renew time if present, or the tgt_end time.
    let clamp_bound = client_tgt_renew_until.unwrap_or(client_tgt_end_time);

    let requested_end_time = cmp::min(requested_end_time, clamp_bound);

    Ok(requested_end_time)
}

pub struct TicketRenewTimeBound {
    start_time: SystemTime,
    end_time: SystemTime,
    renew_until: SystemTime,
}

impl TicketRenewTimeBound {
    pub fn start_time(&self) -> SystemTime {
        self.start_time
    }

    pub fn end_time(&self) -> SystemTime {
        self.end_time
    }

    pub fn renew_until(&self) -> SystemTime {
        self.renew_until
    }

    pub fn from_tgs_req(
        current_time: SystemTime,
        maximum_clock_skew: Duration,
        maximum_ticket_lifetime: Duration,
        tgs_req_valid: &TicketGrantRequest,
    ) -> Result<TicketRenewTimeBound, TimeBoundError> {
        if !tgs_req_valid
            .ticket_flags()
            .contains(TicketFlags::Renewable)
        {
            warn!("Denying renewal of ticket that is not renewable.");
            return Err(TimeBoundError::RenewalNotAllowed);
        }

        let client_tgt = tgs_req_valid.ticket_granting_ticket();

        // We currently default the renew until here to the client tgt, but in
        // future we may be able to make server aware choices to clamp this during
        // the renewal to expire sessions of bad actors.
        let Some(renew_until) = client_tgt.renew_until() else {
            warn!("Denying renewal of ticket that has no renew time.");

            return Err(TimeBoundError::RenewalNotAllowed);
        };

        let start_time = tgs_req_start_time(
            current_time,
            tgs_req_valid.requested_start_time(),
            maximum_clock_skew,
            client_tgt.start_time(),
            client_tgt.end_time(),
        )?;

        let end_time = tgs_req_end_time(
            start_time,
            tgs_req_valid.requested_end_time(),
            client_tgt.end_time(),
            client_tgt.renew_until(),
            maximum_ticket_lifetime,
        )?;

        Ok(TicketRenewTimeBound {
            start_time,
            end_time,
            renew_until,
        })
    }
}
