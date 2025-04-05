/*
 * The string after "KEYRING:" is called the residual and has three parts:
 * <anchor>:<collection>:<subsidiary>
 *
 * The <anchor> is the keyring to use:
 *   - process
 *   - session
 *   - user
 *   - persistent
 *
 * There can be multiple collections of credentials in the anchor.
 *
 * One <collection> can contain multiple subsidiaries. A subsidiary stores the
 * tickets for a particular principal name (e.g., TGTs for different realms or multiple
 * service tickets). Each collection has a "primary" subsidiary identified by a key
 * named krb_ccache:primary. Usually the command line tools read this key when the subsidiary
 * name was not given in the residual.
 *
 * MIT uses the collection name as the subsidiary name when it is not given, or,
 * in case of storing a ticket for other principal, it creates a random one.
 *
 * Example of a kernel keyring credential cache:
 *
 * $ KRB5CCNAME="KEYRING:session:foo" klist
 * Ticket cache: KEYRING:session:foo:krb_ccache_Hsq3H8X
 * Default principal: u2@AFOREST.AD
 *
 * Valid starting     Expires            Service principal
 * 17/01/25 13:50:38  17/01/25 23:50:38  krbtgt/AFOREST.AD@AFOREST.AD
 *         renew until 18/01/25 13:50:36
 *
 * Ticket cache: KEYRING:session:foo:foo
 * Default principal: u1@AFOREST.AD
 *
 * Valid starting     Expires            Service principal
 * 17/01/25 13:41:20  17/01/25 23:41:02  cifs/win2k25-1.aforest.ad@AFOREST.AD
 *         renew until 18/01/25 13:41:00
 * 17/01/25 13:41:02  17/01/25 23:41:02  krbtgt/AFOREST.AD@AFOREST.AD
 *         renew until 18/01/25 13:41:00
 *
 * $ keyctl show
 * Session Keyring
 *  719031901 --alswrv   1000   100  keyring: _ses
 *  541342232 --alswrv   1000   100   \_ keyring: _krb_foo
 *  557625224 --alswrv   1000   100       \_ user: krb_ccache:primary
 *  967438278 --alswrv   1000   100       \_ keyring: krb_ccache_Hsq3H8X
 *  624398775 --alswrv   1000   100       |   \_ user: __krb5_princ__
 *  217070267 --alswrv   1000   100       |   \_ user: krbtgt/AFOREST.AD@AFOREST.AD
 *  354787744 --alswrv   1000   100       |   \_ user: krb5_ccache_conf_data/pa_type/krbtgt\/AFOREST.AD\@AFOREST.AD@X-CACHECONF:
 *  764584426 --alswrv   1000   100       |   \_ user: __krb5_time_offsets__
 *  463197567 --alswrv   1000   100       \_ keyring: foo
 *  106708269 --alswrv   1000   100           \_ user: __krb5_princ__
 *  150210269 --alswrv   1000   100           \_ user: cifs/win2k25-1.aforest.ad@AFOREST.AD
 *  676215280 --alswrv   1000   100           \_ user: krbtgt/AFOREST.AD@AFOREST.AD
 * 1072460542 --alswrv   1000   100           \_ user: krb5_ccache_conf_data/pa_type/krbtgt\/AFOREST.AD\@AFOREST.AD@X-CACHECONF:
 *  999302906 --alswrv   1000   100           \_ user: __krb5_time_offsets__
 *
 * $ keyctl read 557625224
 * 11 bytes of data in key:
 * 00000001 00000003 666f6f
 *                   f o o
 *
 * $ keyctl read 106708269
 * 28 bytes of data in key:
 * 00000001 00000001 0000000a 41464f52 4553542e 41440000 00027531
 *                            A F O R  E S T .  A D          u 1
 *
 * $ keyctl read 624398775
 * 28 bytes of data in key:
 * 00000001 00000001 0000000a 41464f52 4553542e 41440000 00027532
 *                            A F O R  E S T .  A D          u 2
 */

use crate::ccache::{CredentialV4, PrincipalV4};
use crate::error::KrbError;
use crate::proto::{EncTicket, KdcReplyPart, Name};

use binrw::{binread, binwrite};
use binrw::{BinReaderExt, BinWrite};
use errno::Errno;
use keyutils::keytypes::user::User;
use keyutils::SpecialKeyring;
use keyutils::{Key, Keyring};
use libc;
use rand::{distr::Alphanumeric, Rng};
use std::time::Duration;
use tracing::error;

impl From<errno::Errno> for KrbError {
    fn from(value: errno::Errno) -> Self {
        error!(errno = ?value, "kernel keyring error");
        KrbError::KeyutilsError
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Residual {
    #[allow(dead_code)]
    anchor: String,
    #[allow(dead_code)]
    collection: String,
    #[allow(dead_code)]
    subsidiary: Option<String>,
}

impl Residual {
    fn parse(residual: &str) -> Result<Self, KrbError> {
        if !residual.starts_with("KEYRING:") {
            return Err(KrbError::UnsupportedCredentialCacheType);
        }
        let residual = residual
            .strip_prefix("KEYRING:")
            .ok_or(KrbError::UnsupportedCredentialCacheType)?;

        let (anchor, suffix) = residual
            .split_once(":")
            .ok_or(KrbError::UnsupportedCredentialCacheType)?;
        if anchor.is_empty() {
            return Err(KrbError::UnsupportedCredentialCacheType);
        }

        let (collection, suffix) = suffix.split_once(":").unwrap_or((suffix, ""));
        if collection.is_empty() {
            return Err(KrbError::UnsupportedCredentialCacheType);
        }

        let subsidiary: Option<String> = match suffix.split_once(":") {
            Some((subsidiary, _)) => Some(subsidiary.to_string()),
            None => {
                if !suffix.is_empty() {
                    Some(suffix.to_string())
                } else {
                    None
                }
            }
        };

        Ok(Residual {
            anchor: anchor.to_string(),
            collection: collection.to_string(),
            subsidiary,
        })
    }
}

#[binwrite]
#[bw(big, magic = 1u32)]
#[binread]
#[br(magic = 1u32)]
struct PrimaryName {
    #[bw(calc=strval.len() as u32)]
    #[br(temp)]
    strlen: u32,
    #[br(count=strlen)]
    strval: Vec<u8>,
}

#[binwrite]
#[bw(big, magic = 1u8)]
#[binread]
#[br(magic = 1u8)]
#[derive(Debug)]
struct TimeOffsets {
    secs: i32,
    usecs: i32,
}

/// Gets the subsidiary's principal name
///
/// This function reads the "__krb5_princ__" key in the subsidiary keyring and returns
/// the stored principal name.
fn get_subsidiary_principal(keyring: &Keyring) -> Result<Option<Name>, KrbError> {
    let key_name = "__krb5_princ__";
    match keyring.search_for_key::<User, &str, Option<&mut Keyring>>(key_name, None) {
        Ok(k) => {
            let payload = k.read()?;
            let mut reader = binrw::io::Cursor::new(payload);
            let name: PrincipalV4 = reader.read_type(binrw::Endian::Big).map_err(|err| {
                error!(error=?err);
                KrbError::BinRWError
            })?;
            let name: Name = name.try_into()?;
            Ok(Some(name))
        }
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::from(e)),
    }
}

/// Checks if a subsidiary name exists within collection.
fn subsidiary_exists(collection: &Keyring, name: &str) -> Result<Option<Keyring>, KrbError> {
    match collection.search_for_keyring(name, None) {
        Ok(k) => Ok(Some(k)),
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::from(e)),
    }
}

/// Generates a valid random subsidiary name.
fn get_random_subsidiary_name(collection: &mut Keyring) -> Result<String, KrbError> {
    for _ in 1..10 {
        let s: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        let s = format!("_krb_{}", s);
        let k = subsidiary_exists(collection, s.as_str())?;
        if k.is_none() {
            return Ok(s);
        }
    }

    error!(collection=?collection, "Failed to generate random cache name");
    Err(KrbError::CredentialCacheError)
}

/// Given a collection and a principal, get the subsidiary keyring
fn get_subsidiary_cache(
    name: &Name,
    collection: &mut Keyring,
    residual: &Residual,
) -> Result<(String, Keyring), KrbError> {
    match &residual.subsidiary {
        Some(subsidiary_name) => {
            // The subsidiary name was given in the residual
            let subsidiary_name = format!("_krb_{}", subsidiary_name);
            match subsidiary_exists(collection, subsidiary_name.as_str())? {
                Some(subsidiary) => {
                    // The subsidiary name was given in the residual and it already
                    // exists, check the stored principal matches the given one.
                    let stored_name = get_subsidiary_principal(&subsidiary)?.ok_or({
                        error!(collection=?collection, subsidiary=?subsidiary, residual=?residual, name=?name, "Subsidiary ccache has no principal");
                        KrbError::CredentialCacheError
                    })?;
                    if &stored_name == name {
                        Ok((subsidiary_name, subsidiary))
                    } else {
                        error!(collection=?collection, residual=?residual, stored_name=?stored_name, name=?name, "Stored principal do not match");
                        Err(KrbError::CredentialCacheError)
                    }
                }
                None => {
                    // The subsidiary name was given in the residual and it does not
                    // exists so create it.
                    let s = collection.add_keyring(subsidiary_name.as_str())?;
                    Ok((subsidiary_name, s))
                }
            }
        }
        None => {
            // The subsidiary name was not given in the residual
            let subsidiary_name = "_krb_default".to_string();
            match subsidiary_exists(collection, subsidiary_name.as_str())? {
                Some(subsidiary) => {
                    let stored_name = get_subsidiary_principal(&subsidiary)?.ok_or({
                        error!(collection=?collection, subsidiary=?subsidiary, residual=?residual, name=?name, "Subsidiary ccache has no principal");
                        KrbError::CredentialCacheError
                    })?;
                    if &stored_name != name {
                        // If the stored principal do not match generate a random subsidiary name
                        let subsidiary_name = get_random_subsidiary_name(collection)?;
                        let subsidiary = collection.add_keyring(subsidiary_name.as_str())?;
                        Ok((subsidiary_name, subsidiary))
                    } else {
                        Ok((subsidiary_name, subsidiary))
                    }
                }
                None => {
                    let subsidiary = collection.add_keyring(subsidiary_name.as_str())?;
                    Ok((subsidiary_name, subsidiary))
                }
            }
        }
    }
}

fn get_primary_subsidiary_name(collection: &mut Keyring) -> Result<Option<String>, KrbError> {
    let primary_name: &str = "krb_ccache:primary";
    match collection.search_for_key::<User, &str, Option<&mut Keyring>>(primary_name, None) {
        Ok(k) => {
            let payload = k.read()?;
            let mut reader = binrw::io::Cursor::new(payload);
            let pn: PrimaryName = reader.read_type(binrw::Endian::Big).map_err(|err| {
                error!(collection=?collection, error=?err, "Failed to read primary name");
                KrbError::BinRWError
            })?;
            let pn: String = String::from_utf8_lossy(pn.strval.as_slice()).to_string();
            Ok(Some(pn))
        }
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::from(e)),
    }
}

fn store_clock_skew(clock_skew: Duration, keyring: &mut Keyring) -> Result<Option<Key>, KrbError> {
    let key_name = "__krb5_time_offsets__";
    let offsets = TimeOffsets {
        secs: clock_skew.as_secs() as i32,
        usecs: clock_skew.subsec_micros() as i32,
    };
    let mut c = std::io::Cursor::new(Vec::new());
    offsets.write(&mut c).map_err(|err| {
        error!(keyring=?keyring, offsets=?offsets, error=?err, "Failed to store clock skew");
        KrbError::BinRWError
    })?;
    let vec = c.into_inner();
    let key = keyring.add_key::<User, &str, &[u8]>(key_name, vec.as_slice())?;
    Ok(Some(key))
}

fn store_credential(
    name: &Name,
    ticket: &EncTicket,
    kdc_reply_part: &KdcReplyPart,
    subsidiary: &mut Keyring,
) -> Result<(), KrbError> {
    // Get the SPN and use it as the key name (creds->server)
    let key_name: String = (&kdc_reply_part.server).into();
    let creds: CredentialV4 = CredentialV4::new(name, ticket, kdc_reply_part)?;
    let mut c = std::io::Cursor::new(Vec::new());
    creds.write(&mut c).map_err(|err| {
        error!(subsidiary=?subsidiary, name=?name,error=?err, "Failed to store credential");
        KrbError::BinRWError
    })?;
    let vec = c.into_inner();
    subsidiary
        .add_key::<User, &str, &[u8]>(key_name.as_str(), vec.as_slice())
        .map_err(KrbError::from)?;
    Ok(())
}

fn store_principal(name: &Name, subsidiary: &mut Keyring) -> Result<(), KrbError> {
    match get_subsidiary_principal(subsidiary)? {
        Some(stored) => {
            if &stored == name {
                Ok(())
            } else {
                error!(subsidiary=?subsidiary, stored_name=?stored, name=?name, "Stored principal do not match");
                Err(KrbError::CredentialCacheError)
            }
        }
        None => {
            let key_name = "__krb5_princ__";
            let princ: PrincipalV4 = name.try_into()?;
            let mut c = std::io::Cursor::new(Vec::new());
            princ.write(&mut c).map_err(|err| {
                error!(subsidiary=?subsidiary, name=?name, error=?err, "Failed to store principal");
                KrbError::BinRWError
            })?;
            let vec = c.into_inner();
            subsidiary
                .add_key::<User, &str, &[u8]>(key_name, vec.as_slice())
                .map_err(KrbError::from)?;
            Ok(())
        }
    }
}

fn store_primary_subsidiary_name(
    subsidiary_name: &str,
    collection: &mut Keyring,
) -> Result<(), KrbError> {
    let key_name: &str = "krb_ccache:primary";
    match collection.search_for_key::<User, &str, Option<&mut Keyring>>(key_name, None) {
        Ok(_) => Ok(()),
        Err(errno::Errno(libc::ENOKEY)) => {
            let pn: PrimaryName = PrimaryName {
                strval: subsidiary_name.as_bytes().to_vec(),
            };
            let mut c = std::io::Cursor::new(Vec::new());
            pn.write(&mut c).map_err(|err| {
                error!(subsidiary_name=?subsidiary_name, collection=?collection, error=?err, "Failed to store primary subsidiary name");
                KrbError::BinRWError
            })?;
            let vec = c.into_inner();
            collection
                .add_key::<User, &str, &[u8]>(key_name, vec.as_slice())
                .map_err(KrbError::from)?;
            Ok(())
        }
        Err(e) => Err(KrbError::from(e)),
    }
}

pub(crate) fn store(
    name: &Name,
    ticket: &EncTicket,
    kdc_reply_part: &KdcReplyPart,
    clock_skew: Option<Duration>,
    residual: &str,
) -> Result<(), KrbError> {
    let residual = Residual::parse(residual)?;

    // Fetch or create the keyring
    // NOTE I have seen once the session keyring revoked and further attempts
    // to attach were rejected with EKEYREVOKED (128). It was fixed running
    // `keyctl new_session`.
    let mut anchor: Keyring = match residual.anchor.as_str() {
        "process" => Keyring::attach_or_create(SpecialKeyring::Process),
        "session" => Keyring::attach_or_create(SpecialKeyring::Session),
        "user" => Keyring::attach_or_create(SpecialKeyring::User),
        _ => Err(Errno(libc::ENOTSUP)),
    }?;

    let collection_name = format!("_krb_{}", residual.collection);
    let mut collection = match anchor.search_for_keyring(collection_name.clone(), None) {
        Ok(k) => Ok(k),
        Err(errno::Errno(libc::ENOKEY)) => anchor.add_keyring(collection_name.clone()),
        Err(e) => Err(e),
    }?;

    let (subsidiary_name, mut subsidiary): (String, Keyring) =
        get_subsidiary_cache(name, &mut collection, &residual)?;

    // Store primary subsidiary name. If it already exists it is not modified.
    store_primary_subsidiary_name(subsidiary_name.as_str(), &mut collection)?;

    // Store the principal name within the subsidiary cache
    store_principal(name, &mut subsidiary)?;

    // Store the principal name within the subsidiary cache
    store_credential(name, ticket, kdc_reply_part, &mut subsidiary)?;

    // Store clockskew within subsidiary cache
    if let Some(cs) = clock_skew {
        store_clock_skew(cs, &mut subsidiary)?;
    };

    Ok(())
}

pub fn destroy(residual: &str) -> Result<(), KrbError> {
    let residual = Residual::parse(residual)?;

    let anchor: Keyring = match residual.anchor.as_str() {
        "process" => Keyring::attach_or_create(SpecialKeyring::Process),
        "session" => Keyring::attach_or_create(SpecialKeyring::Session),
        "user" => Keyring::attach_or_create(SpecialKeyring::User),
        _ => Err(Errno(libc::ENOTSUP)),
    }?;

    let collection_name = format!("_krb_{}", residual.collection);
    let mut collection = anchor.search_for_keyring(collection_name.clone(), None)?;

    // Use the given subsidiary name or read it from the collection
    let subsidiary_name = residual.subsidiary.map(Ok).unwrap_or_else(|| {
        get_primary_subsidiary_name(&mut collection)?.ok_or({
            error!(collection=?collection, "No primary subsidiary key");
            KrbError::CredentialCacheError
        })
    })?;

    // Drop the subsidiary
    match collection.search_for_keyring(subsidiary_name.clone(), None) {
        Ok(subsidiary) => collection.unlink_keyring(&subsidiary),
        Err(e) => Err(e),
    }
    .map_err(KrbError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ccache_keyring_residual_parse() -> Result<(), KrbError> {
        let residual = Residual::parse("KEYRING:session");
        assert!(residual.is_err());
        let residual = Residual::parse("KEYRING:session:");
        assert!(residual.is_err());
        let residual = Residual::parse("KEYRING:session:1000")?;
        assert_eq!(
            residual,
            Residual {
                anchor: "session".to_string(),
                collection: "1000".to_string(),
                subsidiary: None
            }
        );
        let residual = Residual::parse("KEYRING:session:1000:")?;
        assert_eq!(
            residual,
            Residual {
                anchor: "session".to_string(),
                collection: "1000".to_string(),
                subsidiary: None
            }
        );
        let residual = Residual::parse("KEYRING:session:1000:foo")?;
        assert_eq!(
            residual,
            Residual {
                anchor: "session".to_string(),
                collection: "1000".to_string(),
                subsidiary: Some("foo".to_string())
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_ccache_keyring() -> Result<(), KrbError> {
        if std::env::var("CI").is_ok() {
            // Skip this test in CI, as it requires a KDC running on localhost
            tracing::warn!("Skipping test_ccache_keyring in CI");
            return Ok(());
        }

        let (name, ticket, kdc_reply_part) =
            crate::proto::get_tgt("testuser1", "EXAMPLE.COM", "password").await?;
        super::store(
            &name,
            &ticket,
            &kdc_reply_part,
            None,
            "KEYRING:process:foo:bar",
        )?;

        // Store the same principal in the same subsidiary must succeed
        let (name, ticket, kdc_reply_part) =
            crate::proto::get_tgt("testuser1", "EXAMPLE.COM", "password").await?;
        super::store(
            &name,
            &ticket,
            &kdc_reply_part,
            None,
            "KEYRING:process:foo:bar",
        )?;

        // Store a different principal in the same subsidiary must fail
        let (name, ticket, kdc_reply_part) =
            crate::proto::get_tgt("testuser2", "EXAMPLE.COM", "password").await?;
        let r = super::store(
            &name,
            &ticket,
            &kdc_reply_part,
            None,
            "KEYRING:process:foo:bar",
        );
        assert!(r.is_err());

        // Store a different principal in a different subsidiary must succeed
        super::store(
            &name,
            &ticket,
            &kdc_reply_part,
            None,
            "KEYRING:process:foo:zap",
        )?;

        // If subsidiary not given a random one will be created
        super::store(&name, &ticket, &kdc_reply_part, None, "KEYRING:process:abc")?;

        Ok(())
    }
}
