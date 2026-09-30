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

use super::CredentialCache;
use super::CredentialCacheCollection;
use super::ResolvedCredentialCache;
use crate::ccache::{CredentialV4, PrincipalV4};
use crate::error::KrbError;
use crate::proto::{KerberosCredentials, Name};

use binrw::{binread, binwrite};
use binrw::{BinReaderExt, BinWrite};
use crypto_glue::rand::{self, distr::Alphanumeric, RngExt};
use errno::Errno;
use keyutils::keytypes::user::User;
use keyutils::{Keyring, SpecialKeyring};
use keyutils_raw::{keyctl_get_keyring_id, keyctl_get_persistent};
use std::fmt::Display;
use std::time::Duration;
use tracing::{debug, error, trace};

impl From<errno::Errno> for KrbError {
    fn from(value: errno::Errno) -> Self {
        error!(errno = ?value, "kernel keyring error");
        KrbError::KeyutilsError
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Residual {
    anchor: String,
    collection: String,
    subsidiary: Option<String>,
}

impl Display for Residual {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.anchor, self.collection)?;
        if let Some(subsidiary) = self.subsidiary.as_ref() {
            write!(f, ":{}", subsidiary)?;
        }
        Ok(())
    }
}

impl Residual {
    fn parse(residual: &str) -> Result<Self, KrbError> {
        trace!(?residual, "Parsing residual");

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
#[bw(big)]
#[binread]
#[derive(Debug)]
struct TimeOffsets {
    secs: i32,
    usecs: i32,
}

fn get_subsidiary_time_offsets(keyring: &Keyring) -> Result<Option<TimeOffsets>, KrbError> {
    let key_name = "__krb5_time_offsets__";
    match keyring.search_for_key::<User, &str, Option<&mut Keyring>>(key_name, None) {
        Ok(k) => {
            let payload = k.read()?;
            let mut reader = binrw::io::Cursor::new(payload);
            let offsets: TimeOffsets = reader.read_type(binrw::Endian::Big).map_err(|err| {
                error!(error=?err);
                KrbError::BinRWError
            })?;
            Ok(Some(offsets))
        }
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::from(e)),
    }
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
            let name: Name = (&name).try_into()?;
            Ok(Some(name))
        }
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::from(e)),
    }
}

fn get_primary_subsidiary_name(collection: &mut Keyring) -> Result<Option<String>, KrbError> {
    let primary_name: &str = "krb_ccache:primary";
    match collection.search_for_key::<User, &str, Option<&mut Keyring>>(primary_name, None) {
        Ok(k) => {
            let payload = k.read()?;
            let mut reader = binrw::io::Cursor::new(payload);
            let pn: PrimaryName = reader.read_type(binrw::Endian::Big).map_err(|err| {
                error!(?collection, ?err, "Failed to read primary name");
                KrbError::BinRWError
            })?;
            let pn: String = String::from_utf8_lossy(pn.strval.as_slice()).to_string();
            Ok(Some(pn))
        }
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::from(e)),
    }
}

fn store_clock_skew(keyring: &mut Keyring, clock_skew: Duration) -> Result<(), KrbError> {
    let key_name = "__krb5_time_offsets__";
    let offsets = TimeOffsets {
        secs: clock_skew.as_secs() as i32,
        usecs: clock_skew.subsec_micros() as i32,
    };
    let mut c = std::io::Cursor::new(Vec::new());
    offsets.write(&mut c).map_err(|err| {
        error!(?offsets, ?err, "Failed to store clock skew");
        KrbError::BinRWError
    })?;
    let vec = c.into_inner();
    keyring.add_key::<User, &str, &[u8]>(key_name, vec.as_slice())?;
    Ok(())
}

fn store_principal(keyring: &mut Keyring, name: &Name) -> Result<(), KrbError> {
    let key_name = "__krb5_princ__";
    let princ: PrincipalV4 = name.try_into()?;
    let mut c = std::io::Cursor::new(Vec::new());
    princ.write(&mut c).map_err(|err| {
        error!(?keyring, ?name, ?err, "Failed to store principal");
        KrbError::BinRWError
    })?;
    let vec = c.into_inner();
    keyring.add_key::<User, &str, &[u8]>(key_name, vec.as_slice())?;
    Ok(())
}

fn store_primary_subsidiary_name(
    keyring: &mut Keyring,
    subsidiary_name: &str,
) -> Result<(), KrbError> {
    let key_name: &str = "krb_ccache:primary";
    let pn: PrimaryName = PrimaryName {
        strval: subsidiary_name.as_bytes().to_vec(),
    };
    let mut c = std::io::Cursor::new(Vec::new());
    pn.write(&mut c).map_err(|err| {
        error!(
            ?keyring,
            ?subsidiary_name,
            ?err,
            "Failed to store primary subsidiary name"
        );
        KrbError::BinRWError
    })?;
    let vec = c.into_inner();
    keyring
        .add_key::<User, &str, &[u8]>(key_name, vec.as_slice())
        .map_err(|e| {
            error!(?e, "Failed to add key");
            KrbError::from(e)
        })?;
    Ok(())
}

fn get_or_create_keyring(parent: &mut Keyring, name: &str) -> Result<Keyring, Errno> {
    match parent.search_for_keyring(name, None) {
        Ok(k) => Ok(k),
        Err(errno::Errno(libc::ENOKEY)) => parent.add_keyring(name),
        Err(e) => Err(e),
    }
    .inspect_err(|e| error!(?parent, ?name, ?e, "Failed to get or create keyring"))
}

fn get_anchor(residual: &Residual) -> Result<Keyring, KrbError> {
    match residual.anchor.as_str() {
        "process" => Keyring::attach_or_create(SpecialKeyring::Process).map_err(|e| {
            error!(?e, "Failed to attach or create process keyring");
            e.into()
        }),
        "thread" => Keyring::attach_or_create(SpecialKeyring::Thread).map_err(|e| {
            error!(?e, "Failed to attach or create thread keyring");
            e.into()
        }),
        "session" => Keyring::attach_or_create(SpecialKeyring::Session).map_err(|e| {
            error!(?e, "Failed to attach or create session keyring");
            e.into()
        }),
        "user" => Keyring::attach_or_create(SpecialKeyring::User).map_err(|e| {
            error!(?e, "Failed to attach or create user keyring");
            e.into()
        }),
        "persistent" => {
            let uid = match residual.collection.parse::<u32>() {
                Ok(uid) => uid,
                Err(e) => {
                    error!(?residual.collection, ?e, "Failed to parse collection name into uid");
                    return Err(KrbError::CredentialCacheError);
                }
            };
            // This check must be performed because new keys will be owned by the effective uid
            let euid = uzers::get_effective_uid();
            if uid != euid {
                error!(
                    ?uid,
                    ?euid,
                    "The collection name (uid) does not match the effective uid (euid)"
                );
                return Err(KrbError::CredentialCacheError);
            }
            // Must use raw calls to get the uid's persistent keyring
            let parent = keyctl_get_keyring_id(SpecialKeyring::Process.serial(), true)
                .inspect_err(|e| error!(?e, "Failed to attach or create process keyring"))?;
            let parent = keyctl_get_persistent(uid, parent)
                .inspect_err(|e| error!(?e, "Failed to attach to persistent keyring"))?;
            let parent = unsafe { Keyring::new(parent) };
            Ok(parent)
        }
        _ => Err(Errno(libc::ENOTSUP).into()),
    }
}

fn get_collection(residual: &Residual) -> Result<Keyring, KrbError> {
    let collection_name = match residual.anchor.as_str() {
        "persistent" => "_krb".to_string(),
        _ => format!("_krb_{}", residual.collection),
    };

    let mut parent = get_anchor(residual)?;
    get_or_create_keyring(&mut parent, &collection_name).map_err(|e| e.into())
}

fn get_subsidiary(residual: &Residual) -> Result<Keyring, KrbError> {
    match &residual.subsidiary {
        Some(name) => {
            let mut collection = get_collection(residual)?;
            get_or_create_keyring(&mut collection, name).map_err(|e| e.into())
        }
        None => Err(KrbError::CredentialCacheNotFound),
    }
}

struct KeyringCredentialCacheContext {
    residual: Residual,
}

impl KeyringCredentialCacheContext {
    fn store_clock_skew(&self, clock_skew: Duration) -> Result<(), KrbError> {
        let mut subsidiary = get_subsidiary(&self.residual)?;
        store_clock_skew(&mut subsidiary, clock_skew)
    }

    fn store_principal(&self, name: &Name) -> Result<(), KrbError> {
        let mut subsidiary = get_subsidiary(&self.residual)?;
        store_principal(&mut subsidiary, name)
    }

    fn time_offsets(&self) -> Result<Option<TimeOffsets>, KrbError> {
        let subsidiary = get_subsidiary(&self.residual)?;
        get_subsidiary_time_offsets(&subsidiary)
    }

    fn clear(&self) -> Result<(), KrbError> {
        let mut subsidiary = get_subsidiary(&self.residual)?;
        subsidiary.clear().map_err(|err| err.into())
    }
}

impl CredentialCache for KeyringCredentialCacheContext {
    fn cc_type(&self) -> &'static str {
        "KEYRING"
    }

    fn name(&self) -> Result<String, KrbError> {
        Ok(self.residual.to_string())
    }

    fn init(&mut self, name: &Name, clock_skew: Option<Duration>) -> Result<(), KrbError> {
        self.clear()?;

        // Store the principal name within the subsidiary cache
        self.store_principal(name)?;

        // Store clockskew within subsidiary cache
        if let Some(cs) = clock_skew {
            trace!(?cs, "Storing clock skew in subsidiary cache");
            self.store_clock_skew(cs)?;
        };

        Ok(())
    }

    fn destroy(&mut self) -> Result<(), KrbError> {
        self.clear()?;

        let mut collection = get_collection(&self.residual)?;
        let subsidiary = get_subsidiary(&self.residual)?;
        collection
            .unlink_keyring(&subsidiary)
            .inspect_err(|e| error!(?e, "Failed to unlink subsidiary from collection"))?;
        Ok(())
    }

    fn store(&mut self, credentials: &KerberosCredentials) -> Result<(), KrbError> {
        let mut subsidiary = get_subsidiary(&self.residual)?;

        // Get the SPN and use it as the key name (creds->server)
        let key_name: String = (&credentials.kdc_reply.server).into();
        let creds: CredentialV4 = CredentialV4::new(
            &credentials.name,
            &credentials.ticket,
            &credentials.kdc_reply,
        )?;
        let mut c = std::io::Cursor::new(Vec::new());
        creds.write(&mut c).map_err(|err| {
            error!(?err, "Failed to store credential");
            KrbError::BinRWError
        })?;
        let vec = c.into_inner();
        subsidiary
            .add_key::<User, &str, &[u8]>(key_name.as_str(), vec.as_slice())
            .map_err(KrbError::from)?;

        Ok(())
    }

    fn dump(&self) -> Result<(), KrbError> {
        let time_offsets = self.time_offsets()?;
        println!("KDC time offset: {:?}", time_offsets);

        let stored_name = self.principal()?;
        println!("Default principal: {:?}", stored_name);

        let subsidiary = get_subsidiary(&self.residual)?;
        let (keys, _) = subsidiary.read().map_err(|e| {
            error!(?e, "Failed to read subsidiary");
            KrbError::CredentialCacheError
        })?;

        for (i, k) in keys.iter().enumerate() {
            let Ok(desc) = k.description() else {
                continue;
            };

            if desc.description == "__krb5_time_offsets__" || desc.description == "__krb5_princ__" {
                continue;
            }

            let payload = k.read()?;
            let mut reader = binrw::io::Cursor::new(payload);
            let v4: CredentialV4 = reader.read_type(binrw::Endian::Big).map_err(|err| {
                error!(error=?err);
                KrbError::BinRWError
            })?;

            println!("Credential [{i}]:");
            println!("{}", v4);
        }
        Ok(())
    }

    fn principal(&self) -> Result<Name, KrbError> {
        let subsidiary = get_subsidiary(&self.residual)?;
        get_subsidiary_principal(&subsidiary)?.ok_or(KrbError::CredentialCacheNotFound)
    }
}

impl KeyringCredentialCacheCollection {
    fn subsidiary_exists(&self, name: &str) -> Result<Option<Keyring>, KrbError> {
        let collection = get_collection(&self.residual)?;
        match collection.search_for_keyring(name, None) {
            Ok(k) => Ok(Some(k)),
            Err(errno::Errno(libc::ENOKEY)) => Ok(None),
            Err(e) => Err(KrbError::from(e)),
        }
    }

    fn gen_random_subsidiary_name(&self) -> Result<String, KrbError> {
        let collection = get_collection(&self.residual)?;
        for _ in 1..10 {
            let s: String = rand::rng()
                .sample_iter(&Alphanumeric)
                .take(7)
                .map(char::from)
                .collect();
            let s = format!("_krb_{s}");
            let k = self.subsidiary_exists(s.as_str())?;
            if k.is_none() {
                return Ok(s);
            }
        }
        error!(?collection, "Failed to generate random cache name");
        Err(KrbError::CredentialCacheError)
    }
}

struct KeyringCredentialCacheCollection {
    pub residual: Residual,
}

impl KeyringCredentialCacheCollection {
    fn store_primary_subsidiary_name(&self, subsidiary_name: &str) -> Result<(), KrbError> {
        let mut collection = get_collection(&self.residual)?;
        store_primary_subsidiary_name(&mut collection, subsidiary_name)
    }
}

impl CredentialCacheCollection for KeyringCredentialCacheCollection {
    fn cc_type(&self) -> &'static str {
        "KEYRING"
    }

    fn name(&self) -> Result<String, KrbError> {
        self.primary()?.name()
    }

    fn primary(&self) -> Result<Box<dyn CredentialCache>, KrbError> {
        let mut collection = get_collection(&self.residual)?;

        let cc = match get_primary_subsidiary_name(&mut collection)? {
            Some(name) => {
                let residual = Residual {
                    anchor: self.residual.anchor.clone(),
                    collection: self.residual.collection.clone(),
                    subsidiary: Some(name.clone()),
                };
                KeyringCredentialCacheContext { residual }
            }
            None => {
                let new_primary_name = self.residual.collection.clone();
                let residual = Residual {
                    anchor: self.residual.anchor.clone(),
                    collection: self.residual.collection.clone(),
                    subsidiary: Some(new_primary_name.clone()),
                };
                self.store_primary_subsidiary_name(&new_primary_name)?;
                KeyringCredentialCacheContext { residual }
            }
        };

        Ok(Box::new(cc))
    }

    fn new_unique(&self) -> Result<Box<dyn CredentialCache>, KrbError> {
        let name = self.gen_random_subsidiary_name()?;
        let residual = Residual {
            anchor: self.residual.anchor.clone(),
            collection: self.residual.collection.clone(),
            subsidiary: Some(name),
        };
        let cc = KeyringCredentialCacheContext { residual };
        Ok(Box::new(cc))
    }

    fn switch(&mut self, ccache: &dyn CredentialCache) -> Result<(), KrbError> {
        let new_primary_name = ccache
            .full_name()
            .and_then(|x| Residual::parse(&x))
            .map(|x| x.subsidiary)?
            .ok_or(KrbError::CredentialCacheNotFound)?;
        self.store_primary_subsidiary_name(&new_primary_name)
    }

    fn subsidiaries(&self) -> Result<Vec<Box<dyn CredentialCache>>, KrbError> {
        let mut subsidiaries: Vec<Box<dyn CredentialCache>> = vec![];
        let collection = get_collection(&self.residual)?;
        trace!(?collection, "Resolved collection within anchor");
        let (_, keyrings) = collection.read().map_err(|e| {
            error!(?e, "Failed to read collection");
            KrbError::CredentialCacheError
        })?;
        trace!(?keyrings, "Read subsidiaries withing collection");

        for k in keyrings {
            let desc = k.description().map_err(|e| {
                error!(?e, "Failed to get keyring description");
                KrbError::CredentialCacheError
            })?;
            trace!(?k, ?desc, "Got subsidiary description");

            let cc = KeyringCredentialCacheContext {
                residual: Residual {
                    anchor: self.residual.anchor.clone(),
                    collection: self.residual.collection.clone(),
                    subsidiary: Some(desc.description.clone()),
                },
            };
            subsidiaries.push(Box::new(cc));
        }
        Ok(subsidiaries)
    }
}

pub(super) fn resolve(ccache_name: &str) -> Result<ResolvedCredentialCache, KrbError> {
    let residual = Residual::parse(ccache_name)?;
    debug!(?residual, "Parsed residual");

    let resolved = match &residual.subsidiary {
        Some(_) => {
            let cc = KeyringCredentialCacheContext { residual };
            ResolvedCredentialCache::Subsidiary(Box::new(cc))
        }
        None => {
            let cccol = KeyringCredentialCacheCollection { residual };
            ResolvedCredentialCache::Collection(Box::new(cccol))
        }
    };
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccache::tests::{klist, klist_all, skip_env};

    // Guard to cleanup the collection on drop
    struct ResidualGuard {
        residual: Residual,
    }

    impl ResidualGuard {
        fn new(residual: &Residual) -> Self {
            Self {
                residual: residual.clone(),
            }
        }
    }

    impl Drop for ResidualGuard {
        fn drop(&mut self) {
            get_anchor(&self.residual).ok().and_then(|mut anchor| {
                anchor
                    .search_for_keyring(format!("_krb_{}", self.residual.collection).as_str(), None)
                    .ok()
                    .and_then(|col| anchor.unlink_keyring(&col).ok())
            });
        }
    }

    #[tokio::test]
    async fn test_ccache_keyring_residual_parse() -> Result<(), KrbError> {
        assert!(Residual::parse("KEYRING:session").is_err());
        assert!(Residual::parse("KEYRING:session:").is_err());
        // Missing/empty anchor
        assert!(Residual::parse("KEYRING::1000").is_err());
        // Non-KEYRING prefix
        assert!(Residual::parse("FILE:/tmp/foo").is_err());
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
        // Display round-trips back to the parsed form.
        assert_eq!(residual.to_string(), "session:1000:foo");
        Ok(())
    }

    // A store into a keyring subsidiary must round-trip the principal via the
    // `__krb5_princ__` key, and clock skew via `__krb5_time_offsets__`, matching
    // MIT's keyring layout.
    #[cfg(feature = "keyring")]
    #[tokio::test]
    async fn test_ccache_keyring_princ_and_skew_roundtrip() -> Result<(), KrbError> {
        let _ = tracing_subscriber::fmt::try_init();

        let residual = Residual {
            anchor: "session".to_string(),
            collection: "krime_test_skew".to_string(),
            subsidiary: Some("s1".to_string()),
        };
        let _guard = ResidualGuard::new(&residual);

        // Guard against environments without a usable session keyring.
        let Ok(mut subsidiary) = get_subsidiary(&residual) else {
            tracing::warn!("Skipping: no usable session keyring");
            return Ok(());
        };
        subsidiary.clear().ok();

        let name = Name::Principal {
            name: "testuser".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };
        store_principal(&mut subsidiary, &name)?;
        assert_eq!(get_subsidiary_principal(&subsidiary)?, Some(name.clone()));

        store_clock_skew(&mut subsidiary, Duration::new(7, 500_000))?;
        let offsets = get_subsidiary_time_offsets(&subsidiary)?.expect("offsets");
        assert_eq!(offsets.secs, 7);
        assert_eq!(offsets.usecs, 500);

        Ok(())
    }

    #[cfg(feature = "keyring")]
    #[tokio::test]
    async fn test_ccache_keyring_roundtrip() -> Result<(), KrbError> {
        let _ = tracing_subscriber::fmt::try_init();
        if skip_env() {
            return Ok(());
        }

        let collection = "krime_test_roundtrip";
        let ccache_name = format!("KEYRING:session:{collection}");
        let residual = Residual::parse(&ccache_name)?;
        let _guard = ResidualGuard::new(&residual);

        crate::ccache::tests::store_and_verify_roundtrip(&ccache_name).await?;

        Ok(())
    }

    // End-to-end with a real TGT stored in a keyring collection, verified via
    // MIT klist.
    #[cfg(feature = "keyring")]
    #[tokio::test]
    async fn test_ccache_keyring_store_e2e() -> Result<(), KrbError> {
        let _ = tracing_subscriber::fmt::try_init();
        if skip_env() {
            return Ok(());
        }

        let collection = "krime_test_e2e";
        let ccache_name = format!("KEYRING:session:{collection}");
        let residual = Residual::parse(&ccache_name)?;
        let _guard = ResidualGuard::new(&residual);

        let Ok(resolved) = crate::ccache::resolve(Some(ccache_name.as_str())) else {
            tracing::warn!("Skipping: keyring resolve failed");
            return Ok(());
        };
        let ResolvedCredentialCache::Collection(cccol) = resolved else {
            panic!("Collection expected");
        };

        let creds = crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password").await?;
        let mut primary = cccol.primary()?;
        primary.init(&creds.name, None)?;
        primary.store(&creds)?;
        assert_eq!(primary.principal()?, creds.name);

        // dump() and subsidiaries() must succeed after a store.
        primary.dump()?;
        assert!(!cccol.subsidiaries()?.is_empty());

        let output = klist(&ccache_name);
        assert!(output.contains("testuser@EXAMPLE.COM"), "{output}");
        assert!(
            output.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
            "{output}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_ccache_keyring_primary() -> Result<(), KrbError> {
        // No subsidiary in residual
        let ccache_name = "KEYRING:session:c1";
        let residual = Residual::parse(ccache_name)?;
        let _guard = ResidualGuard::new(&residual);

        let p1 = Name::Principal {
            name: "p1".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };
        let p2 = Name::Principal {
            name: "p2".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };
        let p3 = Name::Principal {
            name: "p3".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };

        let ResolvedCredentialCache::Collection(cccol) = crate::ccache::resolve(Some(ccache_name))?
        else {
            panic!("Collection expected");
        };
        let mut col = get_collection(&Residual {
            anchor: "session".to_string(),
            collection: "c1".to_string(),
            subsidiary: None,
        })?;

        // Will set primary to collection name
        let mut primary_cc = cccol.primary()?;
        let primary = get_primary_subsidiary_name(&mut col)?.expect("No primary key");
        assert_eq!(primary, "c1");

        primary_cc.init(&p1, None)?;
        let primary = get_primary_subsidiary_name(&mut col)?.expect("No primary key");
        assert_eq!(primary, "c1");

        // Will not overwrite primary
        let mut p2_cc = cccol.new_unique()?;
        p2_cc.init(&p2, None)?;
        let primary = get_primary_subsidiary_name(&mut col)?.expect("No primary key");
        assert_eq!(primary, "c1");

        // Subsidiary specified, primary not overrided
        let ccache_name = Some("KEYRING:session:c1:p3");
        let ResolvedCredentialCache::Subsidiary(mut p3_cc) = crate::ccache::resolve(ccache_name)?
        else {
            panic!("Subsidiary expected")
        };
        p3_cc.init(&p3, None)?;
        let primary = get_primary_subsidiary_name(&mut col)?.expect("No primary key");
        assert_eq!(primary, "c1");

        // At this point, collection has 3 subsidiaries
        let ccache_name = "KEYRING:session:c1";
        let output = klist_all(ccache_name);
        assert!(output.contains("p1@EXAMPLE.COM"));
        assert!(output.contains("p2@EXAMPLE.COM"));
        assert!(output.contains("p3@EXAMPLE.COM"));

        // Destroy the primary subsidiary
        let ccache_name = "KEYRING:session:c1:c1";
        let ResolvedCredentialCache::Subsidiary(mut p1_cc) =
            crate::ccache::resolve(Some(ccache_name))?
        else {
            panic!("Subsidiary expected")
        };
        p1_cc.destroy()?;
        let ccache_name = "KEYRING:session:c1";
        let output = klist_all(ccache_name);
        assert!(!output.contains("p1@EXAMPLE.COM"));
        assert!(output.contains("p2@EXAMPLE.COM"));
        assert!(output.contains("p3@EXAMPLE.COM"));

        // But the primary key remains pointing to the deleted subsidiary
        let primary = get_primary_subsidiary_name(&mut col)?.expect("No primary key");
        assert_eq!(primary, "c1");

        // Swith the primary and destroy without specifying the subsidiary has to delete the primary.
        let ccache_name = "KEYRING:session:c1";
        let ResolvedCredentialCache::Collection(mut cccol) =
            crate::ccache::resolve(Some(ccache_name))?
        else {
            panic!("Collection expected")
        };
        let p2_cc = cccol.find(&p2)?;
        cccol.switch(&*p2_cc)?;
        let primary = get_primary_subsidiary_name(&mut col)?.expect("No primary key");
        assert!(primary != "c1");

        cccol.destroy()?;
        let output = klist_all(ccache_name);
        assert!(!output.contains("p1@EXAMPLE.COM"));
        assert!(!output.contains("p2@EXAMPLE.COM"));
        assert!(output.contains("p3@EXAMPLE.COM"));

        Ok(())
    }
}
