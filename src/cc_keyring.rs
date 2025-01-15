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
use rand::{distributions::Alphanumeric, Rng};
use std::time::Duration;

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
#[bw(big, magic = 1u8)]
#[binread]
#[br(magic = 1u8)]
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
struct TimeOffsets {
    secs: i32,
    usecs: i32,
}

fn get_subsidiary_principal(keyring: &Keyring) -> Result<Option<Name>, KrbError> {
    let key_name = "__krb5_princ__";
    match keyring.search_for_key::<User, &str, Option<&mut Keyring>>(key_name, None) {
        Ok(k) => {
            let payload = k.read().map_err(|e| KrbError::KeyutilsError(e))?;
            let mut reader = binrw::io::Cursor::new(payload);
            let stored: PrincipalV4 = reader
                .read_type(binrw::Endian::Big)
                .map_err(|e| KrbError::BinRWError(e))?;
            let stored: Name = stored.try_into()?;
            Ok(Some(stored))
        }
        Err(errno::Errno(libc::ENOKEY)) => Ok(None),
        Err(e) => Err(KrbError::KeyutilsError(e)),
    }
}

fn get_random_subsidiary(collection: &mut Keyring) -> Result<(String, Keyring), KrbError> {
    for _ in 1..10 {
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        let s = format!("_krb_{}", s);
        match collection.search_for_keyring(s.clone(), None) {
            Ok(_) => continue,
            Err(errno::Errno(libc::ENOKEY)) => {
                let k = collection
                    .add_keyring(s.clone())
                    .map_err(|e| KrbError::KeyutilsError(e))?;
                return Ok((s, k));
            }
            Err(e) => return Err(KrbError::KeyutilsError(e)),
        }
    }
    return Err(KrbError::CredentialCacheCannotCreate(
        "Failed to generate random cache name".to_string(),
    ));
}

fn get_subsidiary_cache(
    name: &Name,
    collection: &mut Keyring,
    residual: Option<String>,
) -> Result<(String, Keyring), KrbError> {
    // If subsidiary name was not given in the residual string, use the collection name
    let subsidiary_name = match residual {
        Some(ref r) => format!("_krb_{}", r),
        None => format!("_krb_default"),
    };

    // Create the subsidiary cache
    let (n, c) = match collection.search_for_keyring(subsidiary_name.clone(), None) {
        Ok(k) => {
            // If the stored principal do not match, or no principal stored, random name
            // unless subsidiary name was forced
            let stored = get_subsidiary_principal(&collection)?.unwrap();
            if &stored != name {
                if residual.is_none() {
                    get_random_subsidiary(collection)?
                } else {
                    return Err(KrbError::CredentialCacheCannotCreate(
                        "Stored principal do not match".to_string(),
                    ));
                }
            } else {
                (subsidiary_name, k)
            }
        }
        Err(errno::Errno(libc::ENOKEY)) => {
            let s = collection
                .add_keyring(subsidiary_name.clone())
                .map_err(|e| KrbError::KeyutilsError(e))?;
            (subsidiary_name, s)
        }
        Err(e) => return Err(KrbError::KeyutilsError(e)),
    };
    Ok((n, c))
}

fn store_clock_skew(clock_skew: Duration, keyring: &mut Keyring) -> Result<Option<Key>, KrbError> {
    let key_name = "__krb5_time_offsets__";
    let offsets = TimeOffsets {
        secs: clock_skew.as_secs() as i32,
        usecs: clock_skew.subsec_micros() as i32,
    };
    let mut c = std::io::Cursor::new(Vec::new());
    offsets.write(&mut c).expect("Failed to write");
    let vec = c.into_inner();
    let key = keyring
        .add_key::<User, &str, &[u8]>(key_name, vec.as_slice())
        .map_err(|e| KrbError::KeyutilsError(e))?;
    Ok(Some(key))
}

fn store_credential(
    name: &Name,
    ticket: &EncTicket,
    kdc_reply_part: &KdcReplyPart,
    keyring: &mut Keyring,
) -> Result<Key, KrbError> {
    // Get the SPN and use it as the key name (creds->server)
    let key_name: String = (&kdc_reply_part.server).into();
    let creds: CredentialV4 = CredentialV4::new(name, ticket, kdc_reply_part)?;
    let mut c = std::io::Cursor::new(Vec::new());
    creds.write(&mut c).expect("Failed to write");
    let vec = c.into_inner();
    keyring
        .add_key::<User, &str, &[u8]>(key_name.as_str(), vec.as_slice())
        .map_err(|e| KrbError::KeyutilsError(e))
}

fn store_principal(name: &Name, keyring: &mut Keyring) -> Result<Key, KrbError> {
    let key_name = "__krb5_princ__";
    match keyring.search_for_key::<User, &str, Option<&mut Keyring>>(key_name, None) {
        Ok(k) => {
            let payload = k.read().map_err(|e| KrbError::KeyutilsError(e))?;
            let mut reader = binrw::io::Cursor::new(payload);
            let stored: PrincipalV4 = reader
                .read_type(binrw::Endian::Big)
                .map_err(|e| KrbError::BinRWError(e))?;
            let stored: Name = stored.try_into()?;
            if name == &stored {
                Ok(k)
            } else {
                Err(KrbError::CredentialCacheCannotCreate(
                    "Stored principal do not match".to_string(),
                ))
            }
        }
        Err(errno::Errno(libc::ENOKEY)) => {
            let princ: PrincipalV4 = name.try_into()?;
            let mut c = std::io::Cursor::new(Vec::new());
            princ.write(&mut c).expect("Failed to write");
            let vec = c.into_inner();
            keyring
                .add_key::<User, &str, &[u8]>(key_name, vec.as_slice())
                .map_err(|e| KrbError::KeyutilsError(e))
        }
        Err(e) => Err(KrbError::KeyutilsError(e)),
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
    let mut anchor: Keyring = match residual.anchor.as_str() {
        "process" => Keyring::attach_or_create(SpecialKeyring::Process),
        "session" => Keyring::attach_or_create(SpecialKeyring::Session),
        "user" => Keyring::attach_or_create(SpecialKeyring::User),
        "persistent" => {
            todo!();
        }
        _ => Err(Errno(libc::ENOTSUP)),
    }
    .map_err(|e| KrbError::KeyutilsError(e))?;

    let collection_name = format!("_krb_{}", residual.collection);
    let mut collection = match anchor.search_for_keyring(collection_name.clone(), None) {
        Ok(k) => Ok(k),
        Err(errno::Errno(libc::ENOKEY)) => anchor
            .add_keyring(collection_name.clone())
            .map_err(|e| KrbError::KeyutilsError(e)),
        Err(e) => Err(KrbError::KeyutilsError(e)),
    }?;

    let (subsidiary_name, mut subsidiary): (String, Keyring) =
        get_subsidiary_cache(name, &mut collection, residual.subsidiary)?;

    // Create the "primary" key within collection if not exists, pointing to the subsidiary cache
    let primary_name: &str = "krbccache:primary";
    match collection.search_for_key::<User, &str, Option<&mut Keyring>>(primary_name, None) {
        Ok(k) => {
            //let payload = k.read().map_err(|e| KrbError::KeyutilsError(e))?;
            //let mut reader = binrw::io::Cursor::new(payload);
            //let pn: PrimaryName = reader
            //    .read_type(binrw::Endian::Big)
            //    .map_err(|e| KrbError::BinRWError(e))?;
            Ok(k)
        }
        Err(errno::Errno(libc::ENOKEY)) => {
            let pn: PrimaryName = PrimaryName {
                strval: subsidiary_name.as_bytes().to_vec(),
            };
            let mut c = std::io::Cursor::new(Vec::new());
            pn.write(&mut c).expect("Failed to write");
            let vec = c.into_inner();
            collection
                .add_key::<User, &str, &[u8]>(primary_name, vec.as_slice())
                .map_err(|e| KrbError::KeyutilsError(e))
        }
        Err(e) => Err(KrbError::KeyutilsError(e)),
    }?;

    // Store the principal name within the subsidiary cache
    let _principal_key = store_principal(name, &mut subsidiary)?;

    // Store the principal name within the subsidiary cache
    let _credential_key = store_credential(name, ticket, kdc_reply_part, &mut subsidiary)?;

    // Store clockskew within subsidiary cache
    let _clock_skew_key = if let Some(cs) = clock_skew {
        store_clock_skew(cs, &mut subsidiary)?
    } else {
        None
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccache;

    #[tokio::test]
    async fn test_ccache_keyring_residual_parse() {
        let residual = Residual::parse("KEYRING:session");
        assert!(residual.is_err());
        let residual = Residual::parse("KEYRING:session:");
        assert!(residual.is_err());
        let residual = Residual::parse("KEYRING:session:1000").expect("Failed to parse");
        assert_eq!(
            residual,
            Residual {
                anchor: "session".to_string(),
                collection: "1000".to_string(),
                subsidiary: None
            }
        );
        let residual = Residual::parse("KEYRING:session:1000:").expect("Failed to parse");
        assert_eq!(
            residual,
            Residual {
                anchor: "session".to_string(),
                collection: "1000".to_string(),
                subsidiary: None
            }
        );
        let residual = Residual::parse("KEYRING:session:1000:foo").expect("Failed to parse");
        assert_eq!(
            residual,
            Residual {
                anchor: "session".to_string(),
                collection: "1000".to_string(),
                subsidiary: Some("foo".to_string())
            }
        );
    }

    /*
     * KEYRING:persistent:123
     *   anchor = persistent
     *   collection = 123
     *   subsidiary = NULL
     *
     * _persistent.123
     * \_ _krb
     *     \_ krb_ccache_12WEF43f2
     *         \_ __krb5_princ__
     *         \_ krbtgt/TEST.KERBEROS.ORG@TEST.KERBEROS.ORG
     *         \_ krb5_ccache_conf_data/fast_avail/...
     *         \_ __krb5_time_offsets__
     *     \_ krb_ccache_fdgsER324
     *     \_ ...
     *     \_ krb_ccache:primary (krb_ccache_12WEF43f2)
     *
     *
     * KEYRING:process:1000
     * \_ _krb_1000
     *      \_ 1000
     *          \_ __krb5_princ__
     *          \_ __krb5_time_offsets__
     *          \_ krb5_ccache_conf_data/fast_avail/...
     *          \_ krbtgt/TEST.KERBEROS.ORG@TEST.KERBEROS.ORG
     *      \_ krb_ccache_5De38WQ
     *          \_ __krb5_princ__
     *          \_ __krb5_time_offsets__
     *          \_ krb5_ccache_conf_data/fast_avail/...
     *          \_ krbtgt/TEST.KERBEROS.ORG@TEST.KERBEROS.ORG
     *      \_ krb_ccache:primary (1000)
     */

    #[tokio::test]
    async fn test_ccache_keyring_store() {
        let (name, ticket, kdc_reply) =
            crate::proto::get_tgt("testuser1", "EXAMPLE.COM", "password")
                .await
                .expect("Failed to get ticket");

        ccache::store(
            &name,
            &ticket,
            &kdc_reply,
            None,
            Some("KEYRING:process:foo:bar"),
        )
        .expect("Failed to store");

        ccache::store(
            &name,
            &ticket,
            &kdc_reply,
            None,
            Some("KEYRING:process:foo:bar"),
        )
        .expect("Failed to store");

        let (name, ticket, kdc_reply) =
            crate::proto::get_tgt("testuser2", "EXAMPLE.COM", "password")
                .await
                .expect("Failed to get ticket");

        let r = ccache::store(
            &name,
            &ticket,
            &kdc_reply,
            None,
            Some("KEYRING:process:foo:bar"),
        );
        assert!(r.is_err());

        let r = ccache::store(
            &name,
            &ticket,
            &kdc_reply,
            None,
            Some("KEYRING:process:foo:zap"),
        );
        assert!(r.is_ok());

        // Test random generated subsidiary
        // Will create default subsidiary
        let r = ccache::store(
            &name,
            &ticket,
            &kdc_reply,
            None,
            Some("KEYRING:process:abc"),
        );
        assert!(r.is_ok());

        let (name, ticket, kdc_reply) =
            crate::proto::get_tgt("testuser1", "EXAMPLE.COM", "password")
                .await
                .expect("Failed to get ticket");

        // Has to generate random subsidiary cache
        let r = ccache::store(
            &name,
            &ticket,
            &kdc_reply,
            None,
            Some("KEYRING:process:abc"),
        );
        assert!(r.is_ok());

        //use std::process::Command;
        //let output = Command::new("klist")
        //    .arg("-A")
        //    .env("KRB5CCNAME", "KEYRING:process:1000")
        //    .output()
        //    .expect("Failed to klist");
        //print!("{:#?}", output);
    }
}
