use super::OsStringExtensions;
use crate::ccache::cc_file::FileCredentialCacheContext;
use crate::ccache::{CredentialCache, CredentialCacheCollection, ResolvedCredentialCache};
use crate::error::KrbError;
use crypto_glue::rand::{self, RngExt, distr::Alphanumeric};
use std::ffi::{OsStr, OsString};
use std::fs::{DirBuilder, File, Permissions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tracing::{debug, error, trace};

struct DirCredentialCacheCollection {
    cccol_path: PathBuf,
}

impl DirCredentialCacheCollection {
    fn create_ccache_dir(ccache_dir: &PathBuf) -> Result<Self, KrbError> {
        trace!(?ccache_dir, "Check collection path");
        match ccache_dir.try_exists() {
            Ok(true) => match ccache_dir.is_dir() {
                false => {
                    error!(?ccache_dir, "Not a directory");
                    Err(KrbError::CredentialCacheError)
                }
                true => Ok(()),
            },
            Ok(false) => DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(ccache_dir)
                .map_err(|e| {
                    error!(?e, ?ccache_dir, "Failed to create directory",);
                    KrbError::IoError
                }),
            Err(e) => {
                error!(?e, "Failed to check if path exists");
                Err(KrbError::IoError)
            }
        }?;

        Ok(Self {
            cccol_path: ccache_dir.to_owned(),
        })
    }

    /// Whether `name` is a cache file name within a collection. This excludes
    /// the "primary" file.
    fn is_cache_file_name(name: &OsStr) -> bool {
        let name = name.as_bytes();
        name.starts_with(b"tkt") && !name.contains(&b'/') && !name.contains(&b'\\')
    }

    /// Generate a subsidiary name. MIT only lists files named "tkt*" as
    /// caches in a collection.
    fn gen_random_subsidiary_name() -> String {
        let s: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();
        format!("tkt{s}")
    }

    fn store_primary_subsidiary_name<P: AsRef<Path>>(
        &self,
        subsidiary_name: P,
    ) -> Result<(), KrbError> {
        let primary_path = self.cccol_path.join("primary");
        let mut f = File::create(&primary_path).map_err(|e| {
            error!(?e, ?primary_path, "Failed to create primary file");
            KrbError::IoError
        })?;

        let perms = Permissions::from_mode(0o600);
        f.set_permissions(perms).map_err(|x| {
            error!(?x, ?primary_path, "Failed to set primary file permissions");
            KrbError::IoError
        })?;

        let subsidiary_path: &Path = subsidiary_name.as_ref();
        let mut bytes = subsidiary_path.as_os_str().as_bytes().to_vec();
        bytes.extend("\n".as_bytes());

        f.write_all(bytes.as_slice()).map_err(|e| {
            error!(?e, ?subsidiary_path, "Failed to write primary file");
            KrbError::IoError
        })
    }

    /// Paths of the regular "tkt*" files directly within the collection
    /// directory. Like MIT, an unreadable directory has no caches.
    fn cache_files(&self) -> Vec<PathBuf> {
        let entries = match std::fs::read_dir(&self.cccol_path) {
            Ok(entries) => entries,
            Err(e) => {
                error!(?e, ?self.cccol_path, "Failed to read collection directory");
                return vec![];
            }
        };
        entries
            .filter_map(|entry| {
                entry
                    .inspect_err(|e| error!(?e, "Failed to read directory entry"))
                    .ok()
            })
            .filter(|entry| Self::is_cache_file_name(&entry.file_name()))
            .filter(|entry| entry.file_type().is_ok_and(|t| t.is_file()))
            .map(|entry| entry.path())
            .collect()
    }

    /// Read the name of the primary subsidiary from the primary file. Returns
    /// `None`, without creating it, if the primary file does not exist.
    fn read_primary_name(&self) -> Result<Option<OsString>, KrbError> {
        let primary = self.cccol_path.join("primary");
        match primary.try_exists() {
            Ok(true) => {
                let mut f = File::open(&primary).map_err(|e| {
                    error!(?primary, ?e, "Failed to open file");
                    KrbError::IoError
                })?;
                let mut buffer: Vec<u8> = vec![];
                f.read_to_end(&mut buffer).map_err(|e| {
                    error!(?primary, ?e, "Filed to read file");
                    KrbError::IoError
                })?;
                // Trim trailing newline bytes written by MIT or
                // store_primary_subsidiary_name. The new line is required by
                // MIT to correctly read the file.
                let trimmed: &[u8] = {
                    let end = buffer
                        .iter()
                        .rposition(|b| !b.is_ascii_whitespace())
                        .map_or(0, |i| i + 1);
                    let start = buffer
                        .iter()
                        .position(|b| !b.is_ascii_whitespace())
                        .unwrap_or(0);
                    &buffer[start..end]
                };
                Ok(Some(OsStr::from_bytes(trimmed).to_owned()))
            }
            Ok(false) => Ok(None),
            Err(e) => {
                error!(?e, ?primary, "Failed to read primary credentials");
                Err(KrbError::IoError)
            }
        }
    }
}

impl CredentialCacheCollection for DirCredentialCacheCollection {
    fn cc_type(&self) -> &'static str {
        "DIR"
    }

    fn name(&self) -> Result<OsString, KrbError> {
        self.primary()?.name()
    }

    fn primary(&self) -> Result<Box<dyn CredentialCache>, KrbError> {
        let subsidiary_name = match self.read_primary_name()? {
            Some(name) => name,
            None => {
                let primary_name = OsString::from("tkt");
                self.store_primary_subsidiary_name(&primary_name)?;
                primary_name
            }
        };
        let fcc = FileCredentialCacheContext {
            cccol_path: Some(self.cccol_path.clone()),
            path: self.cccol_path.join(subsidiary_name),
        };
        Ok(Box::new(fcc))
    }

    fn new_unique(&self) -> Result<Box<dyn CredentialCache>, KrbError> {
        for _ in 1..10 {
            let new_name = Self::gen_random_subsidiary_name();
            let path = self.cccol_path.join(new_name);
            match path.try_exists() {
                Ok(true) => {
                    continue;
                }
                Ok(false) => {
                    let cc = FileCredentialCacheContext {
                        cccol_path: Some(self.cccol_path.clone()),
                        path,
                    };
                    return Ok(Box::new(cc));
                }
                Err(e) => {
                    debug!("Failed to check if path {:?} exists: {:?}", path, e);
                    return Err(KrbError::IoError);
                }
            }
        }
        error!("Failed to generate a random subsidiary name");
        Err(KrbError::CredentialCacheError)
    }

    fn switch(&mut self, ccache: &dyn CredentialCache) -> Result<(), KrbError> {
        let primary_path = ccache.name().map(PathBuf::from)?;
        let primary_name = primary_path
            .file_name()
            .ok_or(KrbError::CredentialCacheNotFound)?;
        self.store_primary_subsidiary_name(primary_name)?;
        Ok(())
    }

    /// List the caches of the collection: the primary first if its file
    /// exists, then the other "tkt*" files directly within the collection
    /// directory.
    fn subsidiaries(&self) -> Result<Vec<Box<dyn CredentialCache>>, KrbError> {
        // MIT rejects a primary that is not a "tkt*" file name, and the cursor
        // then ignores it.
        let primary = match self.read_primary_name() {
            Ok(Some(name)) if Self::is_cache_file_name(&name) => {
                Some(self.cccol_path.join(name)).filter(|path| path.exists())
            }
            _ => None,
        };
        let others = self
            .cache_files()
            .into_iter()
            .filter(|path| Some(path) != primary.as_ref());

        let subsidiaries = primary
            .clone()
            .into_iter()
            .chain(others)
            .map(|path| {
                Box::new(FileCredentialCacheContext {
                    cccol_path: Some(self.cccol_path.clone()),
                    path,
                }) as Box<dyn CredentialCache>
            })
            .collect();
        Ok(subsidiaries)
    }
}

pub(super) fn resolve(ccache_name: &OsString) -> Result<ResolvedCredentialCache, KrbError> {
    trace!(?ccache_name, "Resolving dir credential cache");

    let ccache_name = ccache_name
        .strip_prefix_str("DIR:")
        .ok_or(KrbError::UnsupportedCredentialCacheType)?;

    let resolved = if ccache_name.starts_with_str(":") {
        trace!(?ccache_name, "Collection with subsidiary");
        let path = ccache_name
            .strip_prefix_str(":")
            .ok_or(KrbError::CredentialCacheError)
            .map(PathBuf::from)?;

        let collection_path = match path.parent() {
            Some(p) => Ok(PathBuf::from(p)),
            None => Err(KrbError::CredentialCacheError),
        }?;
        DirCredentialCacheCollection::create_ccache_dir(&collection_path)?;

        let fcc = FileCredentialCacheContext {
            cccol_path: Some(collection_path),
            path,
        };
        let fcc = Box::new(fcc);
        ResolvedCredentialCache::Subsidiary(fcc)
    } else {
        trace!(?ccache_name, "Collection without subsidiary");
        let collection_path = PathBuf::from(ccache_name);

        let cccol = DirCredentialCacheCollection::create_ccache_dir(&collection_path)?;
        ResolvedCredentialCache::Collection(Box::new(cccol))
    };

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccache::tests::{klist, skip_env};
    use crate::proto::Name;

    #[tokio::test]
    async fn test_ccache_dir_roundtrip() -> Result<(), KrbError> {
        let _ = tracing_subscriber::fmt::try_init();
        if skip_env() {
            return Ok(());
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("krb5cc_rt");
        let mut ccache_name = OsString::from("DIR:");
        ccache_name.push(path);

        crate::ccache::tests::store_and_verify_roundtrip(&ccache_name).await
    }

    #[tokio::test]
    async fn test_ccache_dir_name() -> Result<(), KrbError> {
        // Residual without subsidiary -> primary subsidiary
        let dir = tempfile::tempdir().expect("tempdir");
        let cccol_path = dir
            .path()
            .join(DirCredentialCacheCollection::gen_random_subsidiary_name())
            .to_string_lossy()
            .to_string();
        let residual = format!("DIR:{}", cccol_path);
        let ccache_name = OsString::from(residual);

        let ResolvedCredentialCache::Collection(mut cccol) =
            crate::ccache::resolve(Some(&ccache_name))?
        else {
            panic!("Expected a collection")
        };
        assert_eq!(
            cccol.name()?.to_string_lossy(),
            format!(":{}/tkt", cccol_path)
        );
        assert_eq!(
            cccol.full_name()?.to_string_lossy(),
            format!("DIR::{}/tkt", cccol_path)
        );
        assert_eq!(
            cccol.name()?.to_string_lossy(),
            cccol.primary()?.name()?.to_string_lossy()
        );
        assert_eq!(
            cccol.full_name()?.to_string_lossy(),
            format!("DIR:{}", cccol.primary()?.name()?.to_string_lossy())
        );

        // Residual without subsidiary -> switch primary -> new primary subsidiary
        let new = cccol.new_unique()?;
        // MIT names new subsidiaries "tktXXXXXX" and only lists "tkt*" files
        let new_name = new.name()?.to_string_lossy().into_owned();
        let new_file = new_name.split("/").last().unwrap();
        assert!(new_file.starts_with("tkt"));
        assert_eq!(new_file.len(), "tktXXXXXX".len());
        cccol.switch(&*new)?;
        assert_eq!(cccol.name()?, new.name()?);
        assert_eq!(cccol.full_name()?, new.full_name()?);
        cccol.destroy().ok();

        // Residual with subsidiary -> given subsidiary
        let dir = tempfile::tempdir().expect("tempdir");
        let cccol_path = dir.path().to_str().expect("Failed to get path");
        let residual = format!("DIR::{}/s1", cccol_path);
        let ccache_name = OsString::from(residual);
        let ResolvedCredentialCache::Subsidiary(cc) = crate::ccache::resolve(Some(&ccache_name))?
        else {
            panic!("Expected a subsidiary")
        };
        assert_eq!(cc.name()?.to_string_lossy(), format!(":{}/s1", cccol_path));
        assert_eq!(
            cc.full_name()?.to_string_lossy(),
            format!("DIR::{}/s1", cccol_path)
        );
        cccol.destroy().ok();

        Ok(())
    }

    /// find() must return the subsidiary whose principal matches, and
    /// CredentialCacheNotFound for an absent principal. subsidiaries() must
    /// exclude the `primary` pointer file.
    #[tokio::test]
    async fn test_ccache_dir_find_and_subsidiaries() -> Result<(), KrbError> {
        let dir = tempfile::tempdir().expect("tempdir");
        let cccol_path = dir
            .path()
            .join(DirCredentialCacheCollection::gen_random_subsidiary_name())
            .to_string_lossy()
            .to_string();
        let residual = format!("DIR:{}", cccol_path);
        let ccache_name = OsString::from(residual);
        let ResolvedCredentialCache::Collection(cccol) =
            crate::ccache::resolve(Some(&ccache_name))?
        else {
            panic!("Expected a collection")
        };

        let p1 = Name::Principal {
            name: "p1".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };
        let p2 = Name::Principal {
            name: "p2".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };
        let absent = Name::Principal {
            name: "nope".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };

        let mut c1 = cccol.primary()?;
        c1.init(&p1, None)?;
        let mut c2 = cccol.new_unique()?;
        c2.init(&p2, None)?;

        // subsidiaries() must not include the `primary` file.
        let subs = cccol.subsidiaries()?;
        assert_eq!(subs.len(), 2, "expected exactly two subsidiaries");

        let found = cccol.find(&p2)?;
        assert_eq!(found.principal()?, p2);

        let res = cccol.find(&absent);
        if let Err(err) = res {
            assert!(matches!(err, KrbError::CredentialCacheNotFound));
        } else {
            panic!("Expected error")
        }

        std::fs::remove_dir_all(&cccol_path).ok();
        Ok(())
    }

    /// subsidiaries() must list the primary first, if it exists, then the other
    /// "tkt*" files directly within the collection directory. The "primary"
    /// file, other files, directories and nested files are not caches, and
    /// neither is a primary file naming something that is not a "tkt*" file.
    #[tokio::test]
    async fn test_ccache_dir_subsidiaries_like_mit() -> Result<(), KrbError> {
        fn sorted(mut v: Vec<String>) -> Vec<String> {
            v.sort();
            v
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let cccol_path = dir.path().to_str().expect("Failed to get path");
        let ccache_name = OsString::from(format!("DIR:{cccol_path}"));
        let ResolvedCredentialCache::Collection(cccol) =
            crate::ccache::resolve(Some(&ccache_name))?
        else {
            panic!("Expected a collection")
        };

        let principal = Name::Principal {
            name: "p1".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };
        for file in ["tkt", "tktA", "tktB", "custom"] {
            let ccache_name = OsString::from(format!("DIR::{cccol_path}/{file}"));
            let ResolvedCredentialCache::Subsidiary(mut cc) =
                crate::ccache::resolve(Some(&ccache_name))?
            else {
                panic!("Expected a subsidiary")
            };
            cc.init(&principal, None)?;
        }
        std::fs::write(dir.path().join("other"), b"").expect("write");
        std::fs::create_dir(dir.path().join("tktdir")).expect("mkdir");
        std::fs::write(dir.path().join("tktdir").join("tktnested"), b"").expect("write");

        let listed = || -> Vec<String> {
            cccol
                .subsidiaries()
                .expect("subsidiaries")
                .iter()
                .map(|cc| {
                    let name = PathBuf::from(cc.name().expect("name"));
                    name.file_name().unwrap().to_string_lossy().into_owned()
                })
                .collect()
        };
        let set_primary = |contents: &str| {
            std::fs::write(dir.path().join("primary"), contents).expect("write");
        };

        // No primary file. It must not be created.
        assert_eq!(sorted(listed()), ["tkt", "tktA", "tktB"]);
        assert!(!dir.path().join("primary").exists());

        // The primary comes first and is not repeated.
        set_primary("tktB\n");
        let files = listed();
        assert_eq!(files[0], "tktB");
        assert_eq!(sorted(files), ["tkt", "tktA", "tktB"]);

        // Invalid primary names are ignored, including the primary file itself.
        for invalid in ["custom\n", "primary\n", "tktdir/tktnested\n"] {
            set_primary(invalid);
            assert_eq!(sorted(listed()), ["tkt", "tktA", "tktB"], "{invalid}");
        }

        // A primary whose file does not exist is not listed.
        set_primary("tktghost\n");
        assert_eq!(sorted(listed()), ["tkt", "tktA", "tktB"]);

        Ok(())
    }

    /// The primary of a fresh collection points at a file that does not exist
    /// yet. Reading its principal must report CredentialCacheNotFound, like
    /// the keyring backend, so callers can tell an uninitialized primary from a failure.
    #[tokio::test]
    async fn test_ccache_dir_fresh_primary_is_not_found() -> Result<(), KrbError> {
        let dir = tempfile::tempdir().expect("tempdir");
        let ccache_name = OsString::from(format!("DIR:{}", dir.path().display()));
        let ResolvedCredentialCache::Collection(cccol) =
            crate::ccache::resolve(Some(&ccache_name))?
        else {
            panic!("Expected a collection")
        };

        let primary = cccol.primary()?;
        assert!(matches!(
            primary.principal(),
            Err(KrbError::CredentialCacheNotFound)
        ));
        assert!(cccol.subsidiaries()?.is_empty());
        Ok(())
    }

    /// End-to-end with a real TGT stored in a DIR collection; MIT must read it
    /// both as a collection (DIR:<dir>) and as a subsidiary (DIR::<dir>/<sub>).
    #[tokio::test]
    async fn test_ccache_dir_store_e2e() -> Result<(), KrbError> {
        let _ = tracing_subscriber::fmt::try_init();
        if skip_env() {
            return Ok(());
        }

        let creds = crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password").await?;

        let dir = tempfile::tempdir().expect("tempdir");
        let cccol_path = dir
            .path()
            .join(DirCredentialCacheCollection::gen_random_subsidiary_name())
            .to_string_lossy()
            .to_string();
        let residual = format!("DIR:{}", cccol_path);
        let ccache_name = OsString::from(residual);

        let ResolvedCredentialCache::Collection(cccol) =
            crate::ccache::resolve(Some(&ccache_name))?
        else {
            panic!("Expected a collection")
        };

        let mut primary = cccol.primary()?;
        primary.init(&creds.name, None)?;
        primary.store(&creds)?;
        assert_eq!(primary.principal()?, creds.name);

        // The underlying subsidiary file must exist inside the collection dir.
        let sub_residual = primary.full_name()?;
        assert!(sub_residual.to_string_lossy().starts_with("DIR::"));

        let out = klist(&ccache_name);
        assert!(out.contains("testuser@EXAMPLE.COM"), "{out}");
        assert!(out.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"), "{out}");

        let out = klist(&sub_residual);
        assert!(out.contains("testuser@EXAMPLE.COM"), "{out}");

        std::fs::remove_dir_all(&cccol_path).ok();
        Ok(())
    }
}
