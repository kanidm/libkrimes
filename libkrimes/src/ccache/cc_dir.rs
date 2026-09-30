use crate::ccache::cc_file::FileCredentialCacheContext;
use crate::ccache::{CredentialCache, CredentialCacheCollection, ResolvedCredentialCache};
use crate::error::KrbError;
use crypto_glue::rand::{self, distr::Alphanumeric, RngExt};
use std::fs::{DirBuilder, File, Permissions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tracing::{debug, error, trace};
use walkdir::WalkDir;

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

    fn gen_random_subsidiary_name() -> String {
        let s: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();
        format!("krb{s}")
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
}

impl CredentialCacheCollection for DirCredentialCacheCollection {
    fn cc_type(&self) -> &'static str {
        "DIR"
    }

    fn name(&self) -> Result<String, KrbError> {
        self.primary()?.name()
    }

    fn primary(&self) -> Result<Box<dyn CredentialCache>, KrbError> {
        let primary = self.cccol_path.join("primary");
        match primary.try_exists() {
            Ok(true) => {
                let mut f = File::open(&primary).map_err(|e| {
                    error!(?primary, ?e, "Failed to open file");
                    KrbError::IoError
                })?;
                let mut buffer = String::new();
                f.read_to_string(&mut buffer).map_err(|e| {
                    error!(?primary, ?e, "Filed to read file");
                    KrbError::IoError
                })?;
                let primary_path = self.cccol_path.join(buffer.trim());
                let fcc = FileCredentialCacheContext {
                    cccol_path: Some(self.cccol_path.clone()),
                    path: primary_path,
                };
                Ok(Box::new(fcc))
            }
            Ok(false) => {
                let primary_name = "tkt".to_string();
                self.store_primary_subsidiary_name(&primary_name)?;
                let fcc = FileCredentialCacheContext {
                    cccol_path: Some(self.cccol_path.clone()),
                    path: self.cccol_path.join(primary_name),
                };
                Ok(Box::new(fcc))
            }
            Err(e) => {
                error!(?e, ?primary, "Failed to read primary credentials");
                Err(KrbError::IoError)
            }
        }
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

    fn subsidiaries(&self) -> Result<Vec<Box<dyn CredentialCache>>, KrbError> {
        let subsidiaries: Vec<Box<dyn CredentialCache>> = WalkDir::new(&self.cccol_path)
            .into_iter()
            .map(|dir_ent| {
                dir_ent
                    .inspect_err(|err| error!(?err, "Failed to read directory entry"))
                    .and_then(|dir_ent| {
                        dir_ent
                            .metadata()
                            .inspect_err(|err| {
                                error!(?err, "Failed to read directory entry metadata")
                            })
                            .map(|dir_ent_meta| (dir_ent, dir_ent_meta))
                    })
                    .map_err(|_| KrbError::IoError)
            })
            .filter_map(|x| x.ok())
            .filter_map(|entry| {
                (entry.1.is_file() && entry.0.file_name() != "primary").then(|| {
                    Box::new(FileCredentialCacheContext {
                        cccol_path: Some(self.cccol_path.clone()),
                        path: entry.0.into_path(),
                    }) as Box<dyn CredentialCache>
                })
            })
            .collect();
        Ok(subsidiaries)
    }
}

pub(super) fn resolve(ccache_name: &str) -> Result<ResolvedCredentialCache, KrbError> {
    trace!(?ccache_name, "Resolving dir credential cache");

    let ccache_name = ccache_name
        .strip_prefix("DIR:")
        .ok_or(KrbError::UnsupportedCredentialCacheType)?;

    let resolved = if ccache_name.starts_with(":") {
        trace!(?ccache_name, "Collection with subsidiary");
        let path = ccache_name
            .strip_prefix(":")
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
        let ccache_name = format!("DIR:{}", path.to_string_lossy());

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

        let ResolvedCredentialCache::Collection(mut cccol) =
            crate::ccache::resolve(Some(residual.as_str()))?
        else {
            panic!("Expected a collection")
        };
        assert_eq!(cccol.name()?, format!(":{}/tkt", cccol_path));
        assert_eq!(cccol.full_name()?, format!("DIR::{}/tkt", cccol_path));
        assert_eq!(cccol.name()?, cccol.primary()?.name()?);
        assert_eq!(
            cccol.full_name()?,
            format!("DIR:{}", cccol.primary()?.name()?)
        );

        // Residual without subsidiary -> switch primary -> new primary subsidiary
        let new = cccol.new_unique()?;
        assert!(new.name()?.split("/").last().unwrap().starts_with("krb"));
        cccol.switch(&*new)?;
        assert_eq!(cccol.name()?, new.name()?);
        assert_eq!(cccol.full_name()?, new.full_name()?);
        cccol.destroy().ok();

        // Residual with subsidiary -> given subsidiary
        let cccol_path = "/tmp/krime_cccol_2".to_string();
        let residual = format!("DIR::{}/s1", cccol_path);
        let ResolvedCredentialCache::Subsidiary(cc) =
            crate::ccache::resolve(Some(residual.as_str()))?
        else {
            panic!("Expected a subsidiary")
        };
        assert_eq!(cc.name()?, format!(":{}/s1", cccol_path));
        assert_eq!(cc.full_name()?, format!("DIR::{}/s1", cccol_path));
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
        let ResolvedCredentialCache::Collection(cccol) =
            crate::ccache::resolve(Some(residual.as_str()))?
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

        let ResolvedCredentialCache::Collection(cccol) =
            crate::ccache::resolve(Some(residual.as_str()))?
        else {
            panic!("Expected a collection")
        };

        let mut primary = cccol.primary()?;
        primary.init(&creds.name, None)?;
        primary.store(&creds)?;
        assert_eq!(primary.principal()?, creds.name);

        // The underlying subsidiary file must exist inside the collection dir.
        let sub_residual = primary.full_name()?;
        assert!(sub_residual.starts_with("DIR::"));

        let out = klist(&residual);
        assert!(out.contains("testuser@EXAMPLE.COM"), "{out}");
        assert!(out.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"), "{out}");

        let out = klist(&sub_residual);
        assert!(out.contains("testuser@EXAMPLE.COM"), "{out}");

        std::fs::remove_dir_all(&cccol_path).ok();
        Ok(())
    }
}
