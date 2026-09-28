use crate::ccache::cc_file::FileCredentialCacheContext;
use crate::ccache::{CredentialCache, CredentialCacheCollection, ResolvedCredentialCache};
use crate::error::KrbError;
use crypto_glue::rand::{self, distr::Alphanumeric, RngExt};
use std::fs::{DirBuilder, File, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tracing::{debug, error, trace};
use walkdir::WalkDir;

struct DirCredentialCacheCollection {
    cccol_path: PathBuf,
}

impl DirCredentialCacheCollection {
    fn create_ccache_dir(ccache_dir: &PathBuf) -> Result<Self, KrbError> {
        trace!(?ccache_dir, "Check collection path");
        match std::fs::exists(ccache_dir) {
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

    fn store_primary_subsidiary_name(&self, subsidiary_name: &str) -> Result<(), KrbError> {
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

        let mut bytes = subsidiary_name.as_bytes().to_vec();
        bytes.extend("\n".as_bytes());

        f.write_all(bytes.as_slice()).map_err(|e| {
            error!(?e, ?subsidiary_name, "Failed to write primary file");
            KrbError::IoError
        })
    }
}

impl CredentialCacheCollection for DirCredentialCacheCollection {
    fn primary(&self) -> Result<Box<dyn CredentialCache>, KrbError> {
        let primary = self.cccol_path.join("primary");
        match std::fs::exists(&primary) {
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

    fn subsidiaries(&self) -> Result<Vec<Box<dyn CredentialCache>>, KrbError> {
        let mut subsidiaries: Vec<Box<dyn CredentialCache>> = vec![];
        for entry in WalkDir::new(&self.cccol_path)
            .into_iter()
            .filter_map(|dir_ent| {
                dir_ent
                    .map_err(|err| {
                        error!(?err, "Failed to read directory entry");
                        KrbError::IoError
                    })
                    .and_then(|dir_ent| {
                        dir_ent
                            .metadata()
                            .map_err(|err| {
                                error!(?err, "Failed to read directory entry metadata");
                                KrbError::IoError
                            })
                            .map(|dir_ent_meta| (dir_ent, dir_ent_meta))
                    })
                    .ok()
            })
            .filter(|a| a.1.is_file() && a.0.file_name() != "primary")
        {
            let fcc = FileCredentialCacheContext {
                cccol_path: Some(self.cccol_path.clone()),
                path: entry.0.into_path(),
            };
            subsidiaries.push(Box::new(fcc));
        }
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
            .ok_or(KrbError::CredentialCacheError)?;
        let path = PathBuf::from(path);

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
mod tests {}
