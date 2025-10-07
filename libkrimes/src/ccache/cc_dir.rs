use super::CredentialCache;
use crate::ccache::cc_file::FileCredentialCacheContext;
use crate::error::KrbError;
use std::fs::{DirBuilder, File};
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use tracing::{error, trace};

fn create_ccache_dir(ccache_dir: &PathBuf) -> Result<(), KrbError> {
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
    }
}

fn get_primary(path: &Path) -> Result<Option<PathBuf>, KrbError> {
    let primary = path.join("primary");
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
            let primary_path = path.join(buffer.trim());
            trace!(?primary_path, "Primary credentials ccache");
            Ok(Some(primary_path))
        }
        Ok(false) => {
            trace!("No primary credentials ccache");
            Ok(None)
        }
        Err(e) => {
            error!(?e, ?primary, "Failed to read primary credentials");
            Err(KrbError::IoError)
        }
    }
}

fn set_primary(path: &Path, primary_name: &str) -> Result<(), KrbError> {
    let primary_path = path.join("primary");
    let mut f = File::create_new(&primary_path).map_err(|e| {
        error!(?e, ?primary_path, "Failed to create primary file");
        KrbError::IoError
    })?;
    f.write_all(primary_name.as_bytes()).map_err(|e| {
        error!(?e, ?primary_path, "Failed to write primary file");
        KrbError::IoError
    })
}

pub(super) fn resolve(ccache_name: &str) -> Result<Box<dyn CredentialCache>, KrbError> {
    trace!(?ccache_name, "Resolving dir credential cache");

    let ccache_name = ccache_name
        .strip_prefix("DIR:")
        .ok_or(KrbError::UnsupportedCredentialCacheType)?;

    let path = if ccache_name.starts_with(":") {
        trace!(?ccache_name, "Collection with subsidiary");
        let ccache_name = ccache_name
            .strip_prefix(":")
            .ok_or(KrbError::CredentialCacheError)?;
        let path = PathBuf::from(ccache_name).canonicalize().map_err(|e| {
            error!(?e, ?ccache_name, "Failed to canonicalize path");
            KrbError::IoError
        })?;

        let collection_path = match path.parent() {
            Some(p) => Ok(PathBuf::from(p)),
            None => Err(KrbError::CredentialCacheError),
        }?;

        create_ccache_dir(&collection_path)?;
        path
    } else {
        trace!(?ccache_name, "Collection without subsidiary");
        let collection_path = PathBuf::from(ccache_name).canonicalize().map_err(|e| {
            error!(?e, ?ccache_name, "Failed to canonicalize path");
            KrbError::IoError
        })?;
        create_ccache_dir(&collection_path)?;

        match get_primary(&collection_path)? {
            Some(primary_path) => primary_path,
            None => {
                set_primary(&collection_path, "tkt")?;
                collection_path.join("tkt")
            }
        }
    };

    trace!(?path, "Resolved dir subsidiary credential cache");

    let fcc = FileCredentialCacheContext { path };
    Ok(Box::new(fcc))
}
