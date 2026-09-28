use super::CredentialCache;
use crate::ccache::{Credential, CredentialV4, Principal, PrincipalV4, ResolvedCredentialCache};
use crate::error::KrbError;
use crate::proto::{KerberosCredentials, Name};
use binrw::helpers::until_eof;
use binrw::io::TakeSeekExt;
use binrw::BinReaderExt;
use binrw::BinWrite;
use binrw::{binread, binwrite};
use std::fmt;
use std::fs;
use std::fs::File;
use std::fs::Permissions;
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, error, trace};

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct HeaderField {
    tag: u16,
    #[bw(try_calc(u16::try_from(value.len())))]
    value_len: u16,
    #[br(count = value_len)]
    value: Vec<u8>,
}

impl fmt::Display for HeaderField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tag {
            1 => {
                let seconds: [u8; 4] = self.value[0..4].try_into().map_err(|_| fmt::Error)?;
                let seconds = u32::from_be_bytes(seconds);
                let microseconds: [u8; 4] = self.value[4..8].try_into().map_err(|_| fmt::Error)?;
                let microseconds = u32::from_be_bytes(microseconds);
                let duration = Duration::new(seconds as u64, microseconds * 1000);
                write!(f, "KDC time offset: {:?}", duration)
            }
            _ => Ok(()),
        }
    }
}

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
struct FileCredentialCacheHeader {
    #[bw(calc = fields.iter().map(|x| (x.value.len() + 4) as u16).sum::<u16>())]
    length: u16,
    #[br(map_stream = |s| s.take_seek(length as u64), parse_with = until_eof)]
    fields: Vec<HeaderField>,
}

#[binwrite]
#[bw(big, magic = 4u8)]
#[binread]
#[br(magic = 4u8)]
#[derive(Debug)]
pub(super) struct FileCredentialCacheV4 {
    header: FileCredentialCacheHeader,
    principal: Principal,
    #[br(parse_with = until_eof)]
    credentials: Vec<Credential>,
}

impl fmt::Display for FileCredentialCacheV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Header fields:")?;
        for (i, field) in self.header.fields.iter().enumerate() {
            writeln!(f, "[{}] {}", i, field)?;
        }
        writeln!(f)?;

        writeln!(f, "Default principal: {}", self.principal)?;
        writeln!(f)?;

        for (i, cred) in self.credentials.iter().enumerate() {
            match cred {
                Credential::V4(v4) => {
                    writeln!(f, "Credential [{}]:", i)?;
                    v4.fmt(f)?;
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

#[binwrite]
#[bw(big, magic = 5u8)]
#[binread]
#[br(magic = 5u8)]
#[derive(Debug)]
pub(super) enum FileCredentialCache {
    V4(FileCredentialCacheV4),
}

impl FileCredentialCache {
    pub fn read(inner: &Vec<u8>) -> Result<Self, KrbError> {
        let mut reader = binrw::io::Cursor::new(inner);
        let ccache: FileCredentialCache = reader.read_type(binrw::Endian::Big).map_err(|e| {
            debug!(?e, "Failed to deserialize credential cache");
            KrbError::BinRWError
        })?;
        Ok(ccache)
    }

    pub fn load(path: &PathBuf) -> Result<Self, KrbError> {
        let f = File::open(path).map_err(|io_err| {
            error!(?io_err, "Unable to open file at {:#?}", path);
            KrbError::IoError
        })?;

        let mut reader = BufReader::new(f);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| {
            error!(?path, ?e, "Failed to read credential cache");
            KrbError::IoError
        })?;

        FileCredentialCache::read(&buffer)
    }
}

impl fmt::Display for FileCredentialCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileCredentialCache::V4(v4) => write!(f, "{v4}"),
        }
    }
}

pub(super) struct FileCredentialCacheContext {
    pub cccol_path: Option<PathBuf>,
    pub path: PathBuf,
}

impl CredentialCache for FileCredentialCacheContext {
    fn cc_type(&self) -> String {
        match &self.cccol_path {
            Some(_) => "DIR".to_string(),
            None => "FILE".to_string(),
        }
    }

    fn name(&self) -> Result<String, KrbError> {
        let name = match &self.cccol_path {
            Some(cccol) => {
                // This is a subsidiary cache in a DIR collection
                let file = self
                    .path
                    .file_name()
                    .map(|x| x.to_string_lossy().to_string())
                    .ok_or(KrbError::CredentialCacheNotFound)?;
                format!(":{}/{}", cccol.to_string_lossy(), file)
            }
            None => self.path.to_string_lossy().to_string(),
        };
        Ok(name)
    }

    fn init(&mut self, name: &Name, clock_skew: Option<Duration>) -> Result<(), KrbError> {
        let mut header = FileCredentialCacheHeader { fields: vec![] };

        if let Some(skew) = clock_skew {
            /*
             * At this time there is only one defined header field. Its tag value is 1,
             * its length is always 8, and its contents are two 32-bit integers giving
             * the seconds and microseconds of the time offset of the KDC relative to
             * the client. Adding this offset to the current time on the client should
             * give the current time on the KDC, if that offset has not changed since
             * the initial authentication.
             */
            let secs = skew.as_secs() as u32;
            let secs: [u8; 4] = secs.to_be_bytes();
            let msecs = skew.subsec_micros();
            let msecs: [u8; 4] = msecs.to_be_bytes();
            let mut field = HeaderField {
                tag: 1u16,
                value: vec![],
            };
            field.value.extend_from_slice(&secs);
            field.value.extend_from_slice(&msecs);
            header.fields.push(field);
        }

        let pv4: PrincipalV4 = name.try_into()?;
        let v4 = FileCredentialCacheV4 {
            header,
            principal: Principal::V4(pv4),
            credentials: vec![],
        };
        let fcc = FileCredentialCache::V4(v4);

        let mut f = File::create(&self.path).map_err(|io_err| {
            error!(?io_err, "Unable to create file at {:#?}", &self.path);
            KrbError::IoError
        })?;

        let perms = Permissions::from_mode(0o600);
        f.set_permissions(perms).map_err(|x| {
            error!(?x, "Unable to set permissions at {:#?}", &self.path);
            KrbError::IoError
        })?;

        fcc.write(&mut f).map_err(|x| {
            error!(?x, "Unable to create file at {:#?}", &self.path);
            KrbError::IoError
        })?;
        Ok(())
    }

    fn destroy(&mut self) -> Result<(), KrbError> {
        match fs::exists(&self.path) {
            Ok(true) => {
                let mut f = File::create(&self.path).map_err(|e| {
                    error!(?e, "Unable to open file at {:#?}", &self.path);
                    KrbError::IoError
                })?;
                let size = f
                    .metadata()
                    .map_err(|e| {
                        error!(?e, "Unable to fstat file at {:#?}", &self.path);
                        KrbError::IoError
                    })?
                    .size();
                let zeros = vec![0; size as usize];
                f.write_all(&zeros).map_err(|e| {
                    error!(?e, "Unable to write file at {:#?}", &self.path);
                    KrbError::IoError
                })?;
                f.flush().map_err(|e| {
                    error!(?e, "Unable to flush file at {:#?}", &self.path);
                    KrbError::IoError
                })?;
                drop(f);
                fs::remove_file(&self.path).map_err(|e| {
                    error!(?e, "Unable to delete file at {:#?}", &self.path);
                    KrbError::IoError
                })?;
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(e) => {
                error!(?e, "Unable to open file at {:#?}", &self.path);
                Err(KrbError::IoError)
            }
        }?;
        self.path = PathBuf::new();
        Ok(())
    }

    fn store(&mut self, credentials: &KerberosCredentials) -> Result<(), KrbError> {
        let cred = Credential::V4(CredentialV4::new(
            &credentials.name,
            &credentials.ticket,
            &credentials.kdc_reply,
        )?);

        let f = File::open(&self.path).map_err(|io_err| {
            error!(?io_err, "Unable to open file at {:#?}", &self.path);
            KrbError::IoError
        })?;

        let mut reader = BufReader::new(&f);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| {
            error!(?self.path, ?e, "Failed to read credential cache");
            KrbError::IoError
        })?;

        let mut fcc = FileCredentialCache::read(&buffer)?;
        match &mut fcc {
            FileCredentialCache::V4(v4) => v4.credentials.push(cred),
        };
        drop(f);

        let mut f = File::create(&self.path).map_err(|io_err| {
            error!(?io_err, "Unable to open file at {:#?}", &self.path);
            KrbError::IoError
        })?;
        fcc.write(&mut f).map_err(|binrw_err| {
            error!(?binrw_err, "Unable to write binary data.");
            KrbError::BinRWError
        })?;
        Ok(())
    }

    fn dump(&self) -> Result<(), KrbError> {
        let ccache = FileCredentialCache::load(&self.path)?;

        println!("{ccache}");

        Ok(())
    }

    fn principal(&self) -> Result<Name, KrbError> {
        let ccache = FileCredentialCache::load(&self.path)?;
        match &ccache {
            FileCredentialCache::V4(v4) => match &v4.principal {
                Principal::V4(pv4) => pv4.try_into(),
            },
        }
    }
}

pub(super) fn resolve(ccache_name: &str) -> Result<ResolvedCredentialCache, KrbError> {
    trace!(?ccache_name, "Resolving file credential cache");
    let path = ccache_name.strip_prefix("FILE:").unwrap_or(ccache_name);
    trace!(?path, "Resolved file credential cache");

    let path = PathBuf::from(&path);

    let fcc = FileCredentialCacheContext {
        cccol_path: None,
        path,
    };
    let fcc = Box::new(fcc);
    Ok(ResolvedCredentialCache::Subsidiary(fcc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccache::tests::{klist, skip_env};
    use crate::ccache::ResolvedCredentialCache;
    use binrw::BinWrite;

    // Test name with and without cccol
    #[tokio::test]
    async fn test_ccache_file_read_write() -> Result<(), KrbError> {
        /*
         * This is a file ccache produced by MIT's kinit
         * including cache configuration entries
         */
        let mit_buf = "0504000c00010008000000000000000000000001000000010000000b4558414d504c452e434f4d00000008746573747573657200000001000000010000000b4558414d504c452e434f4d00000008746573747573657200000001000000030000000c582d4341434845434f4e463a000000156b7262355f6363616368655f636f6e665f646174610000000a666173745f617661696c0000001e6b72627467742f4558414d504c452e434f4d404558414d504c452e434f4d0000000000000000000000000000000000000000000000000000000000000000000000000000037965730000000000000001000000010000000b4558414d504c452e434f4d00000008746573747573657200000002000000020000000b4558414d504c452e434f4d000000066b72627467740000000b4558414d504c452e434f4d001200000020de5604735e4216fdf4e7992177ac3d6b25416e6517edce48fcb8be73f9ecf46f66a7815b66a7815b66a80dfb66b0bbdb0000c100000000000000000000000001ba618201b6308201b2a003020105a10d1b0b4558414d504c452e434f4da220301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da382017830820174a003020112a103020101a2820166048201620c0ded71bdab6134022d37fa7ea73856eb87044fa4340e36a2668c8fc74f21a9637fac7ccf2777202583b9fea5ca609cec1b1479f72a7374f2ae7e5347bcc64a66de1575bd8bc9eaa6ce96049e199d7a6f835dda18aea8b0d093d05bd4bba4fc5c2385f000297217adde3c23dff75705a4fafe58dee48774eeef2c969a8dd64ea3f754087d72c4796506ebb23fef404fbb41826483642af6f2a97680146319dd5541adbe2b6247766f36f0b5a673bffea5cc8b89e8c91359147f291e740e8f69377e88f984829d1791912c7da7cc7f6277470a91cf140b6c71da0f4e561722e0536a23af6da7a375343b6e5b72c4847f3c848d4e8b044ae313979f954db7a7210052922f587e6e5d21447aec02beaeab9371dd1ae9903dde0838b1fd9b791a4a4065565905664a62c92980053c8532586deeafd0e558df77de6e4ce2c653feff9aefc2c9b0a34ab2cc405e3bf4a8b49c9bf1c8d1c6f79be11fa71272edcfc3a5c51700000000";
        let mit_buf = hex::decode(mit_buf).expect("Invalid hex buffer");
        let krime_ccache = FileCredentialCache::read(&mit_buf)?;

        let mut c = std::io::Cursor::new(Vec::new());
        krime_ccache.write(&mut c).unwrap();
        let krime_buf = c.into_inner();

        assert_eq!(krime_buf, mit_buf);
        Ok(())
    }

    #[tokio::test]
    async fn test_ccache_file_roundtrip() -> Result<(), KrbError> {
        let _ = tracing_subscriber::fmt::try_init();
        if skip_env() {
            return Ok(());
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("krb5cc_rt");
        let ccache_name = format!("FILE:{}", path.to_string_lossy());

        crate::ccache::tests::store_and_verify_roundtrip(&ccache_name).await
    }

    /// The clock-skew header (tag 1) must be written as 8 bytes (secs + usecs)
    /// and survive a reload, matching MIT's KDC-time-offset header semantics.
    #[tokio::test]
    async fn test_ccache_file_header_clock_skew() -> Result<(), KrbError> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("krb5cc_skew");
        let name = Name::Principal {
            name: "testuser".to_string(),
            realm: "EXAMPLE.COM".to_string(),
        };

        let mut ctx = FileCredentialCacheContext {
            cccol_path: None,
            path: path.clone(),
        };
        ctx.init(&name, Some(Duration::new(42, 123_000)))?;

        let fcc = FileCredentialCache::load(&path)?;
        let FileCredentialCache::V4(v4) = fcc;
        assert_eq!(v4.header.fields.len(), 1);
        let field = &v4.header.fields[0];
        assert_eq!(field.tag, 1);
        assert_eq!(field.value.len(), 8);
        let secs = u32::from_be_bytes(field.value[0..4].try_into().unwrap());
        let usecs = u32::from_be_bytes(field.value[4..8].try_into().unwrap());
        assert_eq!(secs, 42);
        assert_eq!(usecs, 123);

        // principal round-trips
        assert_eq!(ctx.principal()?, name);
        Ok(())
    }

    /// destroy() on a path that does not exist must be a no-op returning Ok.
    #[tokio::test]
    async fn test_ccache_file_destroy_missing_is_noop() -> Result<(), KrbError> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does_not_exist");
        let mut ctx = FileCredentialCacheContext {
            cccol_path: None,
            path,
        };
        ctx.destroy()?;
        Ok(())
    }

    /// End-to-end with a real TGT: init -> store -> 0o600 perms -> principal
    /// matches -> klist reads it -> destroy removes the file. Also verifies
    /// that a second store() appends a credential rather than overwriting.
    #[tokio::test]
    async fn test_ccache_file_store_e2e() -> Result<(), KrbError> {
        let _ = tracing_subscriber::fmt::try_init();
        if skip_env() {
            return Ok(());
        }

        let creds = crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password").await?;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("krb5cc_e2e");
        let ccache_name = format!("FILE:{}", path.to_string_lossy());

        let ResolvedCredentialCache::Subsidiary(mut ccache) =
            crate::ccache::resolve(Some(ccache_name.as_str()))?
        else {
            panic!("Expected a subsidiary")
        };

        ccache.init(&creds.name, None)?;
        ccache.store(&creds)?;

        assert!(std::fs::exists(&path).expect("exists"));
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "ccache must be mode 0o600");

        assert_eq!(ccache.principal()?, creds.name);

        let output = klist(&ccache_name);
        assert!(output.contains("testuser@EXAMPLE.COM"), "{output}");
        assert!(
            output.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
            "{output}"
        );

        // Storing a second credential appends (count grows to 2).
        ccache.store(&creds)?;
        let fcc = FileCredentialCache::load(&path)?;
        let FileCredentialCache::V4(v4) = fcc;
        assert_eq!(v4.credentials.len(), 2, "store() must append credentials");

        ccache.destroy()?;
        assert!(!std::fs::exists(&path).expect("exists"));
        Ok(())
    }
}
