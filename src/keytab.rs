use binrw::helpers::until_eof;
use binrw::io::TakeSeekExt;
use binrw::{binread, binwrite};
use std::fmt;

use crate::proto::Name;

#[binwrite]
#[brw(big)]
#[binread]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data {
    #[br(temp)]
    #[bw(try_calc(u16::try_from(value.len())))]
    pub value_len: u16,
    #[br(count = value_len)]
    pub value: Vec<u8>,
}

#[binwrite]
#[brw(big)]
#[binread]
#[br(import { version: u8 })]
#[derive(Clone, PartialEq, Eq)]
pub struct Principal {
    #[br(temp)]
    #[bw(try_calc(u16::try_from(components.len())))]
    pub components_count: u16,
    pub realm: Data,
    // components includes the realm in version 1
    #[br(count = if version == 1 { components_count - 1 } else { components_count })]
    pub components: Vec<Data>,
    #[br(if(version > 1))]
    pub name_type: Option<u32>,
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c: Vec<_> = self
            .components
            .iter()
            .map(|x| String::from_utf8_lossy(x.value.as_slice()))
            .collect();
        let r = String::from_utf8_lossy(self.realm.value.as_slice());
        f.debug_struct("Principal")
            .field("components", &c)
            .field("realm", &r)
            .finish()
    }
}

#[binread]
#[binwrite]
#[brw(big)]
#[br(import { version: u8, rlen: i32 })]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    #[br(pre_assert(rlen > 0))]
    Entry {
        #[br(args { version })]
        principal: Principal,
        timestamp: u32,
        key_version_u8: u8,
        enctype: u16,
        key: Data,
        // Only if 4 bytes remaining in the stream (field present from version 1.14)
        #[br(try)]
        key_version_u32: Option<u32>,
    },
    // A negative record length represents a "hole" in the file, it is, an entry that has
    // been invalidated. The length of the hole is the inverse of the record length.
    #[br(pre_assert(rlen <= 0))]
    Hole {
        #[br(count = rlen.abs())]
        pad: Vec<u8>,
    },
}

#[binread]
#[binwrite]
#[brw(big)]
#[br(import { version: u8 })]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    #[br(dbg)]
    #[bw(if(*rlen > 0))]
    pub rlen: i32,
    #[br(map_stream = |s| s.take_seek(rlen.abs() as u64), args { version, rlen })]
    #[bw(if(*rlen > 0))]
    pub rdata: RecordData,
}

#[binread]
#[binwrite]
#[brw(big)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileKeytabV2 {
    #[br(parse_with = until_eof, args { version: 2 })]
    pub records: Vec<Record>,
}

#[binread]
#[binwrite]
#[brw(big, magic = 5u8)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKeytab {
    #[brw(magic = 2u8)]
    V2(FileKeytabV2),
}

#[binread]
#[binwrite]
#[brw(big)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Keytab {
    File(FileKeytab),
}

impl From<Name> for Principal {
    fn from(value: Name) -> Self {
        match value {
            Name::Principal { name, realm } => Principal {
                realm: Data {
                    value: realm.as_bytes().to_vec(),
                },
                components: vec![Data {
                    value: name.as_bytes().to_vec(),
                }],
                name_type: Some(1),
            },
            Name::SrvInst {
                service,
                instance,
                realm,
            } => {
                let mut c: Vec<Data> = vec![Data {
                    value: service.as_bytes().to_vec(),
                }];
                c.extend(instance.iter().map(|x| Data {
                    value: x.as_bytes().to_vec(),
                }));
                Principal {
                    realm: Data {
                        value: realm.as_bytes().to_vec(),
                    },
                    components: c,
                    name_type: Some(2),
                }
            }
            Name::SrvHst {
                service,
                host,
                realm,
            } => Principal {
                realm: Data {
                    value: realm.as_bytes().to_vec(),
                },
                components: vec![
                    Data {
                        value: service.as_bytes().to_vec(),
                    },
                    Data {
                        value: host.as_bytes().to_vec(),
                    },
                ],
                name_type: Some(3),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KrbError;
    use binrw::io::{Seek, Write};
    use binrw::{BinReaderExt, BinWrite};
    use std::env;
    use std::fs;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    impl FileKeytab {
        pub fn read(inner: &Vec<u8>) -> Result<Self, KrbError> {
            let mut reader = binrw::io::Cursor::new(inner);
            let keytab: FileKeytab = reader
                .read_type(binrw::Endian::Big)
                .map_err(|e| KrbError::BinRWError(e))?;
            Ok(keytab)
        }

        pub fn write<W: Write + Seek>(self: &Self, writer: &mut W) -> Result<(), KrbError> {
            let keytab = Keytab::File(self.clone());
            keytab.write(writer).map_err(|e| KrbError::BinRWError(e))
        }

        pub fn load(path: Option<PathBuf>) -> Result<Self, KrbError> {
            let mut f: File = match path {
                Some(p) => File::open(p).map_err(|e| KrbError::IoError(e)),
                None => match env::var("KRB5_KTNAME") {
                    Ok(val) => {
                        if !val.starts_with("FILE:") {
                            return Err(KrbError::UnsupportedKeytabType);
                        }
                        let p = val.strip_prefix("FILE:").expect("Failed to strip prefix");
                        let p = PathBuf::from(p);
                        File::open(p).map_err(|e| KrbError::IoError(e))
                    }
                    _ => {
                        // default_keytab_name from config file
                        todo!()
                    }
                },
            }?;
            let mut buffer = Vec::new();
            f.read_to_end(&mut buffer)
                .map_err(|e| KrbError::IoError(e))?;
            FileKeytab::read(&buffer)
        }

        pub fn store(self: &Self, path: Option<PathBuf>) -> Result<(), KrbError> {
            let mut f: File = match path {
                Some(p) => File::create(p).map_err(|e| KrbError::IoError(e)),
                None => match env::var("KRB5_KTNAME") {
                    Ok(val) => {
                        if !val.starts_with("FILE:") {
                            return Err(KrbError::UnsupportedKeytabType);
                        }
                        let p = val.strip_prefix("FILE:").expect("Failed to strip prefix");
                        let p = PathBuf::from(p);
                        File::create(p).map_err(|e| KrbError::IoError(e))
                    }
                    _ => {
                        // default_keytab_name from config file
                        todo!()
                    }
                },
            }?;
            self.write(&mut f)
        }
    }

    #[tokio::test]
    async fn test_keytab_read_write() {
        /*
         * This is a file ccache produced by MIT's kinit
         * including cache configuration entries
         */

        let mit_buf = "0502000000370001000a41464f524553542e41440006414e45544f240000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea900000002000000470001000a41464f524553542e41440006414e45544f240000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f000000020000003c0002000a41464f524553542e41440004686f73740005414e45544f0000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea9000000020000004c0002000a41464f524553542e41440004686f73740005414e45544f0000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f00000002000000490002000a41464f524553542e41440011526573747269637465644b7262486f73740005414e45544f0000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea900000002000000590002000a41464f524553542e41440011526573747269637465644b7262486f73740005414e45544f0000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f00000002";
        let mit_buf = hex::decode(mit_buf).expect("Failed to decode sample");
        let krime_keytab = FileKeytab::read(&mit_buf).expect("Failed to read from buffer");

        let mut c = std::io::Cursor::new(Vec::new());
        krime_keytab.write(&mut c).expect("Failed to write");
        let krime_buf = c.into_inner();

        assert_eq!(krime_buf, mit_buf);
    }

    #[tokio::test]
    async fn test_keytab_read_write_with_holes() {
        let mit_buf = "0502000000370001000a41464f524553542e41440006414e45544f240000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea900000002ffffffb90001000a41464f524553542e41440006414e45544f240000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f000000020000003c0002000a41464f524553542e41440004686f73740005414e45544f0000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea9000000020000004c0002000a41464f524553542e41440004686f73740005414e45544f0000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f00000002ffffffb70002000a41464f524553542e41440011526573747269637465644b7262486f73740005414e45544f0000000166ffb9ce0200110010cf8ea47a88cf230810f8ecbc9a1d4ea900000002000000590002000a41464f524553542e41440011526573747269637465644b7262486f73740005414e45544f0000000166ffb9ce0200120020ed373e70378deac2b312e0ef95c5675091273661a2d7d001fb5dd28fb7ee007f00000002";
        let mit_buf = hex::decode(mit_buf).expect("Failed to decode sample");
        let krime_keytab = FileKeytab::read(&mit_buf).expect("Failed to read from buffer");

        let FileKeytab::V2(k) = &krime_keytab;
        assert_eq!(k.records.len(), 6);
        assert!(matches!(k.records[0].rdata, RecordData::Entry { .. }));
        assert!(matches!(k.records[1].rdata, RecordData::Hole { .. }));
        assert!(matches!(k.records[2].rdata, RecordData::Entry { .. }));
        assert!(matches!(k.records[3].rdata, RecordData::Entry { .. }));
        assert!(matches!(k.records[4].rdata, RecordData::Hole { .. }));
        assert!(matches!(k.records[5].rdata, RecordData::Entry { .. }));

        let holes_len = 4 + k.records[1].rlen.abs() + 4 + k.records[4].rlen.abs();

        let mut c = std::io::Cursor::new(Vec::new());
        let krime_keytab = FileKeytab::read(&mit_buf).expect("Failed to read from buffer");
        krime_keytab.write(&mut c).expect("Failed to write");
        let krime_buf = c.into_inner();

        assert_eq!(mit_buf.len() - holes_len as usize, krime_buf.len());

        let krime_keytab2 = FileKeytab::read(&krime_buf).expect("Failed to read from buffer");
        let FileKeytab::V2(k2) = &krime_keytab2;
        assert_eq!(k2.records.len(), 4);

        assert_eq!(k.records[0], k2.records[0]);
        assert_eq!(k.records[2], k2.records[1]);
        assert_eq!(k.records[3], k2.records[2]);
        assert_eq!(k.records[5], k2.records[3]);
    }

    #[tokio::test]
    async fn test_keytab_read_pre_1_14() {
        let mit_buf = "0502000000460001000b4558414d504c452e4f524700087465737475736572000000016703af2e010012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000460001000b4558414d504c452e4f524700087465737475736572000000016703af2fff0012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000460001000b4558414d504c452e4f524700087465737475736572000000016703af2f000012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000460001000b4558414d504c452e4f524700087465737475736572000000016703af2fd20012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b";
        let mit_buf = hex::decode(mit_buf).expect("Failed to decode sample");
        let mit_keytab = FileKeytab::read(&mit_buf).expect("Failed to read from buffer");
        let FileKeytab::V2(mit_keytab) = &mit_keytab;

        let kvs_wrap = [1, 255, 0, 250];
        assert_eq!(mit_keytab.records.len(), kvs_wrap.len());

        for i in 0..3 {
            let e = &mit_keytab.records[i];
            match e.rdata {
                RecordData::Entry {
                    principal: _,
                    timestamp: _,
                    key_version_u8,
                    enctype: _,
                    key: _,
                    key_version_u32,
                } => {
                    assert_eq!(key_version_u8, kvs_wrap[i]);
                    assert!(key_version_u32.is_none());
                }
                _ => {
                    assert!(false);
                }
            }
        }

        let mit_buf = "05020000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeff010012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000010000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeffff0012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000ff0000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeff000012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000001000000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeffd20012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b499602d2";
        let mit_buf = hex::decode(mit_buf).expect("Failed to decode sample");
        let mit_keytab = FileKeytab::read(&mit_buf).expect("Failed to read from buffer");
        let FileKeytab::V2(mit_keytab) = &mit_keytab;

        let kvs: [u32; 4] = [1, 255, 256, 1234567890];
        assert_eq!(mit_keytab.records.len(), kvs.len());

        for i in 0..3 {
            let e = &mit_keytab.records[i];
            match e.rdata {
                RecordData::Entry {
                    principal: _,
                    timestamp: _,
                    key_version_u8,
                    enctype: _,
                    key: _,
                    key_version_u32,
                } => {
                    assert_eq!(key_version_u8, kvs_wrap[i]);
                    assert_eq!(key_version_u32.unwrap(), kvs[i]);
                }
                _ => {
                    assert!(false);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_keytab_store_load() {
        let buf = "05020000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeff010012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000010000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeffff0012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000000ff0000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeff000012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b000001000000004a0001000b4558414d504c452e4f524700087465737475736572000000016703aeffd20012002012041af3423a7ec2002784c14dfd9c6df58b49498238a250249940b5f36f430b499602d2";
        let buf = hex::decode(buf).expect("Failed to decode sample");
        let keytab = FileKeytab::read(&buf).expect("Failed to read from buffer");

        let path = "/tmp/krime.keytab";
        keytab
            .store(Some(PathBuf::from(path)))
            .expect("Failed to write");

        let status = Command::new("klist")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .arg("-k")
            .arg(path)
            .status()
            .expect("Failed to klist");

        let keytab2 =
            FileKeytab::load(Some(PathBuf::from(path))).expect("Failed to load from file");
        assert_eq!(keytab, keytab2);

        fs::remove_file(path).expect("Failed to rm ccache file");
        assert!(status.success());
    }
}
