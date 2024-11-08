use crate::asn1::constants::PrincipalNameType;
use crate::error::KrbError;
use crate::proto::{Name, SessionKey};
use binrw::helpers::until_eof;
use binrw::io::TakeSeekExt;
use binrw::{binread, binwrite};

/* TODO:
 *   - Handle cache conf entries. CredentialCache::new() could take a KV pair collection
 *   - Handle parsing. CredentialCache::read() just reads the credential cache, but there
 *     should be a CredentialCache::parse() to return Result<(Name, Vec<Ticket>), KrbError>,
 *     and maybe a KV pair collection with the conf entries.
 */

#[binwrite]
#[bw(big)]
#[binread]
#[derive(Debug)]
pub(crate) struct HeaderField {
    tag: u16,
    #[bw(try_calc(u16::try_from(value.len())))]
    value_len: u16,
    #[br(count = value_len)]
    value: Vec<u8>,
}

#[binwrite]
#[bw(big)]
#[binread]
pub(crate) struct FileCredentialCacheHeader {
    #[bw(calc = fields.iter().map(|x| (x.value.len() + 4) as u16).sum::<u16>())]
    length: u16,
    #[br(map_stream = |s| s.take_seek(length as u64), parse_with = until_eof)]
    fields: Vec<HeaderField>,
}

#[binwrite]
#[bw(big)]
#[binread]
struct DataComponent {
    #[bw(try_calc(u32::try_from(value.len())))]
    value_len: u32,
    #[br(count = value_len)]
    value: Vec<u8>,
}

#[binwrite]
#[bw(big)]
#[binread]
struct PrincipalV4 {
    name_type: u32,
    #[bw(try_calc(u32::try_from(components.len())))]
    components_count: u32,
    realm: DataComponent,
    #[br(count = components_count)]
    components: Vec<DataComponent>,
}

#[binwrite]
#[bw(big)]
#[binread]
enum FileCredentialCachePrincipal {
    V4(PrincipalV4),
}

#[binwrite]
#[bw(big)]
#[binread]
struct KeyBlockV4 {
    enc_type: u16,
    data: DataComponent,
}

#[binwrite]
#[bw(big)]
#[binread]
enum KeyBlock {
    V4(KeyBlockV4),
}

#[binwrite]
#[bw(big)]
#[binread]
struct Address {
    addr_type: u16,
    data: DataComponent,
}

#[binwrite]
#[bw(big)]
#[binread]
struct Addresses {
    #[bw(try_calc(u32::try_from(addresses.len())))]
    count: u32,
    #[br(count = count)]
    addresses: Vec<Address>,
}

#[binwrite]
#[bw(big)]
#[binread]
struct AuthDataComponent {
    ad_type: u16,
    data: DataComponent,
}

#[binwrite]
#[bw(big)]
#[binread]
struct AuthData {
    #[bw(try_calc(u32::try_from(auth_data.len())))]
    count: u32,
    #[br(count = count)]
    auth_data: Vec<AuthDataComponent>,
}

#[binwrite]
#[bw(big)]
#[binread]
struct CredentialV4 {
    client: PrincipalV4,
    server: PrincipalV4,
    keyblock: KeyBlock,
    authtime: u32,
    starttime: u32,
    endtime: u32,
    renew_till: u32,
    is_skey: u8,
    ticket_flags: u32,
    addresses: Addresses,
    authdata: AuthData,
    ticket: DataComponent,
    second_ticket: DataComponent,
}

#[binwrite]
#[bw(big)]
#[binread]
enum Credential {
    V4(CredentialV4),
}

#[binwrite]
#[bw(big, magic = 4u8)]
#[binread]
#[br(magic = 4u8)]
pub(crate) struct FileCredentialCacheV4 {
    header: FileCredentialCacheHeader,
    principal: FileCredentialCachePrincipal,
    #[br(parse_with = until_eof)]
    credentials: Vec<Credential>,
}

#[binwrite]
#[bw(big, magic = 5u8)]
#[binread]
#[br(magic = 5u8)]
pub(crate) enum FileCredentialCache {
    V4(FileCredentialCacheV4),
}

#[binwrite]
#[bw(big)]
#[binread]
pub(crate) enum CredentialCache {
    File(FileCredentialCache),
}

impl TryFrom<&Name> for PrincipalV4 {
    type Error = KrbError;

    fn try_from(name: &Name) -> Result<Self, Self::Error> {
        match name {
            Name::Principal { name, realm } => {
                let p: PrincipalV4 = PrincipalV4 {
                    name_type: PrincipalNameType::NtPrincipal as u32,
                    realm: DataComponent {
                        value: realm.as_bytes().into(),
                    },
                    components: vec![DataComponent {
                        value: name.as_bytes().into(),
                    }],
                };
                Ok(p)
            }
            Name::SrvInst {
                service,
                instance,
                realm,
            } => {
                let mut components: Vec<DataComponent> = vec![];
                components.push(DataComponent {
                    value: service.as_bytes().into(),
                });
                let iv: Vec<DataComponent> = instance
                    .into_iter()
                    .map(|x| DataComponent {
                        value: x.as_bytes().into(),
                    })
                    .collect();
                components.extend(iv);

                let p: PrincipalV4 = PrincipalV4 {
                    name_type: PrincipalNameType::NtSrvInst as u32,
                    realm: DataComponent {
                        value: realm.as_bytes().into(),
                    },
                    components,
                };
                Ok(p)
            }
            _ => todo!(),
        }
    }
}

impl TryFrom<&SessionKey> for KeyBlockV4 {
    type Error = KrbError;

    fn try_from(value: &SessionKey) -> Result<Self, Self::Error> {
        match value {
            SessionKey::Aes256CtsHmacSha196 { k } => Ok(KeyBlockV4 {
                enc_type: 0x12,
                data: DataComponent { value: k.to_vec() },
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::constants::encryption_types::EncryptionType as Asn1EncryptionType;
    use crate::asn1::encrypted_data::EncryptedData as Asn1EncryptedData;
    use crate::asn1::tagged_ticket::TaggedTicket as Asn1TaggedTicket;
    use crate::asn1::tagged_ticket::Ticket as Asn1Ticket;
    use crate::proto::{EncTicket, EncryptedData, KdcReplyPart};
    use binrw::io::{Seek, Write};
    use binrw::{BinReaderExt, BinWrite};
    use der::asn1::OctetString;
    use der::Encode;
    use std::env;
    use std::fs;
    use std::fs::File;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, SystemTime};

    impl FileCredentialCache {
        pub fn new(
            name: &Name,
            ticket: &EncTicket,
            enc_part: &KdcReplyPart,
            clock_skew: Option<Duration>,
        ) -> Result<Self, KrbError> {
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
                let msecs = skew.subsec_micros() as u32;
                let msecs: [u8; 4] = msecs.to_be_bytes();
                let mut field = HeaderField {
                    tag: 1u16,
                    value: vec![],
                };
                field.value.extend_from_slice(&secs);
                field.value.extend_from_slice(&msecs);
                header.fields.push(field);
            }

            let principal = FileCredentialCachePrincipal::V4(name.try_into()?);

            let credentials = vec![
                //Credential::V4(CredentialV4 {
                //    client: name.try_into()?,
                //    server: PrincipalV4 {
                //        name_type: 1,
                //        realm: DataComponent {
                //            value: "X-CACHECONF:".as_bytes().into(),
                //        },
                //        components: vec![
                //            DataComponent {
                //                value: "krb5_ccache_conf_data".as_bytes().into(),
                //            },
                //            DataComponent {
                //                value: "fast_avail".as_bytes().into(),
                //            },
                //            DataComponent {
                //                value: "krbtgt/EXAMPLE.COM@EXAMPLE.COM".as_bytes().into(),
                //            },
                //        ],
                //    },
                //    keyblock: KeyBlock::V4(KeyBlockV4 {
                //        enc_type: 0,
                //        data: DataComponent { value: vec![] },
                //    }),
                //    authtime: 0u32,
                //    starttime: 0u32,
                //    endtime: 0u32,
                //    renew_till: 0u32,
                //    is_skey: 0u8,
                //    ticket_flags: 0u32,
                //    addresses: Addresses { addresses: vec![] },
                //    authdata: AuthData { auth_data: vec![] },
                //    ticket: DataComponent {
                //        value: "yes".as_bytes().into(),
                //    },
                //    second_ticket: DataComponent { value: vec![] },
                //}),
                Credential::V4(CredentialV4 {
                    client: name.try_into()?,
                    server: (&enc_part.server).try_into()?,
                    keyblock: KeyBlock::V4((&enc_part.key).try_into()?),
                    authtime: enc_part
                        .auth_time
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_err(|_| KrbError::InsufficientData)?
                        .as_secs() as u32,
                    starttime: if let Some(start_time) = enc_part.start_time {
                        start_time
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map_err(|_| KrbError::InsufficientData)?
                            .as_secs() as u32
                    } else {
                        0u32
                    },
                    endtime: enc_part
                        .end_time
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_err(|_| KrbError::InsufficientData)?
                        .as_secs() as u32,
                    renew_till: if let Some(till) = enc_part.renew_until {
                        till.duration_since(SystemTime::UNIX_EPOCH)
                            .map_err(|_| KrbError::InsufficientData)?
                            .as_secs() as u32
                    } else {
                        0u32
                    },
                    is_skey: 0u8,
                    ticket_flags: enc_part.flags.bits().reverse_bits(),
                    addresses: Addresses { addresses: vec![] },
                    authdata: AuthData { auth_data: vec![] },
                    ticket: DataComponent {
                        value: match &ticket.enc_part {
                            EncryptedData::Aes256CtsHmacSha196 { kvno: _, data } => {
                                let t = Asn1Ticket {
                                    tkt_vno: 5,
                                    realm: (&enc_part.server).try_into()?,
                                    sname: (&enc_part.server).try_into()?,
                                    enc_part: Asn1EncryptedData {
                                        etype: Asn1EncryptionType::AES256_CTS_HMAC_SHA1_96 as i32,
                                        kvno: Some(1), // TODO Why?
                                        cipher: OctetString::new(data.clone())
                                            .expect("Failed to build OctetString"),
                                    },
                                };
                                let tt = Asn1TaggedTicket::new(t);
                                tt.to_der().map_err(|e| {
                                    println!("{:#?}", e);
                                    KrbError::DerEncodeEncTicketPart
                                })?
                            }
                        },
                    },
                    second_ticket: DataComponent { value: vec![] },
                }),
            ];

            let ccache: FileCredentialCacheV4 = FileCredentialCacheV4 {
                header,
                principal,
                credentials,
            };

            Ok(FileCredentialCache::V4(ccache))
        }

        pub fn store(self: Self, path: Option<PathBuf>) -> Result<(), KrbError> {
            let mut f: File = match path {
                Some(p) => File::create(p).map_err(|e| KrbError::IoError(e)),
                None => match env::var("KRB5CCNAME") {
                    Ok(val) => {
                        if !val.starts_with("FILE:") {
                            return Err(KrbError::UnsupportedCredentialCacheType);
                        }
                        let p = val.strip_prefix("FILE:").expect("Failed to strip prefix");
                        let p = PathBuf::from(p);
                        File::create(p).map_err(|e| KrbError::IoError(e))
                    }
                    _ => {
                        // default_ccache_name from config file
                        todo!()
                    }
                },
            }?;
            self.write(&mut f)
        }

        pub fn write<W: Write + Seek>(self: Self, writer: &mut W) -> Result<(), KrbError> {
            let ccache = CredentialCache::File(self);
            ccache.write(writer).map_err(|e| KrbError::BinRWError(e))
        }

        pub fn read(inner: &Vec<u8>) -> Result<Self, KrbError> {
            let mut reader = binrw::io::Cursor::new(inner);
            let ccache: FileCredentialCache = reader
                .read_type(binrw::Endian::Big)
                .map_err(|e| KrbError::BinRWError(e))?;
            Ok(ccache)
        }
    }

    #[tokio::test]
    async fn test_ccache_file_read_write() {
        /*
         * This is a file ccache produced by MIT's kinit
         * including cache configuration entries
         */
        let mit_buf = "0504000c00010008000000000000000000000001000000010000000b4558414d504c452e434f4d00000008746573747573657200000001000000010000000b4558414d504c452e434f4d00000008746573747573657200000001000000030000000c582d4341434845434f4e463a000000156b7262355f6363616368655f636f6e665f646174610000000a666173745f617661696c0000001e6b72627467742f4558414d504c452e434f4d404558414d504c452e434f4d0000000000000000000000000000000000000000000000000000000000000000000000000000037965730000000000000001000000010000000b4558414d504c452e434f4d00000008746573747573657200000002000000020000000b4558414d504c452e434f4d000000066b72627467740000000b4558414d504c452e434f4d001200000020de5604735e4216fdf4e7992177ac3d6b25416e6517edce48fcb8be73f9ecf46f66a7815b66a7815b66a80dfb66b0bbdb0000c100000000000000000000000001ba618201b6308201b2a003020105a10d1b0b4558414d504c452e434f4da220301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da382017830820174a003020112a103020101a2820166048201620c0ded71bdab6134022d37fa7ea73856eb87044fa4340e36a2668c8fc74f21a9637fac7ccf2777202583b9fea5ca609cec1b1479f72a7374f2ae7e5347bcc64a66de1575bd8bc9eaa6ce96049e199d7a6f835dda18aea8b0d093d05bd4bba4fc5c2385f000297217adde3c23dff75705a4fafe58dee48774eeef2c969a8dd64ea3f754087d72c4796506ebb23fef404fbb41826483642af6f2a97680146319dd5541adbe2b6247766f36f0b5a673bffea5cc8b89e8c91359147f291e740e8f69377e88f984829d1791912c7da7cc7f6277470a91cf140b6c71da0f4e561722e0536a23af6da7a375343b6e5b72c4847f3c848d4e8b044ae313979f954db7a7210052922f587e6e5d21447aec02beaeab9371dd1ae9903dde0838b1fd9b791a4a4065565905664a62c92980053c8532586deeafd0e558df77de6e4ce2c653feff9aefc2c9b0a34ab2cc405e3bf4a8b49c9bf1c8d1c6f79be11fa71272edcfc3a5c51700000000";
        let mit_buf = hex::decode(mit_buf).expect("Failed to decode sample");
        let krime_ccache = FileCredentialCache::read(&mit_buf).expect("Failed to read from buffer");

        let mut c = std::io::Cursor::new(Vec::new());
        krime_ccache.write(&mut c).expect("Failed to write");
        let krime_buf = c.into_inner();

        assert_eq!(krime_buf, mit_buf);
    }

    #[tokio::test]
    async fn test_ccache_file_write() {
        let (name, ticket, kdc_reply) =
            crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password")
                .await
                .expect("Failed to get ticket");

        /*
         * This is a file ccache produced by MIT's kinit manually edited
         * to remove the cache configuration entries
         */
        let mit_ccache = "0504000c00010008000000000000000000000001000000010000000b4558414d504c452e434f4d00000008746573747573657200000001000000010000000b4558414d504c452e434f4d00000008746573747573657200000002000000020000000b4558414d504c452e434f4d000000066b72627467740000000b4558414d504c452e434f4d00120000002022ea076fcce3a4624bf3f71a5f9131240f2aac4b2f8027fe009a174362b9a14466a354d566a354d566a3e17566ac8f550000c100000000000000000000000001ba618201b6308201b2a003020105a10d1b0b4558414d504c452e434f4da220301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da382017830820174a003020112a103020101a282016604820162d1d8e32a6b96171c211107bb955fbcbf9bf047541794c0d1cf562dafd9a0dd8cd75f87ce3d534b076f5d1b44753036c3fdc6868ae9129128983ca40ba36350d49a6e590de51e003b50faae07fd3dc7d257ff672f413ac1f5cfa4a01fdd1cfc98cb53d7124813395455b87e0965183d21782a72fc0aa509e785392404662be4f6ef6fc9f7c09f4d84c0bf991509f6fd428c7d5d85374ca28c0b27aef5796d159563c63fd346dd5858502c58b4e7c44430d835c752eadaaeec650464d8d83e1757987782a9d13198a5c0e1a6b23958bba2116fbaccb18852672ad7060306904bf0f7a6976afe9fe4dcda75faded3b8e759b137b9eb191c4e7c0400199315479ffd8d5e0b3e0d113a0e36fa21f25eeb93b74aedaa38b280285651a940aa2b07af75c14e5281b3240f0619e85476e48d1bc9610583bbeeda09a73d3886db916137f32ff035eb107eccbf0eea65b555f7c46b6d7401cc9de2d3646543d5c1115d46de56d500000000";
        let mit_buf = hex::decode(mit_ccache).expect("Failed to decode sample");

        let krime_ccache =
            FileCredentialCache::new(&name, &ticket, &kdc_reply, Some(Duration::new(0, 0)))
                .expect("Failed to create file credential cache");
        let mut c = std::io::Cursor::new(Vec::new());
        krime_ccache.write(&mut c).expect("Failed to write");
        let krime_buf = c.into_inner();

        assert_eq!(mit_buf.len(), krime_buf.len());

        /* Equal until beginning of keyblock */
        assert_eq!(&mit_buf[0..81], &krime_buf[0..81]);
    }

    #[tokio::test]
    async fn test_ccache_file_store() {
        let (name, ticket, kdc_reply) =
            crate::proto::get_tgt("testuser", "EXAMPLE.COM", "password")
                .await
                .expect("Failed to get ticket");

        let krime_ccache =
            FileCredentialCache::new(&name, &ticket, &kdc_reply, Some(Duration::new(0, 0)))
                .expect("Failed to create file credential cache");
        let path = "/tmp/krb5cc_krime";
        krime_ccache
            .store(Some(PathBuf::from(path)))
            .expect("Failed to write");

        let status = Command::new("klist")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .arg("-c")
            .arg(path)
            .status()
            .expect("Failed to klist");

        fs::remove_file(path).expect("Failed to rm ccache file");

        assert!(status.success());
    }
}
