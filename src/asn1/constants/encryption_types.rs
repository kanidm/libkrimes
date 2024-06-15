use num_enum::{IntoPrimitive, TryFromPrimitive};

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(i32)]
pub enum EncryptionType {
    DES_CBC_CRC = 1,
    DES_CBC_MD4 = 2,
    DES_CBC_MD5 = 3,
    DES3_CBC_MD5 = 5,
    DES3_CBC_SHA1 = 7,
    // PKINIT
    DSA_SHA1_CMS = 9,
    MD5_RSA_CMS = 10,
    SHA1_RSA_CMS = 11,
    RC2_CBC_ENV = 12,
    RSA_ENV = 13,
    RSA_ES_OAEP_ENV = 14,
    DES3_CBC_ENV = 15,

    DES3_CBC_SHA1_KD = 16,
    AES128_CTS_HMAC_SHA1_96 = 17,
    AES256_CTS_HMAC_SHA1_96 = 18,
    AES128_CTS_HMAC_SHA256_128 = 19,
    AES256_CTS_HMAC_SHA384_192 = 20,
    RC4_HMAC = 23,
    RC4_HMAC_EXP = 24,
    CAMELLIA128_CTS_CMAC = 25,
    CAMELLIA256_CTS_CMAC = 26,
}
