mod kt_file;

use crate::error::KrbError;
use crate::proto::{DerivedKey, Name};
use std::env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeytabEntry {
    pub principal: Name,
    pub key: DerivedKey,
    pub timestamp: u32,
}

pub type Keytab = Vec<KeytabEntry>;

fn parse_keytab_name(kt_name: Option<&str>) -> String {
    match kt_name {
        Some(c) => c.to_string(),
        None => match env::var("DEFKTNAME") {
            Ok(val) => val,
            _ => "FILE:/etc/krb5.keytab".to_string(),
        },
    }
}

pub fn store(kt_name: Option<&str>, kt: &Keytab) -> Result<(), KrbError> {
    let kt_name = parse_keytab_name(kt_name);
    if kt_name.starts_with("FILE:") {
        return kt_file::store(&kt_name, kt);
    }
    Err(KrbError::UnsupportedKeytabType)
}

pub fn load(kt_name: Option<&str>) -> Result<Keytab, KrbError> {
    let kt_name = parse_keytab_name(kt_name);
    if kt_name.starts_with("FILE:") {
        return kt_file::load(&kt_name);
    }
    Err(KrbError::UnsupportedKeytabType)
}
