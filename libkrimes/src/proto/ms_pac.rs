// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962

pub struct AdWin2kPac {}

// I think this is a raw binary structure, not asn.1.
impl AdWin2kPac {
    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::default()
    }
}

// pub struct AdWin2kPacBuilder {}
