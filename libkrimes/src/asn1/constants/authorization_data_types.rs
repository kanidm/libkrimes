use num_enum::{IntoPrimitive, TryFromPrimitive};

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive, PartialEq, Eq, Clone, Copy)]
#[repr(i32)]
pub enum AuthorizationDataType {
    AdIfRelevant = 1,
    AdWin2kPac = 128,
}
