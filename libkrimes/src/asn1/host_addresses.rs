use super::host_address::HostAddress;

/// ```text
/// HostAddresses   ::= SEQUENCE OF HostAddress
/// ````
pub(crate) type HostAddresses = Vec<HostAddress>;
