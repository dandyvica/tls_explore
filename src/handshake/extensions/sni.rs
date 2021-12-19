// server name indication: RFC 6066
use crate::handshake::common::VariableLengthVector;
use crate::tls_derive::TlsDerive;
use tls_derive::{TlsDerive};

#[derive(Debug, Default, TlsDerive)]
pub struct ServerName {
    name_type: u8,
    name: VariableLengthVector<u16, u8, 1>,
}

#[derive(Debug, Default, TlsDerive)]
pub struct ServerNameList {
    server_name_list: VariableLengthVector<u16, ServerName, 1>,
}
