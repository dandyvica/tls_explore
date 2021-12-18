// server name indication: RFC 6066
use crate::handshake::common::VariableLengthVector;
use crate::structurizer::{
    from_network::TlsFromNetworkBytes, length::Length, to_network::TlsToNetworkBytes,
};
use tls_derive::{TlsFromNetworkBytes, TlsLength, TlsToNetworkBytes};

#[derive(Debug, Default, TlsLength, TlsToNetworkBytes, TlsFromNetworkBytes)]
pub struct ServerName {
    name_type: u8,
    name: VariableLengthVector<u16, u8, 1>,
}

#[derive(Debug, Default, TlsLength, TlsToNetworkBytes, TlsFromNetworkBytes)]
pub struct ServerNameList {
    server_name_list: VariableLengthVector<u16, ServerName, 1>,
}
