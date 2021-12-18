// the definition of the client_hello structure as defined in https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.4
use std::io::Result;

use tls_derive::{TlsEnum, TlsFromNetworkBytes, TlsLength, TlsToNetworkBytes};

use crate::{ext_type};
use crate::handshake::common::VariableLengthVector;
use crate::structurizer::{
    from_network::TlsFromNetworkBytes, length::Length, to_network::TlsToNetworkBytes,
};


#[allow(unused_variables)]
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, TlsEnum)]
#[repr(u16)]
pub enum ExtensionType {
    server_name = 0,
    max_fragment_length = 1,
    client_certificate_url = 2,
    trusted_ca_keys = 3,
    truncated_hmac = 4,
    status_request = 5,
    signature_algorithms = 13,
}

// this trait is used fro the add() method, to make it more generic
trait ExtType {
    fn extension_type(&self) -> ExtensionType;
}

// extensions as described in https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4
#[derive(Debug, Default, TlsLength, TlsToNetworkBytes, TlsFromNetworkBytes)]
pub struct Extension {
    extension_type: ExtensionType,
    extension_data: VariableLengthVector<u16, u8, 0>,
}

impl Extension {
    pub fn add<T: TlsToNetworkBytes>(ext: T) -> Result<()> {
        // convert ext structure of type T to network bytes
        let mut v = Vec::new();
        ext.to_network_bytes(&mut v)?;
        
        
    }
}


// SNI extension
#[derive(Debug, Default, TlsLength, TlsToNetworkBytes, TlsFromNetworkBytes)]
pub struct ServerName {
    host_name_type: u8,
    host_name: VariableLengthVector<u16, u8, 1>,
}

pub type ServerNameList = VariableLengthVector<u16, ServerName, 1>;

ext_type!(ServerName, server_name);



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni() {

    }
}
