// the definition of the client_hello structure as defined in https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.4
//use std::io::Result;

use crate::ext_type;
use crate::handshake::common::{
    CipherSuite, CompressionMethod, ProtocolVersion, Random, SessionID, VariableLengthVector,
};
use crate::handshake::constants::*;
use crate::structurizer::{
    from_network::TlsFromNetworkBytes, length::TlsLength, to_network::TlsToNetworkBytes,
};
use tls_derive::{TlsEnum, TlsFromNetworkBytes, TlsLength, TlsToNetworkBytes};

//
#[derive(Debug, Default, TlsLength, TlsToNetworkBytes, TlsFromNetworkBytes)]
pub struct ClientHello {
    client_version: ProtocolVersion,
    random: Random,
    session_id: SessionID,
    cipher_suites: VariableLengthVector<CipherSuite, 2, 2>,
    compression_methods: VariableLengthVector<CompressionMethod, 1, 1>,
    extensions: Option<VariableLengthVector<GenericExtension, 0, 2>>,
}

impl ClientHello {
    // create a new ClientHello without any extension
    pub fn new(suites: &[CipherSuite]) -> Self {
        Self {
            client_version: TLS12,
            random: Random::new(),
            session_id: rand::random(),
            cipher_suites: VariableLengthVector {
                length: 2,
                data: suites.to_vec().clone(),
            },
            compression_methods: VariableLengthVector {
                length: 1,
                data: vec![0u8],
            },
            extensions: None,
        }
    }

    // add any type of extension
    // pub fn add_extension<T: TlsToNetworkBytes + ExtType>(
    //     &mut self,
    //     extension: T,
    // ) -> std::io::Result<()> {
    //     // init a vector for converting to Vec<u8> and convert the extension
    //     let mut v = Vec::new();
    //     extension.to_network_bytes(&mut v)?;

    //     // init extensions field if not already existing
    //     // if self.extensions.is_none() {
    //     //     self.extensions = Some(VariableLengthVector::new(0, None));
    //     // }
    //     let ext = Extension {
    //         extension_type: extension.extension_type(),
    //         extension_data: VariableLengthVector::<u16, u8, 0>::new(0, Some(&v)),
    //     };

    //     self.push_extension(ext);

    //     Ok(())
    // }

    // fn push_extension(&mut self, extension: GenericExtension) {
    //     // if no extension yet, create a new vec with the extension argument
    //     if self.extensions.is_none() {
    //         self.extensions = Some(VariableLengthVector {
    //             length: extension.tls_len() as u16,
    //             data: vec![extension],
    //         });
    //     } else {
    //         let x = self.extensions.as_mut().unwrap();
    //         x.length = extension.tls_len() as u16;
    //         x.data.push(extension);
    //     }
    // }
}

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
pub trait ExtType {
    fn extension_type(&self) -> ExtensionType;
}

// extensions as described in https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4
#[derive(Debug, Default, TlsLength, TlsToNetworkBytes, TlsFromNetworkBytes)]
pub struct GenericExtension {
    extension_type: ExtensionType,
    extension_data: VariableLengthVector<u8, 0, 2>,
    //extension_data: VariableLengthVector<u16, Box<dyn TlsToNetworkBytes>, 0>,
}

impl GenericExtension {
    pub fn from_extension<T: TlsToNetworkBytes + ExtType>(extension: &T) -> std::io::Result<Self> {
        // get type from trait's method
        let extension_type = extension.extension_type();

        // convert ext structure of type T to network bytes
        let mut v = Vec::new();
        extension.to_network_bytes(&mut v)?;

        Ok(Self {
            extension_type: extension_type,
            extension_data: VariableLengthVector::from_slice(&v),
        })
    }
}

// SNI extension
#[derive(Debug, Default, TlsLength, TlsToNetworkBytes, TlsFromNetworkBytes)]
pub struct ServerNameList {
    length: u16,
    host_name_type: u8,
    host_name_length: u16,
    host_name: Vec<u8>,
}

impl ServerNameList {
    pub fn new(host_name: &str) -> Self {
        let length = host_name.len();

        Self {
            length: (length + 3) as u16,
            host_name_type: 0,
            host_name_length: length as u16,
            host_name: host_name.as_bytes().to_vec(),
        }
    }
}

ext_type!(ServerNameList, server_name);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_ch() {
        let ch = ClientHello::new(&vec![TLS_DHE_RSA_WITH_AES_256_CBC_SHA]);

        assert_eq!(ch.tls_len(), 2 + 32 + 32 + 2 + 2 + 1 + 1);
    }

    #[test]
    fn sni() {
        let sni = ServerNameList::new("example.ulfheim.net");
        assert_eq!(sni.length, 22);
        assert_eq!(sni.host_name_type, 0);
        assert_eq!(sni.host_name_length, 19);
        assert_eq!(
            sni.host_name,
            &[
                0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69,
                0x6d, 0x2e, 0x6e, 0x65, 0x74
            ]
        );

        let ext = GenericExtension::from_extension(&sni).unwrap();

        //assert_eq!(ext.extension_type, ExtensionType::server_name);
        //assert_eq!(ext.extension_data.data, &[0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74]);
    }

    //#[test]
    fn from_network() {
        let mut ch = ClientHello::default();
        let mut v = std::io::Cursor::new(vec![
            0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xcc, 0xa8,
            0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x09,
            0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12,
            0x00, 0x0a, 0x01, 0x00,
        ]);
        let _ = ch.from_network_bytes(&mut v);
        assert_eq!(ch.client_version, [0x03, 0x03]);
        assert_eq!(
            ch.random.random_bytes,
            [
                0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
                0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            ]
        );
        assert_eq!(ch.session_id, [0u8; 32]);
        assert_eq!(ch.cipher_suites.length, 32);

        let mut iter = ch.cipher_suites.data.iter();
        assert_eq!(
            iter.next().unwrap(),
            &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        );

        assert_eq!(
            iter.next().unwrap(),
            &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        );
        assert_eq!(iter.next().unwrap(), &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        assert_eq!(iter.next().unwrap(), &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        assert_eq!(
            iter.next().unwrap(),
            &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        );
        assert_eq!(
            iter.next().unwrap(),
            &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        );
        assert_eq!(iter.next().unwrap(), &TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        assert_eq!(iter.next().unwrap(), &TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        assert_eq!(iter.next().unwrap(), &TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        assert_eq!(iter.next().unwrap(), &TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
        assert_eq!(iter.next().unwrap(), &TLS_RSA_WITH_AES_128_GCM_SHA256);
        assert_eq!(iter.next().unwrap(), &TLS_RSA_WITH_AES_256_GCM_SHA384);
        assert_eq!(iter.next().unwrap(), &TLS_RSA_WITH_AES_128_CBC_SHA);
        assert_eq!(iter.next().unwrap(), &TLS_RSA_WITH_AES_256_CBC_SHA);
        assert_eq!(iter.next().unwrap(), &TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
        assert_eq!(iter.next().unwrap(), &TLS_RSA_WITH_3DES_EDE_CBC_SHA);

        assert_eq!(ch.compression_methods.length, 1);
        assert_eq!(ch.compression_methods.data, [0u8]);
    }
}
