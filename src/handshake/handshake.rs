use std::fmt::Debug;

// the global handshake structure as defined in https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.4
use crate::derive_tls::TlsDerive;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::common::{to_u24, CipherSuite};
use tls_derive::{TlsDerive, TlsEnum};

#[allow(unused_variables)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, TlsEnum)]
#[repr(u8)]
pub enum HandshakeType {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    certificate_url = 21,
    certificate_status = 22,
    // fake value to use it when creating a default
    fake = 255,
}

// the handshake by itself
#[derive(Debug, Default, TlsDerive)]
pub struct Handshake<T>
where
    T: Debug + TlsDerive,
{
    msg_type: HandshakeType,

    // length in bytes of the following data
    length: [u8; 3],
    body: T,
}

impl Handshake<ClientHello> {
    pub fn new(suites: &[CipherSuite]) -> Self {
        let ch = ClientHello::new(suites);

        Self {
            msg_type: HandshakeType::client_hello,
            length: to_u24(ch.tls_len() as u32),
            body: ch,
        }
    }
}
