use std::fmt::Debug;

// the global handshake structure as defined in https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.4
use crate::derive_tls::TlsDerive;
use crate::handshake::common::ContentType;
use tls_derive::TlsDerive;

use super::common::ProtocolVersion;

// https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.1
#[derive(Debug, Default, TlsDerive)]
pub struct RecordHeader {
    pub content_type: ContentType,
    pub version: ProtocolVersion,
    pub length: u16,
}

// the main structure which is exchanged between client and server
#[derive(Debug, Default, TlsDerive)]
pub struct RecordLayer<T>
where
    T: Debug + Default + TlsDerive,
{
    pub header: RecordHeader,
    pub data: T,
}

impl<T> RecordLayer<T>
where
    T: Debug + Default + TlsDerive,
{
    pub fn set_length(&mut self) {
        self.header.length = self.data.tls_len() as u16;
    }
}
