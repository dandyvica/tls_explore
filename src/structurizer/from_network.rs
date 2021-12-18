// all methods for copying a structure like ClientHello as a bigendian buffer
use std::io::prelude::*;
use std::io::Cursor;
use std::io::{Error, ErrorKind, Result};

use byteorder::BigEndian;
use byteorder::ReadBytesExt;

use crate::alert::alert::AlertDescription;
use crate::alert::alert::AlertLevel;
use crate::enum_from_network_bytes;
use crate::handshake::client_hello::ExtensionType;
use crate::handshake::common::{ContentType, Random, VariableLengthVector};
use crate::handshake::handshake::HandshakeType;

pub trait TlsFromNetworkBytes {
    // copy structure data to a network-order buffer
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()>;
}

/// ```
/// use std::io::Cursor;
/// use tls_explore::structurizer::from_network::TlsFromNetworkBytes;
///
/// let mut buffer = Cursor::new(vec![0xFF]);
/// let mut v = 0u8;
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert_eq!(v, 255);
/// ```
impl TlsFromNetworkBytes for u8 {
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        *self = v.read_u8()?;
        Ok(())
    }
}

/// ```
/// use std::io::Cursor;
/// use tls_explore::structurizer::from_network::TlsFromNetworkBytes;
///
/// let mut buffer = Cursor::new(vec![0x12, 0x34]);
/// let mut v = 0u16;
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert_eq!(v, 0x1234);
/// ```
impl TlsFromNetworkBytes for u16 {
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        *self = v.read_u16::<BigEndian>()?;
        Ok(())
    }
}

/// ```
/// use std::io::Cursor;
/// use tls_explore::structurizer::from_network::TlsFromNetworkBytes;
///
/// let mut buffer = Cursor::new(vec![0x12, 0x34, 0x56, 0x78]);
/// let mut v = 0u32;
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert_eq!(v, 0x12345678);
/// ```
impl TlsFromNetworkBytes for u32 {
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        *self = v.read_u32::<BigEndian>()?;
        Ok(())
    }
}

/// ```
/// use std::io::Cursor;
/// use tls_explore::structurizer::from_network::TlsFromNetworkBytes;
///
/// let mut buffer = Cursor::new(vec![0x12, 0x34, 0x56, 0x78]);
/// let mut v = [0u8;4];
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert_eq!(v, [0x12_u8, 0x34, 0x56, 0x78]);
///
/// let mut buffer = Cursor::new(vec![0x12, 0x34, 0x56, 0x78]);
/// let mut v = [0u16;2];
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert_eq!(v, [0x1234_u16, 0x5678]);
/// ```
impl<T: TlsFromNetworkBytes, const N: usize> TlsFromNetworkBytes for [T; N] {
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        for x in self {
            x.from_network_bytes(v)?;
        }
        //v.read_exact(self)?;
        Ok(())
    }
}

enum_from_network_bytes!(ContentType, u8);
enum_from_network_bytes!(HandshakeType, u8);
enum_from_network_bytes!(AlertDescription, u8);
enum_from_network_bytes!(AlertLevel, u8);
enum_from_network_bytes!(ExtensionType, u16);

/// ```
/// use std::io::Cursor;
/// use tls_explore::structurizer::from_network::TlsFromNetworkBytes;
/// use tls_explore::handshake::common::Random;
///
/// let mut buffer = Cursor::new(vec![0xFF;32]);
/// let mut v = Random::default();
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert_eq!(v.gmt_unix_time, u32::MAX);
/// assert_eq!(v.random_bytes, [0xFF;28]);
/// ```
impl TlsFromNetworkBytes for Random {
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        self.gmt_unix_time = v.read_u32::<BigEndian>()?;
        v.read_exact(&mut self.random_bytes)?;
        Ok(())
    }
}

/// ```
/// use std::io::Cursor;
/// use tls_explore::structurizer::from_network::TlsFromNetworkBytes;
///
/// let mut buffer = Cursor::new(vec![0x12, 0x34, 0x56, 0x78]);
/// let mut v: Option<u32> = None;
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert!(v.is_none());
///
/// let mut buffer = Cursor::new(vec![0x12, 0x34, 0x56, 0x78]);
/// let mut v: Option<u32> = Some(0u32);
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert_eq!(v.unwrap(), 0x12345678);
/// ```
impl<T: TlsFromNetworkBytes> TlsFromNetworkBytes for Option<T> {
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        if self.is_none() {
            Ok(())
        } else {
            self.as_mut().unwrap().from_network_bytes(v)
        }
    }
}

/// ```
/// use std::io::Cursor;
/// use tls_explore::structurizer::from_network::TlsFromNetworkBytes;
/// use tls_explore::handshake::common::VariableLengthVector;
///
/// let mut buffer = Cursor::new(vec![0x03, 0x34, 0x56, 0x78]);
/// let mut v = VariableLengthVector::<u8, 1, 1>::default();
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert_eq!(v.length, 3u32);
/// assert_eq!(v.data, &[0x34, 0x56, 0x78]);
///
/// let mut buffer = Cursor::new(vec![0x00, 0x04, 0x12, 0x34, 0x56, 0x78]);
/// let mut v = VariableLengthVector::<u16, 1, 2>::default();
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert_eq!(v.length, 4u32);
/// assert_eq!(v.data, &[0x1234, 0x5678]);
/// ```
impl<T, const MIN: u8, const BYTES: u8> TlsFromNetworkBytes for VariableLengthVector<T, MIN, BYTES>
where
    T: Default + TlsFromNetworkBytes,
{
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        debug_assert!(BYTES <= 3);

        // convert u32 from u8/u16/u24 bytes, depending on BYTES value
        // BYTES can't be used yet in const constructs
        let mut buffer = [0u8; 4];

        // read BYTES bytes from cursor
        v.take(BYTES as u64).read(&mut buffer)?;

        // build a new buffer to be used with from_be_bytes()
        match BYTES {
            1 => buffer.rotate_right(3),
            2 => buffer.rotate_right(2),
            3 => buffer.rotate_right(1),
            _ => panic!("not a valid value for BYTES: <{}>", BYTES),
        }

        // convert to big endian
        self.length = u32::from_be_bytes(buffer);

        // the length field holds the length of data field in bytes
        let length = self.length / std::mem::size_of::<T>() as u32;
        println!("length={}", length);
        for _ in 0..length {
            let mut u: T = T::default();
            u.from_network_bytes(v)?;
            self.data.push(u);
        }
        Ok(())
    }
}

/// ```
/// use std::io::Cursor;
/// use tls_explore::structurizer::from_network::TlsFromNetworkBytes;
///
/// let mut buffer = Cursor::new(vec![0x12, 0x34, 0x56, 0x78]);
/// let mut v: Vec<u16> = Vec::new();
/// assert!(v.from_network_bytes(&mut buffer).is_ok());
/// assert_eq!(v, &[0x1234_u16, 0x5678]);
/// ```
impl<T: TlsFromNetworkBytes + Default> TlsFromNetworkBytes for Vec<T> {
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        // the length field holds the length of data field in bytes
        let length = v.get_ref().len() / std::mem::size_of::<T>();
        for _ in 0..length {
            let mut u: T = T::default();
            u.from_network_bytes(v)?;
            self.push(u);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tls_derive::TlsFromNetworkBytes;

    use super::*;

    #[test]
    fn from_network() {
        // simple struct
        #[derive(Default, TlsFromNetworkBytes)]
        struct A {
            x: u16,
            y: u16,
            z: [u8; 3],
        }

        let mut v = std::io::Cursor::new(vec![2, 5, 3, 0, 1, 2, 3]);
        let mut a = A::default();
        let _ = a.from_network_bytes(&mut v);
        assert_eq!(a.x, 517);
        assert_eq!(a.y, 768);
        assert_eq!(a.z, [1, 2, 3]);

        // fancier struct
        #[derive(Default, TlsFromNetworkBytes)]
        struct B {
            x: u16,
            y: u16,
            z: VariableLengthVector<[u8; 2], 0, 1>,
        }
        let mut v = std::io::Cursor::new(vec![2, 5, 3, 0, 10, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8]);
        let mut b = B::default();
        let _ = b.from_network_bytes(&mut v);
        assert_eq!(b.x, 517);
        assert_eq!(b.y, 768);
        assert_eq!(b.z.length, 10);
        assert_eq!(b.z.data.len(), 5);
    }
}
