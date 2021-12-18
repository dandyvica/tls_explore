use std::io::Result;

// all methods for copying a structure like ClientHello as a bigendian buffer
use byteorder::{BigEndian, WriteBytesExt};

use crate::alert::alert::{AlertDescription, AlertLevel};
use crate::enum_to_network_bytes;
use crate::handshake::client_hello::ExtensionType;
use crate::handshake::common::{ContentType, Random, VariableLengthVector};
use crate::handshake::handshake::HandshakeType;

pub trait TlsToNetworkBytes {
    // copy structure data to a network-order buffer
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()>;
}

/// ```
/// use tls_explore::structurizer::to_network::TlsToNetworkBytes;
///
/// let mut buffer: Vec<u8> = Vec::new();
/// assert!(255_u8.to_network_bytes(&mut buffer).is_ok());
/// assert_eq!(buffer, &[0xFF]);
/// ```
impl TlsToNetworkBytes for u8 {
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
        v.write_u8(*self)
    }
}

/// ```
/// use tls_explore::structurizer::to_network::TlsToNetworkBytes;
///
/// let mut buffer: Vec<u8> = Vec::new();
/// assert!(0x00FF_u16.to_network_bytes(&mut buffer).is_ok());
/// assert_eq!(buffer, &[0x00, 0xFF]);
/// ```
impl TlsToNetworkBytes for u16 {
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
        v.write_u16::<BigEndian>(*self)
    }
}

/// ```
/// use tls_explore::structurizer::to_network::TlsToNetworkBytes;
///
/// let mut buffer: Vec<u8> = Vec::new();
/// assert!(0x00FF00FF_u32.to_network_bytes(&mut buffer).is_ok());
/// assert_eq!(buffer, &[0x00, 0xFF, 0x00, 0xFF]);
/// ```
impl TlsToNetworkBytes for u32 {
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
        v.write_u32::<BigEndian>(*self)
    }
}

/// ```
/// use tls_explore::structurizer::to_network::TlsToNetworkBytes;
///
/// let mut buffer: Vec<u8> = Vec::new();
/// assert!(&[0x00_u8, 0xFF, 0x00, 0xFF].to_network_bytes(&mut buffer).is_ok());
/// assert_eq!(buffer, &[0x00, 0xFF, 0x00, 0xFF]);
/// ```
impl TlsToNetworkBytes for [u8] {
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
        v.append(&mut self.to_vec());
        Ok(())
    }
}

/// ```
/// use tls_explore::structurizer::to_network::TlsToNetworkBytes;
///
/// let mut buffer: Vec<u8> = Vec::new();
/// assert!([0xFFFF_u16; 10].to_network_bytes(&mut buffer).is_ok());
/// assert_eq!(buffer, &[0xFF; 20]);
/// ```
impl<T: TlsToNetworkBytes, const N: usize> TlsToNetworkBytes for [T; N] {
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
        for x in self {
            // first convert x to network bytes
            let mut buffer: Vec<u8> = Vec::new();
            x.to_network_bytes(&mut buffer)?;

            v.append(&mut buffer);
        }
        //v.append(&mut self.to_vec());
        Ok(())
    }
}

enum_to_network_bytes!(ContentType);
enum_to_network_bytes!(HandshakeType);
enum_to_network_bytes!(AlertLevel);
enum_to_network_bytes!(AlertDescription);
enum_to_network_bytes!(ExtensionType);

/// ```
/// use tls_explore::structurizer::to_network::TlsToNetworkBytes;
/// use tls_explore::handshake::common::Random;
///
/// let mut buffer: Vec<u8> = Vec::new();
/// let mut r = Random::new();
/// r.gmt_unix_time = 0xFFFFFFFF_u32;
/// r.random_bytes = [0xFF; 28];
/// assert!(r.to_network_bytes(&mut buffer).is_ok());
/// assert_eq!(buffer, &[0xFF; 32]);
/// ```
impl TlsToNetworkBytes for Random {
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
        v.write_u32::<BigEndian>(self.gmt_unix_time)?;
        v.append(&mut self.random_bytes.to_vec());
        Ok(())
    }
}

/// ```
/// use tls_explore::structurizer::to_network::TlsToNetworkBytes;
///
/// let mut buffer: Vec<u8> = Vec::new();
/// assert!(Some(0xFF_u8).to_network_bytes(&mut buffer).is_ok());
/// assert_eq!(buffer, &[0xFF]);
///
/// let mut buffer: Vec<u8> = Vec::new();
/// let r: Option<u8> = None;
/// assert!(r.to_network_bytes(&mut buffer).is_ok());
/// assert!(buffer.is_empty());
/// ```
impl<T: TlsToNetworkBytes> TlsToNetworkBytes for Option<T> {
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
        if self.is_none() {
            Ok(())
        } else {
            self.as_ref().unwrap().to_network_bytes(v)
        }
    }
}

// pub trait VariableData {
//     fn copy_data(&self, v: &mut Vec<u8>) -> Result<()>;
// }

// impl<const N: usize> VariableData for [u8; N] {
//     fn copy_data(&self, v: &mut Vec<u8>) -> Result<()> {
//         v.extend_from_slice(self);
//         Ok(())
//     }
// }

// impl VariableData for u8 {
//     fn copy_data(&self, v: &mut Vec<u8>) -> Result<()> {
//         v.write_u8(*self)
//     }
// }

/// ```
/// use tls_explore::structurizer::to_network::TlsToNetworkBytes;
/// use tls_explore::handshake::common::VariableLengthVector;
///
/// let mut buffer: Vec<u8> = Vec::new();
/// let v: VariableLengthVector<[u16;3], 1, 2> = VariableLengthVector::from_slice(&[[0xFFFF;3],[0xFFFF;3],[0xFFFF;3]]);
/// assert!(v.to_network_bytes(&mut buffer).is_ok());
/// assert_eq!(&buffer[2..], &[0xFF; 18]);
/// assert_eq!(&buffer[0..2], &[0, 18]);
/// ```
impl<T: TlsToNetworkBytes, const MIN: u8, const BYTES: u8> TlsToNetworkBytes
    for VariableLengthVector<T, MIN, BYTES>
{
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
        // convert u32 to u8/u16/u24 bytes, depending on BYTES value
        let buffer = self.length.to_be_bytes();

        match BYTES {
            1 => &buffer[3..4].to_network_bytes(v)?,
            2 => &buffer[2..4].to_network_bytes(v)?,
            3 => &buffer[1..4].to_network_bytes(v)?,
            _ => panic!("not a valid value for BYTES: <{}>", BYTES),
        };

        //self.length.to_network_bytes(v)?;

        // copy data for each element
        Ok(for item in &self.data {
            item.to_network_bytes(v)?;
        })
    }
}

/// ```
/// use tls_explore::structurizer::to_network::TlsToNetworkBytes;
///
/// let mut buffer: Vec<u8> = Vec::new();
/// let v = vec![[0xFFFF_u16;3],[0xFFFF;3],[0xFFFF;3]];
/// assert!(v.to_network_bytes(&mut buffer).is_ok());
/// assert_eq!(&buffer, &[0xFF; 18]);
/// ```
impl<T: TlsToNetworkBytes> TlsToNetworkBytes for Vec<T> {
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
        // copy data for each element
        Ok(for item in self {
            item.to_network_bytes(v)?;
        })
    }
}

// impl TlsToNetworkBytes for Vec<Box<dyn TlsToNetworkBytes>> {
//     fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
//         // copy data for each element
//         Ok(for item in self {
//             item.to_network_bytes(v)?;
//         })
//     }
// }

impl<const MIN: u8, const BYTES: u8> TlsToNetworkBytes
    for VariableLengthVector<Box<dyn TlsToNetworkBytes>, MIN, BYTES>
{
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<()> {
        for x in &self.data {
            x.to_network_bytes(v)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tls_derive::TlsToNetworkBytes;

    use super::*;

    #[test]
    fn to_network_bytes() {
        #[derive(TlsToNetworkBytes)]
        struct A {
            a: u16,
            b: u8,
        }
        let a = A { a: 0x00FF, b: 0x20 };
        let mut v = Vec::new();
        let mut f = a.to_network_bytes(&mut v);
        assert!(f.is_ok());
        assert_eq!(v, [0x00, 0xFF, 0x20]);

        #[derive(TlsToNetworkBytes)]
        struct B {
            a: u16,
            b: [u8; 3],
        }
        let b = B {
            a: 0x00FF,
            b: [1u8, 2, 3],
        };
        v.clear();
        f = b.to_network_bytes(&mut v);
        assert!(f.is_ok());
        assert_eq!(v, [0, 255, 1, 2, 3]);

        #[derive(TlsToNetworkBytes)]
        struct C {
            a: u16,
            d: VariableLengthVector<[u8; 2], 0, 1>,
        }
        let c = C {
            a: 0x00FF,
            d: VariableLengthVector {
                length: 4,
                data: vec![[0; 2], [1; 2]],
            },
        };
        v.clear();
        f = c.to_network_bytes(&mut v);
        assert!(f.is_ok());
        assert_eq!(v, [0, 255, 4, 0, 0, 1, 1]);

        #[derive(TlsToNetworkBytes)]
        struct D {
            a: u16,
            d: Vec<Box<dyn TlsToNetworkBytes>>,
        }
    }
}