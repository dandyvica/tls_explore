use std::io::prelude::*;
use std::io::Cursor;
use std::io::Result;

// all methods for copying a structure like ClientHello as a bigendian buffer
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::alert::alert::{AlertDescription, AlertLevel};
use crate::handshake::client_hello::ExtensionType;
use crate::handshake::common::{ContentType, Random, VariableLengthVector};
use crate::handshake::handshake::HandshakeType;

use crate::{enum_from_network_bytes, enum_length, enum_to_network_bytes};

// functions to convert or build TLS structures
pub trait TlsDerive {
    // give the length of the type when converted to [u8]
    fn tls_len(&self) -> usize;

    // copy structure data to a network-order buffer
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> std::io::Result<usize>;

    // copy structure data from a network-order buffer
    fn from_network_bytes(&mut self, v: &mut std::io::Cursor<Vec<u8>>) -> std::io::Result<()>;
}

impl TlsDerive for u8 {
    enum_length!(u8);

    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(255_u8.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0xFF]);
    /// ```    
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        v.write_u8(*self)?;
        Ok(1)
    }

    /// ```
    /// use std::io::Cursor;
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer = Cursor::new(vec![0xFF]);
    /// let mut v = 0u8;
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, 255);
    /// ```
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        *self = v.read_u8()?;
        Ok(())
    }
}

impl TlsDerive for u16 {
    enum_length!(u16);

    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x1234_u16.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34]);
    /// ```   
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        v.write_u16::<BigEndian>(*self)?;
        Ok(2)
    }

    /// ```
    /// use std::io::Cursor;
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer = Cursor::new(vec![0x12, 0x34]);
    /// let mut v = 0u16;
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, 0x1234);
    /// ```
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        *self = v.read_u16::<BigEndian>()?;
        Ok(())
    }
}

impl TlsDerive for u32 {
    enum_length!(u32);

    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(0x12345678_u32.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```    
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        v.write_u32::<BigEndian>(*self)?;
        Ok(4)
    }
    /// ```
    /// use std::io::Cursor;
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer = Cursor::new(vec![0x12, 0x34, 0x56, 0x78]);
    /// let mut v = 0u32;
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, 0x12345678);
    /// ```
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        *self = v.read_u32::<BigEndian>()?;
        Ok(())
    }
}

impl TlsDerive for [u8] {
    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let v = [0u8;10];
    /// assert_eq!(v.tls_len(), 10);
    /// ```
    fn tls_len(&self) -> usize {
        self.len()
    }

    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert!(&[0x12_u8, 0x34, 0x56, 0x78].to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0x12, 0x34, 0x56, 0x78]);
    /// ```
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        v.append(&mut self.to_vec());
        Ok(self.len())
    }

    fn from_network_bytes(&mut self, _v: &mut Cursor<Vec<u8>>) -> Result<()> {
        Ok(())
    }
}

impl<T: TlsDerive, const N: usize> TlsDerive for [T; N] {
    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let v = [0u8;10];
    /// assert_eq!(v.tls_len(), 10);
    /// ```
    fn tls_len(&self) -> usize {
        N * std::mem::size_of::<T>()
    }
    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert_eq!([0xFFFF_u16; 10].to_network_bytes(&mut buffer).unwrap(), 20);
    /// assert_eq!(buffer, &[0xFF; 20]);
    /// ```    
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        let mut length = 0usize;

        for x in self {
            // first convert x to network bytes
            let mut buffer: Vec<u8> = Vec::new();
            length += x.to_network_bytes(&mut buffer)?;

            v.append(&mut buffer);
        }
        //v.append(&mut self.to_vec());
        Ok(length)
    }

    /// ```
    /// use std::io::Cursor;
    /// use tls_explore::derive_tls::TlsDerive;
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
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        for x in self {
            x.from_network_bytes(v)?;
        }
        //v.read_exact(self)?;
        Ok(())
    }
}

impl TlsDerive for Random {
    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    /// use tls_explore::handshake::common::Random;
    ///
    /// let v = Random::new();
    /// assert_eq!(v.tls_len(), 32);
    /// ```
    fn tls_len(&self) -> usize {
        4 + 28
    }

    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    /// use tls_explore::handshake::common::Random;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let mut r = Random::new();
    /// r.gmt_unix_time = 0xFFFFFFFF_u32;
    /// r.random_bytes = [0xFF; 28];
    /// assert!(r.to_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(buffer, &[0xFF; 32]);
    /// ```    
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        v.write_u32::<BigEndian>(self.gmt_unix_time)?;
        v.append(&mut self.random_bytes.to_vec());
        Ok(32)
    }
    /// ```
    /// use std::io::Cursor;
    /// use tls_explore::derive_tls::TlsDerive;
    /// use tls_explore::handshake::common::Random;
    ///
    /// let mut buffer = Cursor::new(vec![0xFF;32]);
    /// let mut v = Random::default();
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v.gmt_unix_time, u32::MAX);
    /// assert_eq!(v.random_bytes, [0xFF;28]);
    /// ```
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        self.gmt_unix_time = v.read_u32::<BigEndian>()?;
        v.read_exact(&mut self.random_bytes)?;
        Ok(())
    }
}

impl TlsDerive for ContentType {
    enum_length!(ContentType);
    enum_to_network_bytes!(ContentType);
    enum_from_network_bytes!(ContentType, u8);
}

impl TlsDerive for HandshakeType {
    enum_length!(HandshakeType);
    enum_to_network_bytes!(HandshakeType);
    enum_from_network_bytes!(HandshakeType, u8);
}

impl TlsDerive for AlertDescription {
    enum_length!(AlertDescription);
    enum_to_network_bytes!(AlertDescription);
    enum_from_network_bytes!(AlertDescription, u8);
}

impl TlsDerive for AlertLevel {
    enum_length!(AlertLevel);
    enum_to_network_bytes!(AlertLevel);
    enum_from_network_bytes!(AlertLevel, u8);
}

impl TlsDerive for ExtensionType {
    enum_length!(ExtensionType);
    enum_to_network_bytes!(ExtensionType);
    enum_from_network_bytes!(ExtensionType, u8);
}

impl<T: TlsDerive> TlsDerive for Option<T> {
    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// assert_eq!(Some(0xFF_u8).tls_len(), 1);
   ///
    /// let r: Option<u8> = None;
    /// assert_eq!(r.tls_len(), 0);
    /// ```     
    fn tls_len(&self) -> usize {
        if self.is_none() {
            0
        } else {
            self.as_ref().unwrap().tls_len()
        }
    }

    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// assert_eq!(Some(0xFF_u8).to_network_bytes(&mut buffer).unwrap(), 1);
    /// assert_eq!(buffer, &[0xFF]);
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let r: Option<u8> = None;
    /// assert_eq!(r.to_network_bytes(&mut buffer).unwrap(), 0);
    /// assert!(buffer.is_empty());
    /// ```    
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        if self.is_none() {
            Ok(0)
        } else {
            self.as_ref().unwrap().to_network_bytes(v)
        }
    }

    /// ```
    /// use std::io::Cursor;
    /// use tls_explore::derive_tls::TlsDerive;
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
    fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
        if self.is_none() {
            Ok(())
        } else {
            self.as_mut().unwrap().from_network_bytes(v)
        }
    }
}

impl<T, const MIN: u8, const BYTES: u8> TlsDerive for VariableLengthVector<T, MIN, BYTES>
where
    T: Default + TlsDerive,
{
    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    /// use tls_explore::handshake::common::VariableLengthVector;
    ///
    /// let v: VariableLengthVector<[u16;3], 1, 2> = VariableLengthVector::from_slice(&[[0xFFFF;3],[0xFFFF;3],[0xFFFF;3]]);
    /// assert_eq!(v.tls_len(), 2+3*2*3);
    /// ```
    fn tls_len(&self) -> usize {
        BYTES as usize + self.data.len() * std::mem::size_of::<T>()
    }

    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    /// use tls_explore::handshake::common::VariableLengthVector;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let v: VariableLengthVector<[u16;3], 1, 2> = VariableLengthVector::from_slice(&[[0xFFFF;3],[0xFFFF;3],[0xFFFF;3]]);
    /// assert_eq!(v.to_network_bytes(&mut buffer).unwrap(), 20);
    /// assert_eq!(&buffer[2..], &[0xFF; 18]);
    /// assert_eq!(&buffer[0..2], &[0, 18]);
    /// ```    
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        // convert u32 to u8/u16/u24 bytes, depending on BYTES value
        to_ubytes(BYTES, self.length, v)?;

        // need to calculate length of the converted struct to return it
        let mut length = 0usize;

        // copy data for each element
        for item in &self.data {
            length += item.to_network_bytes(v)?;
        }

        Ok(length + BYTES as usize)
    }

    /// ```
    /// use std::io::Cursor;
    /// use tls_explore::derive_tls::TlsDerive;
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

impl<T> TlsDerive for Vec<T>
where
    T: Default + TlsDerive,
{
    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let v: Vec<[u16;3]> = vec![[0xFFFF;3],[0xFFFF;3],[0xFFFF;3]];
    /// assert_eq!(v.tls_len(), 3*2*3);
    /// ```
    fn tls_len(&self) -> usize {
        self.len() * std::mem::size_of::<T>()
    }

    /// ```
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer: Vec<u8> = Vec::new();
    /// let v = vec![[0xFFFF_u16;3],[0xFFFF;3],[0xFFFF;3]];
    /// assert_eq!(v.to_network_bytes(&mut buffer).unwrap(), 18);
    /// assert_eq!(&buffer, &[0xFF; 18]);
    /// ```    
    fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
        let mut length = 0usize;

        // copy data for each element
        for item in self {
            length += item.to_network_bytes(v)?;
        }

        Ok(length)
    }

    /// ```
    /// use std::io::Cursor;
    /// use tls_explore::derive_tls::TlsDerive;
    ///
    /// let mut buffer = Cursor::new(vec![0x12, 0x34, 0x56, 0x78]);
    /// let mut v: Vec<u16> = Vec::new();
    /// assert!(v.from_network_bytes(&mut buffer).is_ok());
    /// assert_eq!(v, &[0x1234_u16, 0x5678]);
    /// ```
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

/// ```
    /// use tls_explore::derive_tls::TlsDerive;
/// use tls_explore::handshake::common::VariableLengthVector;
/// use tls_derive::TlsDerive;
///
/// let mut vlv: VariableLengthVector<Box<dyn TlsDerive>, 1, 2> = VariableLengthVector::default();
///
/// #[derive(TlsDerive)] struct A { x: u16, y: u16 }
/// #[derive(TlsDerive)] struct B { a: Option<[u16;3]>, b: Vec<u16> }
///
/// vlv = VariableLengthVector {
///     length: 0,  
///     data: vec! [
///         Box::new(A { x: 0x1234, y: 0x5678 }),
///         Box::new(B { a: Some([0x1234, 0x5678, 0x9ABC]), b: vec![0x1234, 0x5678] })
///     ]
/// }
///
/// ```
// impl<const MIN: u8, const BYTES: u8> TlsDerive
//     for VariableLengthVector<Box<dyn TlsDerive>, MIN, BYTES>
// {
//     fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
//         // convert u32 to u8/u16/u24 bytes, depending on BYTES value
//         to_ubytes(BYTES, self.length, v)?;

//         // need to calculate length of the converted struct to return it
//         let length = 0usize;

//         for x in &self.data {
//             x.to_network_bytes(v)?;
//         }

//         Ok(length + BYTES as usize)
//     }
// }

// convert a u8/u16/u24 to u32 bigendian
fn to_ubytes<T: Into<u32> + std::fmt::Debug>(x: T, length: u32, v: &mut Vec<u8>) -> Result<()> {
    let buffer = length.to_be_bytes();

    // convert value to u32
    let conv = x.into();
    match conv {
        1 => &buffer[3..4].to_network_bytes(v)?,
        2 => &buffer[2..4].to_network_bytes(v)?,
        3 => &buffer[1..4].to_network_bytes(v)?,
        _ => panic!("not a valid value for BYTES: <{:?}>", conv),
    };

    Ok(())
}
