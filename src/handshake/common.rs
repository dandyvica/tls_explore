use std::mem;
use std::time::SystemTime;

use tls_derive::TlsEnum;

//use crate::{enum_default, enum_to_u8};

// common structures for TLS handshake
#[allow(unused_variables)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, TlsEnum)]
#[repr(u8)]
pub enum ContentType {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    fake = 255,
}

// enum_default!(ContentType, fake);
// enum_to_u8!(ContentType);

// impl TryFrom<u8> for ContentType {
//     type Error = String;

//     fn try_from(value: u8) -> Result<Self, Self::Error> {
//         match value {
//             20 => Ok(ContentType::change_cipher_spec),
//             21 => Ok(ContentType::alert),
//             22 => Ok(ContentType::handshake),
//             23 => Ok(ContentType::application_data),
//             _ => Err(format!("error converting <{}> to ContentType", value)),
//         }
//     }
// }

// Protocol version
pub type ProtocolVersion = [u8; 2];

// Random struct
#[derive(Debug, Default)]
pub struct Random {
    pub gmt_unix_time: u32,
    pub random_bytes: [u8; 28],
}

impl Random {
    pub fn new() -> Self {
        // calculate duration since EPOCH
        let since_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        Self {
            gmt_unix_time: since_epoch.as_secs() as u32,
            random_bytes: rand::random(),
        }
    }

    pub fn fixed() -> Self {
        Self {
            gmt_unix_time: 0,
            random_bytes: [0xFF; 28],
        }
    }
}

// SessionID => always fixed
pub type SessionID = [u8; 32];

// variable lenght vectors contain a length and an array: https://datatracker.ietf.org/doc/html/rfc5246#section-4.3
#[derive(Debug, Default)]
pub struct VariableLengthVector<T, const MIN: u8, const BYTES: u8> {
    pub length: u32,
    pub data: Vec<T>,
}

impl<T, const MIN: u8, const BYTES: u8> VariableLengthVector<T, MIN, BYTES>
where
    T: Clone,
{
    // pub fn new() -> Self {
    //     VariableLengthVector {
    //         length: 0,
    //         data: Vec::new(),
    //     }
    // }

    pub fn from_slice(data: &[T]) -> Self {
        // check the minimum length
        //debug_assert!(N <= data.unwrap().len(), "wrong number of elements");

        VariableLengthVector {
            length: (data.len() * mem::size_of::<T>()) as u32,
            data: data.to_vec(),
        }
    }
}

use crate::derive_tls::TlsDerive;
impl<const MIN: u8, const BYTES: u8> std::default::Default
    for VariableLengthVector<Box<dyn TlsDerive>, MIN, BYTES>
{
    fn default() -> Self {
        Self {
            length: 0,
            data: Vec::new(),
        }
    }
}
impl<const MIN: u8, const BYTES: u8> VariableLengthVector<Box<dyn TlsDerive>, MIN, BYTES> {
    fn push(&mut self, elem: Box<dyn TlsDerive>) {
        self.length += elem.tls_len() as u32;
        self.data.push(elem);
    }
}

// cipher suites are just an array of 2 bytes
pub type CipherSuite = [u8; 2];

// compression methods = one byte
pub type CompressionMethod = u8;

// a specific u24 = 3 bytes integer
pub fn to_u24(n: u32) -> [u8; 3] {
    let mut a: [u8; 3] = [0; 3];

    // just convert using the definition of an integer: a2*16^2 + a1*16^1 + a0*16^0
    a[2] = (n % 256) as u8;
    a[1] = (n / 256 % 256) as u8;
    a[0] = (n / 65536 % 256) as u8;

    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use tls_derive::TlsEnum;

    #[test]
    fn u24() {
        assert_eq!(to_u24(0xFF), [0x00, 0x00, 0xFF]);
        assert_eq!(to_u24(31500), [0x00, 0x7B, 0x0C]);
        assert_eq!(to_u24(75235), [0x01, 0x25, 0xE3]);
        assert_eq!(to_u24(161), [0x00, 0x00, 0xA1]);
    }

    // #[test]
    // fn variable_length_ok() {
    //     let _v1 = VariableLengthVector::<u8, u8, 1>::new(2u8, Some(&vec![0u8, 1]));
    // }

    // #[test]
    // #[should_panic]
    // fn variable_length_wrong() {
    //     let _v1 = VariableLengthVector::<u8, u8, 1>::new(1u8, Some(&vec![0u8, 1]));
    // }

    #[test]
    fn tls_enum() {
        #[derive(Debug, PartialEq, TlsEnum)]
        enum Foo {
            X = 1,
            Y = 3,
            Z = 5,
        }

        // test Default impl
        assert_eq!(Foo::default(), Foo::X);

        // test TryFrom<u8> impl
        let x = Foo::try_from(3u8);
        assert!(x.is_ok());
        assert_eq!(x.unwrap(), Foo::Y);

        // test FromStr
        use std::str::FromStr;
        let x = Foo::from_str("Z");
        assert!(x.is_ok());
        assert_eq!(x.unwrap(), Foo::Z);

        // test Display
        let x = Foo::from_str("Z");
        assert!(x.is_ok());
        assert_eq!(format!("{}", x.unwrap()), String::from("Z(5)"));
    }
}
