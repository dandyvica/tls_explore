use crate::alert::alert::{AlertDescription, AlertLevel};
use crate::enum_length;
use crate::handshake::client_hello::ExtensionType;
use crate::handshake::common::{ContentType, Random, VariableLengthVector};
use crate::handshake::handshake::HandshakeType;

// Implementers of this trait will be used in the derive macro
pub trait TlsLength {
    // give the length of the type when converted to [u8]
    fn tls_len(&self) -> usize;
}

/// ```
/// use tls_explore::structurizer::length::TlsLength;
///
/// let v = [0u8;10];
/// assert_eq!(v.tls_len(), 10);
/// ```
impl<T, const N: usize> TlsLength for [T; N] {
    fn tls_len(&self) -> usize {
        N * std::mem::size_of::<T>()
    }
}

/// ```
/// use tls_explore::structurizer::length::TlsLength;
/// use tls_explore::handshake::common::Random;
///
/// let v = Random::new();
/// assert_eq!(v.tls_len(), 32);
/// ```
impl TlsLength for Random {
    fn tls_len(&self) -> usize {
        4 + 28
    }
}

//enum_length!(Random);

/// ```
/// use tls_explore::structurizer::length::TlsLength;
///
/// let v = Some(0u8);
/// assert_eq!(v.tls_len(), 1);
///
/// let v: Option<u16> = None;
/// assert_eq!(v.tls_len(), 0);
/// ```
impl<T: TlsLength> TlsLength for Option<T> {
    fn tls_len(&self) -> usize {
        if self.is_none() {
            0
        } else {
            self.as_ref().unwrap().tls_len()
        }
    }
}

/// ```
/// use tls_explore::structurizer::length::TlsLength;
/// use tls_explore::handshake::common::VariableLengthVector;
///
/// let v: VariableLengthVector<[u16;3], 1, 2> = VariableLengthVector::from_slice(&[[0xFFFF;3],[0xFFFF;3],[0xFFFF;3]]);
/// assert_eq!(v.tls_len(), 2+3*2*3);
/// ```
impl<T, const MIN: u8, const BYTES: u8> TlsLength for VariableLengthVector<T, MIN, BYTES> {
    fn tls_len(&self) -> usize {
        BYTES as usize + self.data.len() * std::mem::size_of::<T>()
    }
}

/// ```
/// use tls_explore::structurizer::length::TlsLength;
///
/// let v: Vec<[u16;3]> = vec![[0xFFFF;3],[0xFFFF;3],[0xFFFF;3]];
/// assert_eq!(v.tls_len(), 3*2*3);
/// ```
impl<T> TlsLength for Vec<T> {
    fn tls_len(&self) -> usize {
        self.len() * std::mem::size_of::<T>()
    }
}

#[cfg(test)]
mod tests {
    use tls_derive::TlsLength;

    use super::*;

    #[test]
    fn length() {
        #[derive(TlsLength)]
        struct A {
            a: u16,
            b: u8,
        }
        let a = A { a: 8, b: 7 };
        assert_eq!(a.tls_len(), 3);

        #[derive(TlsLength)]
        struct B {
            a: u32,
            b: [u8; 100],
            c: Random,
            d: VariableLengthVector<u8, 0, 2>,
        }
        let b = B {
            a: 8,
            b: [0; 100],
            c: Random::new(),
            d: VariableLengthVector {
                length: 0,
                data: b"0123456789".to_vec(),
            },
        };
        assert_eq!(b.tls_len(), 4 + 100 + 32 + 2 + 10);

        #[derive(TlsLength)]
        struct C {
            a: u32,
            d: VariableLengthVector<[u8; 2], 0, 1>,
        }
        let c = C {
            a: 8,
            d: VariableLengthVector {
                length: 0,
                data: vec![[0; 2], [1; 2]],
            },
        };
        assert_eq!(c.tls_len(), 4 + 1 + 4);
    }
}
