// for some structs or enums, len == size_of
#[macro_export]
macro_rules! enum_length {
    ($t:ty) => {
        impl TlsLength for $t {
            fn tls_len(&self) -> usize {
                std::mem::size_of::<$t>()
            }
        }
    };
}

/// auto-implement the `Default` trait for an enum
#[macro_export]
macro_rules! enum_default {
    ($t:ty, $e:ident) => {
        impl std::default::Default for $t {
            fn default() -> Self {
                <$t>::$e
            }
        }
    };
}

// auto-implement the conversion to u8
#[macro_export]
macro_rules! enum_to_u8 {
    ($t:ty) => {
        impl Into<u8> for $t {
            fn into(self) -> u8 {
                self as u8
            }
        }
    };
}

// auto-implement the conversion to network bytes for enums
#[macro_export]
macro_rules! enum_to_network_bytes {
    ($t:ty) => {
        impl TlsToNetworkBytes for $t {
            fn to_network_bytes(&self, v: &mut Vec<u8>) -> Result<usize> {
                v.write_u8(*self as u8)?;
                Ok(1)
            }
        }
    };
}

// auto-implement the conversion from network bytes for enums
#[macro_export]
macro_rules! enum_from_network_bytes {
    ($t:ty, u8) => {
        impl TlsFromNetworkBytes for $t {
            fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
                let value = v.read_u8()?;
                if let Ok(ct) = <$t>::try_from(value as u16) {
                    *self = ct;
                    Ok(())
                } else {
                    Err(Error::new(ErrorKind::Other, "TryFrom() conversion error"))
                }
            }
        }
    };

    ($t:ty, u16) => {
        impl TlsFromNetworkBytes for $t {
            fn from_network_bytes(&mut self, v: &mut Cursor<Vec<u8>>) -> Result<()> {
                let value = v.read_u16::<BigEndian>()?;
                if let Ok(ct) = <$t>::try_from(value) {
                    *self = ct;
                    Ok(())
                } else {
                    Err(Error::new(ErrorKind::Other, "TryFrom() conversion error"))
                }
            }
        }
    };
}

// helper to implement the ExtType trait
#[macro_export]
macro_rules! ext_type {
    ($t:ty, $v:ident) => {
        impl ExtType for $t {
            fn extension_type(&self) -> ExtensionType {
                ExtensionType::$v
            }
        }
    };
}
