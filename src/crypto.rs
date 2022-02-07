use std::convert::TryFrom;

use aes::{Aes128, Aes256};
use block_modes::block_padding::Pkcs7;
use block_modes::BlockMode;
use cipher::generic_array::typenum::{U16, U32};
use cipher::generic_array::{ArrayLength, GenericArray};
use cipher::NewBlockCipher;
use rand::{thread_rng, RngCore};

use crate::{ErrorInfo, Result};

/// A 128 bit AES key.
#[derive(Clone)]
pub struct Key128(GenericArray<u8, U16>);

/// A 256 bit AES key.
#[derive(Clone)]
pub struct Key256(GenericArray<u8, U32>);

// Type alias for CBC mode with Pkcs7 padding.
type Cbc<T> = block_modes::Cbc<T, Pkcs7>;

// An internal type for providing a deterministic IV in tests.
pub(crate) type IV = [u8; aes::BLOCK_SIZE];

#[derive(Clone)]
pub enum Key {
    /// A 128 bit AES key.
    Key128(Key128),
    /// A 256 bit AES key.
    Key256(Key256),
}

impl Key {
    /// Returns the length of the key in bits.
    pub fn len(&self) -> usize {
        match self {
            Self::Key128(_) => 128,
            Self::Key256(_) => 256,
        }
    }

    /// Encrypts the given data using AES-CBC with Pkcs7 padding.
    pub fn encrypt<'a>(&self, iv: &[u8], buf: &'a mut [u8], pos: usize) -> Result<&'a [u8]> {
        let iv = GenericArray::from_slice(iv);
        match self {
            Self::Key128(key) => Cbc::new(Aes128::new(&key.0), iv).encrypt(buf, pos),
            Self::Key256(key) => Cbc::new(Aes256::new(&key.0), iv).encrypt(buf, pos),
        }
        .map_err(Into::into)
    }

    /// Decrypts the given data using AES-CBC with Pkcs7 padding.
    pub fn decrypt<'a>(&self, iv: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let iv = GenericArray::from_slice(iv);
        match self {
            Self::Key128(key) => Cbc::new(Aes128::new(&key.0), iv).decrypt(buf),
            Self::Key256(key) => Cbc::new(Aes256::new(&key.0), iv).decrypt(buf),
        }
        .map_err(Into::into)
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = ErrorInfo;

    /// Try to instantiate a 128 or 256 bit Key from the given byte vector.
    ///
    /// Returns an error if the byte vector has an unsupported length.
    fn try_from(v: Vec<u8>) -> Result<Self> {
        match v.len() {
            16 => Ok(Self::Key128(Key128(*GenericArray::from_slice(&v)))),
            32 => Ok(Self::Key256(Key256(*GenericArray::from_slice(&v)))),
            _ => Err(error!(
                40000,
                format!(
                    "invalid cipher key length {}, must be 128 or 256 bits",
                    v.len()
                )
            )),
        }
    }
}

impl TryFrom<String> for Key {
    type Error = ErrorInfo;

    /// Try to instantiate a 128 or 256 bit Key from the given base64 encoded
    /// string.
    ///
    /// Returns an error if the decoded bytes have an unsupported length.
    fn try_from(s: String) -> Result<Self> {
        Self::try_from(base64::decode(s)?)
    }
}

impl TryFrom<&str> for Key {
    type Error = ErrorInfo;

    /// Try to instantiate a 128 or 256 bit Key from the given base64 encoded
    /// string.
    ///
    /// Returns an error if the decoded bytes have an unsupported length.
    fn try_from(s: &str) -> Result<Self> {
        Self::try_from(base64::decode(s)?)
    }
}

/// Instantiate a Key of a particular length.
///
/// This is used as a generic parameter to generate_random_key to generate keys
/// of a supported length.
pub trait NewKey {
    type Length: ArrayLength<u8>;

    fn new(data: GenericArray<u8, Self::Length>) -> Key;
}

impl NewKey for Key128 {
    type Length = U16;

    fn new(data: GenericArray<u8, Self::Length>) -> Key {
        Key::Key128(Self(data))
    }
}

impl NewKey for Key256 {
    type Length = U32;

    fn new(data: GenericArray<u8, Self::Length>) -> Key {
        Key::Key256(Self(data))
    }
}

/// Generate a random 128 or 256 bit Key.
///
/// # Example
///
/// ```
/// use ably::crypto::*;
///
/// let key = generate_random_key::<Key128>();
/// assert_eq!(key.len(), 128);
///
/// let key = generate_random_key::<Key256>();
/// assert_eq!(key.len(), 256);
/// ```
pub fn generate_random_key<T: NewKey>() -> Key {
    let mut data = GenericArray::default();
    thread_rng().fill_bytes(&mut data);
    T::new(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_random_key_128() {
        let key = generate_random_key::<Key128>();
        assert_eq!(key.len(), 128);
    }

    #[test]
    fn generate_random_key_256() {
        let key = generate_random_key::<Key256>();
        assert_eq!(key.len(), 256);
    }
}
