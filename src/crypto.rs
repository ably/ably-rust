use std::convert::TryFrom;

use cipher::generic_array::typenum::{U16, U32};
use cipher::generic_array::{ArrayLength, GenericArray};
use rand::{thread_rng, RngCore};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::cipher::block_padding::Pkcs7;

use crate::{ErrorInfo, Result};

/// A 128 bit AES key.
#[derive(Clone)]
pub struct Key128(GenericArray<u8, U16>);

/// A 256 bit AES key.
#[derive(Clone)]
pub struct Key256(GenericArray<u8, U32>);

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub(crate) type IV = [u8; Key::block_size()];

#[derive(Clone)]
pub enum Key {
    /// A 128 bit AES key.
    Key128(Key128),
    /// A 256 bit AES key.
    Key256(Key256),
}

impl Key {
    /// Returns the length of the key in bits.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::Key128(_) => 128,
            Self::Key256(_) => 256,
        }
    }

    pub const fn block_size() -> usize {
        // aes blocksize is 128 bits
        16
    }

    /// Encrypts the given data using AES-CBC with Pkcs7 padding.
    pub fn encrypt<'a>(&self, iv: &[u8; Self::block_size()], buf: &'a mut [u8], len: usize) -> Result<&'a [u8]> {
        let iv = GenericArray::from_slice(iv);
        match self {
            Self::Key128(key) => {
                Aes128CbcEnc::new(&key.0.into(), iv)
                    .encrypt_padded_mut::<Pkcs7>(buf, len)
            },
            Self::Key256(key) => {
                Aes256CbcEnc::new(&key.0.into(), iv)
                    .encrypt_padded_mut::<Pkcs7>(buf, len)
            }
        }
        .map_err(|_| unimplemented!())
    }

    /// Decrypts the given data using AES-CBC with Pkcs7 padding.
    pub fn decrypt<'a>(&self, iv: &[u8; Self::block_size()], buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let iv = GenericArray::from_slice(iv);
        match self {
            Self::Key128(key) => {

                Aes128CbcDec::new(&key.0.into(), iv).decrypt_padded_mut::<Pkcs7>(buf)

            },
            Self::Key256(key) => {
                Aes256CbcDec::new(&key.0.into(), iv).decrypt_padded_mut::<Pkcs7>(buf)

            }
        }
        .map_err(|_| unimplemented!())
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

    fn key(data: GenericArray<u8, Self::Length>) -> Key;
}

impl NewKey for Key128 {
    type Length = U16;

    fn key(data: GenericArray<u8, Self::Length>) -> Key {
        Key::Key128(Self(data))
    }
}

impl NewKey for Key256 {
    type Length = U32;

    fn key(data: GenericArray<u8, Self::Length>) -> Key {
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
    T::key(data)
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::fs;

    use serde::Deserialize;

    use super::*;
    use crate::{json, rest};

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

    #[derive(Deserialize)]
    struct CryptoData {
        key: String,
        iv: String,
        items: Vec<CryptoFixture>,
    }

    impl CryptoData {
        fn load(name: &str) -> Self {
            let path = format!("submodules/ably-common/test-resources/{}", name);
            let file = fs::File::open(path).expect(format!("Expected {} to open", name).as_str());
            serde_json::from_reader(file).expect(format!("Expected JSON data in {}", name).as_str())
        }

        fn opts(&self) -> rest::ChannelOptions {
            self.cipher_params().into()
        }

        fn cipher_params(&self) -> rest::CipherParams {
            rest::CipherParams::from(self.cipher_key()).set_iv(self.cipher_iv())
        }

        fn cipher_key(&self) -> Key {
            base64::decode(&self.key)
                .expect("Expected base64 encoded cipher key")
                .try_into()
                .unwrap()
        }

        fn cipher_iv(&self) -> IV {
            base64::decode(&self.iv)
                .expect("Expected base64 encoded IV")
                .try_into()
                .expect("Expected 16-byte IV")
        }
    }

    #[derive(Deserialize)]
    struct CryptoFixture {
        encoded: json::Value,
        encrypted: json::Value,
    }

    #[tokio::test]
    async fn encrypt_message_128() -> Result<()> {
        let data = CryptoData::load("crypto-data-128.json");
        let cipher = data.cipher_params();
        for item in data.items.iter() {
            let mut msg = rest::Message::from_encoded(item.encoded.clone(), None)?;
            msg.encode(&rest::Format::MessagePack, Some(&cipher))?;
            let expected = rest::Message::from_encoded(item.encrypted.clone(), None)?;
            assert_eq!(msg.data, expected.data);
            assert_eq!(msg.encoding, expected.encoding);
        }
        Ok(())
    }

    #[tokio::test]
    async fn encrypt_message_256() -> Result<()> {
        let data = CryptoData::load("crypto-data-256.json");
        let cipher = data.cipher_params();
        for item in data.items.iter() {
            let mut msg = rest::Message::from_encoded(item.encoded.clone(), None)?;
            msg.encode(&rest::Format::MessagePack, Some(&cipher))?;
            let expected = rest::Message::from_encoded(item.encrypted.clone(), None)?;
            assert_eq!(msg.data, expected.data);
            assert_eq!(msg.encoding, expected.encoding);
        }
        Ok(())
    }

    #[tokio::test]
    async fn decrypt_message_128() -> Result<()> {
        let data = CryptoData::load("crypto-data-128.json");
        let opts = data.opts();
        for item in data.items.iter() {
            let msg = rest::Message::from_encoded(item.encrypted.clone(), Some(&opts))?;
            assert_eq!(msg.encoding, rest::Encoding::None);
            let expected = rest::Message::from_encoded(item.encoded.clone(), None)?;
            assert_eq!(msg.data, expected.data);
        }
        Ok(())
    }

    #[tokio::test]
    async fn decrypt_message_256() -> Result<()> {
        let data = CryptoData::load("crypto-data-256.json");
        let opts = data.opts();
        for item in data.items.iter() {
            let msg = rest::Message::from_encoded(item.encrypted.clone(), Some(&opts))?;
            assert_eq!(msg.encoding, rest::Encoding::None);
            let expected = rest::Message::from_encoded(item.encoded.clone(), None)?;
            assert_eq!(msg.data, expected.data);
        }
        Ok(())
    }
}
