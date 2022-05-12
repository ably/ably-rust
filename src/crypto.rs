use std::convert::TryFrom;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cipher::generic_array::GenericArray;
use rand::{thread_rng, RngCore};

use crate::{ErrorInfo, Result};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub(crate) type IV = [u8; 16];

#[derive(Clone, Debug)]
pub enum Cipher {
    /// A 128 bit AES key.
    Aes128Cbc([u8; 16]),
    /// A 256 bit AES key.
    Aes256Cbc([u8; 32]),
}

impl Default for Cipher {
    fn default() -> Self {
        Self::builder().build().unwrap()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum CipherKind {
    #[default]
    AesCbc,
}

#[derive(Clone, Copy, Debug)]
pub enum KeyLen {
    Bits128,
    Bits256,
}

#[derive(Clone, Debug, Default)]
pub struct CipherBuilder {
    kind: CipherKind,
    len: Option<KeyLen>,
    key: Option<Vec<u8>>,
}

impl CipherBuilder {
    pub fn kind(mut self, kind: CipherKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }

    pub fn string(mut self, key: &str) -> Result<Self> {
        let key = base64::decode(key)?;
        self.key = Some(key);
        Ok(self)
    }

    pub fn len(mut self, len: KeyLen) -> Self {
        self.len = Some(len);
        self
    }

    pub fn build(self) -> Result<Cipher> {
        let len = self.len.or_else(|| {
            self.key.as_ref().and_then(|key| match key.len() {
                16 => Some(KeyLen::Bits128),
                32 => Some(KeyLen::Bits256),
                _ => None,
            })
        });

        let cipher = match self.kind {
            CipherKind::AesCbc => match len {
                Some(KeyLen::Bits128) => {
                    let key = if let Some(key) = self.key {
                        key.try_into()
                            .map_err(|_| error!(40000, "Invalid key size"))?
                    } else {
                        let mut data = [0; 16];
                        thread_rng().fill_bytes(&mut data);
                        data
                    };

                    Cipher::Aes128Cbc(key)
                }
                Some(KeyLen::Bits256) | None => {
                    let key = if let Some(key) = self.key {
                        key.try_into()
                            .map_err(|_| error!(40000, "Invalid key size"))?
                    } else {
                        let mut data = [0; 32];
                        thread_rng().fill_bytes(&mut data);
                        data
                    };
                    Cipher::Aes256Cbc(key)
                }
            },
        };

        Ok(cipher)
    }
}

impl Cipher {
    pub fn builder() -> CipherBuilder {
        CipherBuilder::default()
    }

    /// Returns the length of the key in bits.
    pub fn bits(&self) -> usize {
        match self {
            Self::Aes128Cbc(_) => 128,
            Self::Aes256Cbc(_) => 256,
        }
    }

    pub(crate) fn block_size(&self) -> usize {
        // aes blocksize is 128 bits
        16
    }

    /// Encrypts the given data using AES-CBC with Pkcs7 padding.
    pub fn encrypt<'a>(&self, iv: &[u8], buf: &'a mut [u8], len: usize) -> Result<&'a [u8]> {
        let iv = GenericArray::from_slice(iv);
        match self {
            Self::Aes128Cbc(key) => {
                Aes128CbcEnc::new(key.into(), iv).encrypt_padded_mut::<Pkcs7>(buf, len)
            }
            Self::Aes256Cbc(key) => {
                Aes256CbcEnc::new(key.into(), iv).encrypt_padded_mut::<Pkcs7>(buf, len)
            }
        }
        .map_err(|_| unimplemented!())
    }

    /// Decrypts the given data using AES-CBC with Pkcs7 padding.
    pub fn decrypt<'a>(&self, iv: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let iv = GenericArray::from_slice(iv);
        match self {
            Self::Aes128Cbc(key) => {
                Aes128CbcDec::new(key.into(), iv).decrypt_padded_mut::<Pkcs7>(buf)
            }
            Self::Aes256Cbc(key) => {
                Aes256CbcDec::new(key.into(), iv).decrypt_padded_mut::<Pkcs7>(buf)
            }
        }
        .map_err(|_| unimplemented!())
    }
}

impl TryFrom<&str> for Cipher {
    type Error = ErrorInfo;

    fn try_from(value: &str) -> Result<Self> {
        Self::builder().string(value)?.build()
    }
}

impl TryFrom<String> for Cipher {
    type Error = ErrorInfo;

    fn try_from(value: String) -> Result<Self> {
        Self::builder().string(&value)?.build()
    }
}

impl TryFrom<&[u8]> for Cipher {
    type Error = ErrorInfo;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::builder().key(value.to_vec()).build()
    }
}

impl TryFrom<Vec<u8>> for Cipher {
    type Error = ErrorInfo;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::builder().key(value).build()
    }
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
        let key = Cipher::builder().len(KeyLen::Bits128).build().unwrap();
        assert_eq!(key.bits(), 128);
    }

    #[test]
    fn generate_random_key_256() {
        let key = Cipher::builder().len(KeyLen::Bits256).build().unwrap();
        assert_eq!(key.bits(), 256);
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

        fn cipher_key(&self) -> Cipher {
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
