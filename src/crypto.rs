use std::convert::TryFrom;

use aes::{Aes128, Aes256};
use block_modes::block_padding::Pkcs7;
use block_modes::BlockMode;
use cipher::generic_array::typenum::Unsigned;
use cipher::generic_array::{ArrayLength, GenericArray};
use cipher::NewBlockCipher;
use rand::{thread_rng, RngCore};

use crate::{ErrorInfo, Result};

type KeySize128 = <Aes128 as NewBlockCipher>::KeySize;
type KeySize256 = <Aes256 as NewBlockCipher>::KeySize;

pub type Key128 = GenericArray<u8, KeySize128>;
pub type Key256 = GenericArray<u8, KeySize256>;

type Cbc<T> = block_modes::Cbc<T, Pkcs7>;

pub(crate) type IV = [u8; aes::BLOCK_SIZE];

#[derive(Clone)]
pub enum Key {
    Key128(Key128),
    Key256(Key256),
}

impl Key {
    pub fn len(&self) -> usize {
        match self {
            Self::Key128(_) => KeySize128::to_usize(),
            Self::Key256(_) => KeySize256::to_usize(),
        }
    }

    pub fn encrypt<'a>(&self, iv: &[u8], buf: &'a mut [u8], pos: usize) -> Result<&'a [u8]> {
        let iv = GenericArray::from_slice(iv);
        match self {
            Self::Key128(key) => Cbc::new(Aes128::new(&key), iv).encrypt(buf, pos),
            Self::Key256(key) => Cbc::new(Aes256::new(&key), iv).encrypt(buf, pos),
        }
        .map_err(Into::into)
    }

    pub fn decrypt<'a>(&self, iv: &[u8], buf: &'a mut [u8]) -> Result<&'a [u8]> {
        let iv = GenericArray::from_slice(iv);
        match self {
            Self::Key128(key) => Cbc::new(Aes128::new(&key), iv).decrypt(buf),
            Self::Key256(key) => Cbc::new(Aes256::new(&key), iv).decrypt(buf),
        }
        .map_err(Into::into)
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = ErrorInfo;

    fn try_from(v: Vec<u8>) -> Result<Self> {
        match v.len() {
            16 => Ok(Self::Key128(*Key128::from_slice(&v))),
            32 => Ok(Self::Key256(*Key256::from_slice(&v))),
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

    fn try_from(s: String) -> Result<Self> {
        Self::try_from(base64::decode(s)?)
    }
}

impl TryFrom<&str> for Key {
    type Error = ErrorInfo;

    fn try_from(s: &str) -> Result<Self> {
        Self::try_from(base64::decode(s)?)
    }
}

pub fn generate_random_key<T: ArrayLength<u8>>() -> GenericArray<u8, T> {
    let mut data = GenericArray::default();
    thread_rng().fill_bytes(&mut data);
    data
}
