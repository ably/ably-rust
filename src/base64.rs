pub use ::base64::{decode, encode};

use serde::{Deserialize, Serialize};

pub fn serialize<S: serde::Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    let data = encode(v);
    String::serialize(&data, s)
}

pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let data = String::deserialize(d)?;
    decode(data.as_bytes()).map_err(serde::de::Error::custom)
}
