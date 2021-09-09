use std::convert::TryFrom;

use crate::error::ErrorInfo;
use crate::Result;
use serde::Deserialize;

/// An enum representing either an API key or a token.
#[derive(Clone, Debug, PartialEq)]
pub enum Credential {
    Key(Key),
    Token(String),
}

/// An API Key used to authenticate with the REST API using HTTP Basic Auth.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Key {
    #[serde(rename(deserialize = "keyName"))]
    pub name:  String,
    pub value: String,
}

impl TryFrom<&str> for Key {
    type Error = ErrorInfo;

    /// Parse an API Key from a string of the form '<keyName>:<keySecret>'.
    fn try_from(s: &str) -> Result<Self> {
        if let [name, value] = s.splitn(2, ':').collect::<Vec<&str>>()[..] {
            Ok(Key {
                name:  name.to_string(),
                value: value.to_string(),
            })
        } else {
            Err(error!(40000, "Invalid key"))
        }
    }
}
