//! A Rust client for the [Ably] REST and Realtime APIs.
//!
//! # Example
//!
//! TODO
//!
//! [Ably]: https://ably.com

/// A client for the [Ably REST API].
///
/// [Ably REST API]: https://ably.com/documentation/rest-api
#[derive(Debug)]
pub struct RestClient {
    pub options: ClientOptions,
}

impl RestClient {
    /// Returns an `ably::RestClient` with the given options.
    ///
    /// This is typically used when configuring custom options. To initialise
    /// a client with just an API key or token, use [`ably::RestClient::from`].
    ///
    /// # Example
    ///
    /// ```
    /// use ably;
    ///
    /// let options = ably::ClientOptions::new();
    /// // ... set some custom options ...
    ///
    /// let client = ably::RestClient::new(options);
    /// ```
    ///
    /// [`ably::RestClient::from`]: RestClient::from
    pub fn new(options: ClientOptions) -> Result<Self, ErrorInfo> {
        options.validate()?;

        Ok(RestClient { options })
    }
}

impl From<&str> for RestClient {
    /// Returns a RestClient initialised with an API key or token contained
    /// in the given string.
    ///
    /// # Example
    ///
    /// ```
    /// // Initialise a RestClient with an API key.
    /// let client = ably::RestClient::from("<api_key>");
    /// ```
    ///
    /// ```
    /// // Initialise a RestClient with a token.
    /// let client = ably::RestClient::from("<token>");
    /// ```
    fn from(s: &str) -> Self {
        // unwrap the result since we're guaranteed to have a valid client when
        // it's initialised with an API key or token.
        RestClient::new(ClientOptions::from(s)).unwrap()
    }
}

/// An [Ably error].
///
/// [Ably error]: https://ably.com/documentation/rest/types#error-info
#[derive(Debug)]
pub struct ErrorInfo {
    /// The [Ably error code].
    ///
    /// [Ably error code]: https://knowledge.ably.com/ably-error-codes
    pub code: u32,

    /// Additional message information, where available.
    pub message: String,

    /// HTTP Status Code corresponding to this error, where applicable.
    pub status_code: Option<u32>,

    /// Link to Ably documenation with more information about the error.
    pub href: String,
}

impl ErrorInfo {
    /// Returns an ErrorInfo with the given code and message.
    fn new(code: u32, message: &str) -> Self {
        ErrorInfo {
            code,
            message: String::from(message),
            status_code: None,
            href: format!("https://help.ably.io/error/{}", code),
        }
    }
}

/// Creates an [`ErrorInfo`] with the given code and message.
///
/// [`ErrorInfo`]: ably::ErrorInfo
macro_rules! error {
    ($code:expr, $message:expr) => (ErrorInfo::new($code, $message))
}

/// [Ably client options] for initialising a REST or Realtime client.
///
/// [Ably client options]: https://ably.com/documentation/rest/types#client-options
#[derive(Debug)]
pub struct ClientOptions {
    /// Holds either an API key or a token.
    credential: Option<auth::Credential>,
}

impl ClientOptions {
    /// Returns ClientOptions with default values.
    pub fn new() -> Self {
        ClientOptions { credential: None }
    }

    /// Returns the API key.
    pub fn key(&self) -> Option<String> {
        match &self.credential {
            Some(auth::Key(s)) => Some(s.to_string()),
            _ => None,
        }
    }

    /// Sets the API key.
    pub fn set_key(&mut self, key: &str) {
        self.credential = Some(auth::Key(String::from(key)));
    }

    /// Returns the token.
    pub fn token(&self) -> Option<String> {
        match &self.credential {
            Some(auth::Token(s)) => Some(s.to_string()),
            _ => None,
        }
    }

    /// Sets the token.
    pub fn set_token(&mut self, token: &str) {
        self.credential = Some(auth::Token(String::from(token)));
    }

    /// Validates the options:
    ///
    /// - checks a credential has been provided ([RSC1b])
    ///
    /// [RSC1b]: https://docs.ably.io/client-lib-development-guide/features/#RSC1b
    fn validate(&self) -> Result<(), ErrorInfo> {
        match self.credential {
            None => Err(error!(40106, "must provide either an API key or a token")),
            _ => Ok(()),
        }
    }
}

impl From<&str> for ClientOptions {
    /// Returns ClientOptions initialised with an API key or token contained
    /// in the given string.
    ///
    /// If the string contains a colon, then the string is assumed to contain
    /// an API key, otherwise it's treated as a token (see [RSC1a]).
    ///
    /// # Example
    ///
    /// ```
    /// // Initialise ClientOptions with an API key.
    /// let client = ably::ClientOptions::from("uTNfLQ.ms51fw:****************");
    /// ```
    ///
    /// ```
    /// // Initialise ClientOptions with a token.
    /// let client = ably::ClientOptions::from("uTNfLQ.Gup2lu*********PYcwUb");
    /// ```
    ///
    /// [RSC1a]: https://docs.ably.io/client-lib-development-guide/features/#RSC1a
    fn from(s: &str) -> Self {
        ClientOptions {
            credential: Some(match s.find(':') {
                Some(_) => auth::Key(String::from(s)),
                None => auth::Token(String::from(s)),
            }),
        }
    }
}

mod auth {
    /// An enum representing either an API key or a token.
    #[derive(Debug, PartialEq)]
    pub enum Credential {
        Key(String),
        Token(String),
    }
    pub use Credential::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_key_credential_from_string_with_colon() {
        let s = "appID.keyID:keySecret";
        let client = RestClient::from(s);
        assert_eq!(client.options.key(), Some(s.to_string()));
        assert_eq!(client.options.token(), None);
    }

    #[test]
    fn sets_token_credential_from_string_without_colon() {
        let s = "appID.tokenID";
        let client = RestClient::from(s);
        assert_eq!(client.options.token(), Some(s.to_string()));
        assert_eq!(client.options.key(), None);
    }

    #[test]
    fn errors_with_no_key_or_token() {
        let options = ClientOptions::new();
        let err = RestClient::new(options).expect_err("Expected 40106 error");
        assert_eq!(err.code, 40106);
    }
}
