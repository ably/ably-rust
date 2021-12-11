use serde::Deserialize;
use std::convert::Infallible;
use std::fmt;

/// Creates an [`ErrorInfo`] with the given code and message.
///
/// [`ErrorInfo`]: ably::ErrorInfo
macro_rules! error {
    ($code:expr, $message:expr) => {
        ErrorInfo::new($code, $message, None)
    };
    ($code:expr, $message:expr, $status_code:expr) => {
        ErrorInfo::new($code, $message, Some($status_code))
    };
}

/// An [Ably error].
///
/// [Ably error]: https://ably.com/documentation/rest/types#error-info
#[derive(Clone, Debug, Deserialize)]
pub struct ErrorInfo {
    /// The [Ably error code].
    ///
    /// [Ably error code]: https://knowledge.ably.com/ably-error-codes
    pub code: u32,

    /// Additional message information, where available.
    pub message: String,

    /// HTTP Status Code corresponding to this error, where applicable.
    #[serde(rename(deserialize = "statusCode"))]
    pub status_code: Option<u32>,

    /// Link to Ably documenation with more information about the error.
    pub href: String,
}

impl ErrorInfo {
    /// Returns an ErrorInfo with the given code, message, and status_code.
    pub fn new<S: Into<String>>(code: u32, message: S, status_code: Option<u32>) -> Self {
        Self {
            code,
            message: message.into(),
            status_code,
            href: format!("https://help.ably.io/error/{}", code),
        }
    }
}

impl fmt::Display for ErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ErrorInfo")?;
        if self.message.len() > 0 {
            write!(f, ": {}", self.message)?;
        }
        if let Some(code) = self.status_code {
            write!(f, "; statusCode={}", code)?;
        }
        write!(f, "; code={}", self.code)?;
        if self.href.len() > 0 {
            write!(f, "; see {} ", self.href)?;
        }
        write!(f, "]")
    }
}

impl From<reqwest::Error> for ErrorInfo {
    fn from(err: reqwest::Error) -> Self {
        match err.status() {
            Some(s) => error!(
                s.as_u16() as u32 * 100,
                format!("Unexpected HTTP status: {}", s),
                s.as_u16() as u32
            ),
            None => error!(40000, format!("Unexpected HTTP error: {}", err)),
        }
    }
}

impl From<url::ParseError> for ErrorInfo {
    fn from(err: url::ParseError) -> Self {
        error!(40000, format!("invalid URL: {}", err))
    }
}

impl From<reqwest::header::InvalidHeaderValue> for ErrorInfo {
    fn from(_: reqwest::header::InvalidHeaderValue) -> Self {
        error!(40000, "invalid HTTP header")
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for ErrorInfo {
    fn from(_: hmac::crypto_mac::InvalidKeyLength) -> Self {
        error!(40101, "invalid credentials")
    }
}

impl From<base64::DecodeError> for ErrorInfo {
    fn from(err: base64::DecodeError) -> Self {
        error!(40013, format!("invalid base64 data: {}", err))
    }
}

impl From<serde_json::Error> for ErrorInfo {
    fn from(err: serde_json::Error) -> Self {
        error!(40001, format!("invalid JSON data: {}", err))
    }
}

impl From<rmp_serde::encode::Error> for ErrorInfo {
    fn from(err: rmp_serde::encode::Error) -> Self {
        error!(40001, format!("invalid MessagePack data: {}", err))
    }
}

impl From<rmp_serde::decode::Error> for ErrorInfo {
    fn from(err: rmp_serde::decode::Error) -> Self {
        error!(40001, format!("invalid MessagePack data: {}", err))
    }
}

impl From<std::str::Utf8Error> for ErrorInfo {
    fn from(err: std::str::Utf8Error) -> Self {
        error!(40001, format!("invalid utf-8 data: {}", err))
    }
}

impl From<block_modes::InvalidKeyIvLength> for ErrorInfo {
    fn from(_: block_modes::InvalidKeyIvLength) -> Self {
        error!(40000, "invalid cipher key or iv length")
    }
}

impl From<block_modes::BlockModeError> for ErrorInfo {
    fn from(err: block_modes::BlockModeError) -> Self {
        error!(40000, format!("error decrypting data: {}", err))
    }
}

impl From<log::SetLoggerError> for ErrorInfo {
    fn from(err: log::SetLoggerError) -> Self {
        error!(40000, format!("error initializing logger: {}", err))
    }
}

/// Implement From<Infallible> to support ErrorInfo being the associated
/// type for the TryInto trait bound in ClientOptions#key.
impl From<Infallible> for ErrorInfo {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

/// Used to deserialize a wrapped ErrorInfo from a JSON error response.
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), serde_json::Error> {
/// use ably::error::WrappedError;
///
/// let response = r#"
///   {
///       "error": {
///           "message": "No authentication information provided. (See https://help.ably.io/error/40101 for help.)",
///           "code": 40101,
///           "statusCode": 401,
///           "href": "https://help.ably.io/error/40101"
///       }
///   }"#;
///
/// let err: WrappedError = serde_json::from_str(response)?;
///
/// assert_eq!(err.error.code, 40101);
/// assert_eq!(err.error.message, "No authentication information provided. (See https://help.ably.io/error/40101 for help.)");
/// assert_eq!(err.error.status_code, Some(401));
/// # Ok(())
/// # }
/// ```
#[derive(Deserialize)]
pub struct WrappedError {
    pub error: ErrorInfo,
}
