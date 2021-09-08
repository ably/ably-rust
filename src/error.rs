/// Creates an [`ErrorInfo`] with the given code and message.
///
/// [`ErrorInfo`]: ably::ErrorInfo
macro_rules! error {
    ($code:expr, $message:expr) => {
        ErrorInfo::new($code, $message, None)
    };
    ($code:expr, $message:expr, $status_code:expr) => {
        ErrorInfo::new($code, $message, $status_code)
    };
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
    /// Returns an ErrorInfo with the given code, message, and status_code.
    pub fn new<S: Into<String>>(code: u32, message: S, status_code: Option<u32>) -> Self {
        ErrorInfo {
            code,
            message: message.into(),
            status_code,
            href: format!("https://help.ably.io/error/{}", code),
        }
    }
}

impl From<reqwest::Error> for ErrorInfo {
    fn from(err: reqwest::Error) -> Self {
        match err.status() {
            Some(s) => error!(
                s.as_u16() as u32 * 100,
                format!("Unexpected HTTP status: {}", s),
                Some(s.as_u16() as u32)
            ),
            None => error!(40000, format!("Unexpected HTTP error: {}", err), None),
        }
    }
}
