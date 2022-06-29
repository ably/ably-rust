use std::convert::Infallible;
use std::fmt::{self, Debug, Display};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::Deserialize;
use serde_repr::Deserialize_repr;

/// A `Result` alias where the `Err` variant contains an `Error`.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(
    Clone, Copy, Debug, Deserialize_repr, FromPrimitive, PartialEq, PartialOrd, Eq, Ord, Hash,
)]
#[repr(u32)]
pub enum ErrorCode {
    NotSet = 0,
    NoError = 10000,
    BadRequest = 40000,
    InvalidRequestBody = 40001,
    InvalidParameterName = 40002,
    InvalidParameterValue = 40003,
    InvalidHeader = 40004,
    InvalidCredential = 40005,
    InvalidConnectionID = 40006,
    InvalidMessageID = 40007,
    InvalidContentLength = 40008,
    MaximumMessageLengthExceeded = 40009,
    InvalidChannelName = 40010,
    StaleRingState = 40011,
    InvalidClientID = 40012,
    InvalidMessageDataOrEncoding = 40013,
    ResourceDisposed = 40014,
    InvalidDeviceID = 40015,
    BatchError = 40020,
    InvalidPublishRequestUnspecified = 40030,
    InvalidPublishRequestInvalidClientSpecifiedID = 40031,
    Testing = 40099,
    Unauthorized = 40100,
    InvalidCredentials = 40101,
    IncompatibleCredentials = 40102,
    InvalidUseOfBasicAuthOverNonTLSTransport = 40103,
    TimestampNotCurrent = 40104,
    NonceValueReplayed = 40105,
    UnableToObtainCredentialsFromGivenParameters = 40106,
    AccountDisabled = 40110,
    AccountRestrictedConnectionLimitsExceeded = 40111,
    AccountBlockedMessageLimitsExceeded = 40112,
    AccountBlocked = 40113,
    AccountRestrictedChannelLimitsExceeded = 40114,
    ApplicationDisabled = 40120,
    KeyErrorUnspecified = 40130,
    KeyRevoked = 40131,
    KeyExpired = 40132,
    KeyDisabled = 40133,
    TokenErrorUnspecified = 40140,
    TokenRevoked = 40141,
    TokenExpired = 40142,
    TokenUnrecognised = 40143,
    InvalidJWTFormat = 40144,
    InvalidTokenFormat = 40145,
    ConnectionBlockedLimitsExceeded = 40150,
    OperationNotPermittedWithProvidedCapability = 40160,
    ErrorFromClientTokenCallback = 40170,
    NoWayToRenewAuthToken = 40171,
    Forbidden = 40300,
    AccountDoesNotPermitTLSConnection = 40310,
    OperationRequiresTLSConnection = 40311,
    ApplicationRequiresAuthentication = 40320,
    NotFound = 40400,
    MethodNotAllowed = 40500,
    RateLimitExceededNonfatal = 42910,
    MaxPerConnectionPublishRateLimitExceededNonfatal = 42911,
    RateLimitExceededFatal = 42920,
    MaxPerConnectionPublishRateLimitExceededFatal = 42921,
    InternalError = 50000,
    InternalChannelError = 50001,
    InternalConnectionError = 50002,
    TimeoutError = 50003,
    RequestFailedDueToOverloadedInstance = 50004,
    ReactorOperationFailed = 70000,
    ReactorOperationFailedPostOperationFailed = 70001,
    ReactorOperationFailedPostOperationReturnedUnexpectedCode = 70002,
    ReactorOperationFailedMaximumNumberOfConcurrentInFlightRequestsExceeded = 70003,
    ExchangeErrorUnspecified = 71000,
    ForcedReAttachmentDueToPermissionsChange = 71001,
    ExchangePublisherErrorUnspecified = 71100,
    NoSuchPublisher = 71101,
    PublisherNotEnabledAsAnExchangePublisher = 71102,
    ExchangeProductErrorUnspecified = 71200,
    NoSuchProduct = 71201,
    ProductDisabled = 71202,
    NoSuchChannelInThisProduct = 71203,
    ExchangeSubscriptionErrorUnspecified = 71300,
    SubscriptionDisabled = 71301,
    RequesterHasNoSubscriptionToThisProduct = 71302,
    ConnectionFailed = 80000,
    ConnectionFailedNoCompatibleTransport = 80001,
    ConnectionSuspended = 80002,
    Disconnected = 80003,
    AlreadyConnected = 80004,
    InvalidConnectionIDRemoteNotFound = 80005,
    UnableToRecoverConnectionMessagesExpired = 80006,
    UnableToRecoverConnectionMessageLimitExceeded = 80007,
    UnableToRecoverConnectionConnectionExpired = 80008,
    ConnectionNotEstablishedNoTransportHandle = 80009,
    InvalidOperationInvalidTransportHandle = 80010,
    UnableToRecoverConnectionIncompatibleAuthParams = 80011,
    UnableToRecoverConnectionInvalidOrUnspecifiedConnectionSerial = 80012,
    ProtocolError = 80013,
    ConnectionTimedOut = 80014,
    IncompatibleConnectionParameters = 80015,
    OperationOnSupersededTransport = 80016,
    ConnectionClosed = 80017,
    InvalidConnectionIDInvalidFormat = 80018,
    ClientConfiguredAuthenticationProviderRequestFailed = 80019,
    ContinuityLossDueToMaximumSubscribeMessageRateExceeded = 80020,
    ClientRestrictionNotSatisfied = 80030,
    ChannelOperationFailed = 90000,
    ChannelOperationFailedInvalidChannelState = 90001,
    ChannelOperationFailedEpochExpiredOrNeverExisted = 90002,
    UnableToRecoverChannelMessagesExpired = 90003,
    UnableToRecoverChannelMessageLimitExceeded = 90004,
    UnableToRecoverChannelNoMatchingEpoch = 90005,
    UnableToRecoverChannelUnboundedRequest = 90006,
    ChannelOperationFailedNoResponseFromServer = 90007,
    MaximumNumberOfChannelsPerConnectionExceeded = 90010,
    UnableToEnterPresenceChannelNoClientID = 91000,
    UnableToEnterPresenceChannelInvalidChannelState = 91001,
    UnableToLeavePresenceChannelThatIsNotEntered = 91002,
    UnableToEnterPresenceChannelMaximumMemberLimitExceeded = 91003,
    UnableToAutomaticallyReEnterPresenceChannel = 91004,
    PresenceStateIsOutOfSync = 91005,
    MemberImplicitlyLeftPresenceChannelConnectionClosed = 91100,
}

impl ErrorCode {
    pub fn new(n: u32) -> Option<Self> {
        Self::from_u32(n)
    }

    pub fn code(self) -> u32 {
        self as u32
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self, f)
    }
}

/// An [Ably error].
///
/// [Ably error]: https://ably.com/documentation/rest/types#error-info
#[derive(Debug, Deserialize)]
pub struct Error {
    /// The [Ably error code].
    ///
    /// [Ably error code]: https://knowledge.ably.com/ably-error-codes
    pub code: ErrorCode,

    /// Additional message information, where available.
    pub message: String,

    /// HTTP Status Code corresponding to this error, where applicable.
    #[serde(rename(deserialize = "statusCode"))]
    pub status_code: Option<u32>,

    /// Link to Ably documenation with more information about the error.
    pub href: String,

    /// Underlying error
    #[serde(skip)]
    pub cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /// Returns an Error with the given code and message.
    pub fn new<S: Into<String>>(code: ErrorCode, message: S) -> Self {
        Self {
            code,
            message: message.into(),
            status_code: None,
            href: format!("https://help.ably.io/error/{}", code.code()),
            cause: None,
        }
    }

    /// Returns an Error with the given code, message, and status_code.
    pub fn with_status<S: Into<String>>(code: ErrorCode, status_code: u32, message: S) -> Self {
        Self {
            code,
            message: message.into(),
            status_code: Some(status_code),
            href: format!("https://help.ably.io/error/{}", code.code()),
            cause: None,
        }
    }
    /// Returns an Error with the given code, message, and cause.
    pub fn with_cause<E, S: Into<String>>(code: ErrorCode, cause: E, message: S) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            code,
            message: message.into(),
            status_code: None,
            href: format!("https://help.ably.io/error/{}", code.code()),
            cause: Some(Box::new(cause)),
        }
    }
}

impl fmt::Display for Error {
    /// Format the error like:
    ///
    /// [ErrorInfo: <msg>; statusCode=<statusCode>; code=<code>; see <url>]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ErrorInfo")?;
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        if let Some(err) = &self.cause {
            write!(f, ": {}", err)?;
        }
        if let Some(code) = self.status_code {
            write!(f, "; statusCode={}", code)?;
        }
        write!(f, "; code={}", self.code.code())?;
        if !self.href.is_empty() {
            write!(f, "; see {} ", self.href)?;
        }
        write!(f, "]")
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        match err.status() {
            Some(s) => Error::with_status(
                ErrorCode::new(s.as_u16() as u32).unwrap_or(ErrorCode::NotSet),
                s.as_u16() as u32,
                format!("Unexpected HTTP status: {}", s),
            ),
            None => Error::with_cause(ErrorCode::BadRequest, err, "Unexpected HTTP error"),
        }
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Self {
        Error::with_cause(ErrorCode::BadRequest, err, "invalid URL")
    }
}

impl From<reqwest::header::InvalidHeaderValue> for Error {
    fn from(_: reqwest::header::InvalidHeaderValue) -> Self {
        Error::new(ErrorCode::BadRequest, "invalid HTTP header")
    }
}

impl From<hmac::digest::InvalidLength> for Error {
    fn from(_: hmac::digest::InvalidLength) -> Self {
        Error::new(ErrorCode::InvalidCredential, "invalid credentials")
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::with_cause(
            ErrorCode::InvalidMessageDataOrEncoding,
            err,
            "invalid base64 data",
        )
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::with_cause(ErrorCode::InvalidRequestBody, err, "invalid JSON data")
    }
}

impl From<rmp_serde::encode::Error> for Error {
    fn from(err: rmp_serde::encode::Error) -> Self {
        Error::with_cause(
            ErrorCode::InvalidRequestBody,
            err,
            "invalid MessagePack data",
        )
    }
}

impl From<rmp_serde::decode::Error> for Error {
    fn from(err: rmp_serde::decode::Error) -> Self {
        Error::with_cause(
            ErrorCode::InvalidRequestBody,
            err,
            "invalid MessagePack data",
        )
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Error::with_cause(ErrorCode::InvalidRequestBody, err, "invalid utf-8 data")
    }
}

/// Implement From<Infallible> to support Error being the associated
/// type for the TryInto trait bound in ClientOptions#key.
impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

/// Used to deserialize a wrapped Error from a JSON error response.
#[derive(Deserialize)]
pub(crate) struct WrappedError {
    pub error: Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_no_status() {
        let err = Error::new(ErrorCode::BadRequest, "error message");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert_eq!(err.message, "error message");
        assert_eq!(err.status_code, None);
    }

    #[test]
    fn error_with_status() {
        let err = Error::with_status(ErrorCode::BadRequest, 400, "error message");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert_eq!(err.message, "error message");
        assert_eq!(err.status_code, Some(400));
    }

    #[test]
    fn error_href() {
        let err = Error::new(ErrorCode::InvalidCredentials, "error message");
        assert_eq!(err.href, "https://help.ably.io/error/40101");
    }

    #[test]
    fn error_fmt() {
        let err = Error::with_status(ErrorCode::InvalidCredentials, 401, "error message");
        assert_eq!(format!("{}", err), "[ErrorInfo: error message; statusCode=401; code=40101; see https://help.ably.io/error/40101 ]");
    }
}
