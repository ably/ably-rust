use std::collections::HashMap;
use std::fmt::{self, Debug, Display};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

pub type Result<T> = std::result::Result<T, ErrorInfo>;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<Box<ErrorInfo>>,
}

impl ErrorInfo {
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            code: Some(code),
            message: Some(message.into()),
            href: Some(format!("https://help.ably.io/error/{}", code)),
            ..Default::default()
        }
    }

    pub fn with_status(code: u32, status_code: u16, message: impl Into<String>) -> Self {
        Self {
            code: Some(code),
            status_code: Some(status_code),
            message: Some(message.into()),
            href: Some(format!("https://help.ably.io/error/{}", code)),
            ..Default::default()
        }
    }

    pub fn with_cause(code: u32, message: impl Into<String>, cause: ErrorInfo) -> Self {
        Self {
            code: Some(code),
            message: Some(message.into()),
            href: Some(format!("https://help.ably.io/error/{}", code)),
            cause: Some(Box::new(cause)),
            ..Default::default()
        }
    }

    pub fn from_code(code: ErrorCode) -> Self {
        Self::new(code.code(), format!("{}", code))
    }

    pub fn code_value(&self) -> u32 {
        self.code.unwrap_or(0)
    }

    pub fn error_code(&self) -> ErrorCode {
        self.code
            .and_then(ErrorCode::new)
            .unwrap_or(ErrorCode::NotSet)
    }
}

impl std::error::Error for ErrorInfo {}

impl Display for ErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ErrorInfo")?;
        if let Some(msg) = &self.message {
            if !msg.is_empty() {
                write!(f, ": {}", msg)?;
            }
        }
        if let Some(cause) = &self.cause {
            write!(f, ": {}", cause)?;
        }
        if let Some(sc) = self.status_code {
            write!(f, "; statusCode={}", sc)?;
        }
        if let Some(code) = self.code {
            write!(f, "; code={}", code)?;
        }
        if let Some(href) = &self.href {
            if !href.is_empty() {
                write!(f, "; see {} ", href)?;
            }
        }
        write!(f, "]")
    }
}

impl From<reqwest::Error> for ErrorInfo {
    fn from(err: reqwest::Error) -> Self {
        match err.status() {
            Some(s) => ErrorInfo::with_status(
                ErrorCode::new(s.as_u16() as u32)
                    .map(|c| c.code())
                    .unwrap_or(0),
                s.as_u16(),
                format!("Unexpected HTTP status: {}", s),
            ),
            None => ErrorInfo::new(ErrorCode::BadRequest.code(), format!("Unexpected HTTP error: {}", err)),
        }
    }
}

impl From<url::ParseError> for ErrorInfo {
    fn from(err: url::ParseError) -> Self {
        ErrorInfo::new(ErrorCode::BadRequest.code(), format!("invalid URL: {}", err))
    }
}

impl From<hmac::digest::InvalidLength> for ErrorInfo {
    fn from(_: hmac::digest::InvalidLength) -> Self {
        ErrorInfo::new(ErrorCode::InvalidCredential.code(), "invalid credentials")
    }
}

impl From<base64::DecodeError> for ErrorInfo {
    fn from(err: base64::DecodeError) -> Self {
        ErrorInfo::new(
            ErrorCode::InvalidMessageDataOrEncoding.code(),
            format!("invalid base64 data: {}", err),
        )
    }
}

impl From<serde_json::Error> for ErrorInfo {
    fn from(err: serde_json::Error) -> Self {
        ErrorInfo::new(
            ErrorCode::InvalidRequestBody.code(),
            format!("invalid JSON data: {}", err),
        )
    }
}

impl From<rmp_serde::encode::Error> for ErrorInfo {
    fn from(err: rmp_serde::encode::Error) -> Self {
        ErrorInfo::new(
            ErrorCode::InvalidRequestBody.code(),
            format!("invalid MessagePack data: {}", err),
        )
    }
}

impl From<rmp_serde::decode::Error> for ErrorInfo {
    fn from(err: rmp_serde::decode::Error) -> Self {
        ErrorInfo::new(
            ErrorCode::InvalidRequestBody.code(),
            format!("invalid MessagePack data: {}", err),
        )
    }
}

impl From<std::str::Utf8Error> for ErrorInfo {
    fn from(err: std::str::Utf8Error) -> Self {
        ErrorInfo::new(
            ErrorCode::InvalidRequestBody.code(),
            format!("invalid utf-8 data: {}", err),
        )
    }
}

#[derive(Deserialize)]
pub(crate) struct WrappedError {
    pub error: ErrorInfo,
}

#[derive(
    Clone, Copy, Debug, Deserialize_repr, Serialize_repr, FromPrimitive, PartialEq, PartialOrd, Eq, Ord, Hash,
)]
#[repr(u32)]
pub enum ErrorCode {
    NotSet = 0,
    #[serde(other)]
    UnknownError = 1,
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

pub type ErrorInfoCode = ErrorCode;
