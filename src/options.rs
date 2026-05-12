use std::sync::Arc;
use std::time::Duration;

use crate::auth::{self, AuthCallback, Credential};
use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::rest;

static REST_HOST: &str = "rest.ably.io";

pub enum LogLevel {
    None,
    Error,
    Major,
    Minor,
    Micro,
}

pub struct ClientOptions {
    pub(crate) credential: Credential,
    pub(crate) tls: bool,
    pub(crate) client_id: Option<String>,
    pub(crate) use_token_auth: bool,
    pub(crate) environment: Option<String>,
    pub(crate) idempotent_rest_publishing: bool,
    pub(crate) fallback_hosts: Vec<String>,
    pub(crate) format: rest::Format,
    pub(crate) query_time: bool,
    pub(crate) default_token_params: Option<auth::TokenParams>,
    pub(crate) auto_connect: bool,
    pub(crate) rest_host: String,
    pub(crate) realtime_host: String,
    pub(crate) port: u32,
    pub(crate) tls_port: u32,
    pub(crate) echo_messages: bool,
    pub(crate) queue_messages: bool,
    pub(crate) transport_params: Vec<(String, String)>,
    pub(crate) disconnected_retry_timeout: Duration,
    pub(crate) suspended_retry_timeout: Duration,
    pub(crate) channel_retry_timeout: Duration,
    pub(crate) http_open_timeout: Duration,
    pub(crate) http_request_timeout: Duration,
    pub(crate) realtime_request_timeout: Duration,
    pub(crate) http_max_retry_count: usize,
    pub(crate) http_max_retry_duration: Duration,
    pub(crate) max_message_size: u64,
    pub(crate) max_frame_size: u64,
    pub(crate) fallback_retry_timeout: Duration,
    pub(crate) add_request_ids: bool,
    pub(crate) http_client: Option<Box<dyn crate::http_client::HttpClient>>,
}

impl ClientOptions {
    pub fn new(s: &str) -> Self {
        match auth::Key::new(s) {
            Ok(k) => Self::with_key(k),
            Err(_) => Self::with_token(s.to_string()),
        }
    }

    pub fn with_auth_url(url: impl Into<String>) -> Self {
        Self::token_source(Credential::Url(url.into()))
    }

    pub fn with_auth_callback(callback: Arc<dyn AuthCallback>) -> Self {
        Self::token_source(Credential::Callback(callback))
    }

    pub fn with_key(key: auth::Key) -> Self {
        Self::token_source(Credential::Key(key))
    }

    pub fn with_token(token: impl Into<String>) -> Self {
        Self::token_source(Credential::TokenDetails(auth::TokenDetails::token(
            token.into(),
        )))
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Result<Self> {
        let client_id = client_id.into();
        if client_id == "*" {
            return Err(ErrorInfo::new(
                ErrorCode::InvalidClientID.code(),
                "Can't use '*' as a clientId as that string is reserved",
            ));
        }
        self.client_id = Some(client_id);
        Ok(self)
    }

    pub fn use_token_auth(mut self, v: bool) -> Self {
        self.use_token_auth = v;
        self
    }

    pub fn token_details(mut self, td: auth::TokenDetails) -> Self {
        self.credential = Credential::TokenDetails(td);
        self
    }

    pub fn environment(mut self, env: impl Into<String>) -> Result<Self> {
        if self.rest_host != REST_HOST {
            return Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "Cannot set both environment and rest_host",
            ));
        }
        let env = env.into();
        self.rest_host = format!("{}-rest.ably.io", env);
        self.fallback_hosts = ('a'..='e')
            .map(|c| format!("{}-{}-fallback.ably-realtime.com", env, c))
            .collect();
        self.environment = Some(env);
        Ok(self)
    }

    pub fn use_binary_protocol(mut self, v: bool) -> Self {
        self.format = if v {
            rest::Format::MessagePack
        } else {
            rest::Format::JSON
        };
        self
    }

    pub fn idempotent_rest_publishing(mut self, v: bool) -> Self {
        self.idempotent_rest_publishing = v;
        self
    }

    pub fn default_token_params(mut self, params: auth::TokenParams) -> Self {
        self.default_token_params = Some(params);
        self
    }

    pub fn rest_host(mut self, host: impl Into<String>) -> Result<Self> {
        if self.environment.is_some() {
            return Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "Cannot set both environment and rest_host",
            ));
        }
        self.fallback_hosts = Vec::new();
        self.rest_host = host.into();
        Ok(self)
    }

    pub fn fallback_hosts(mut self, hosts: Vec<String>) -> Self {
        self.fallback_hosts = hosts;
        self
    }

    pub fn http_request_timeout(mut self, timeout: Duration) -> Self {
        self.http_request_timeout = timeout;
        self
    }

    pub fn http_max_retry_count(mut self, count: usize) -> Self {
        self.http_max_retry_count = count;
        self
    }

    pub fn add_request_ids(mut self, v: bool) -> Self {
        self.add_request_ids = v;
        self
    }

    pub fn log_level(self, _level: LogLevel) -> Self {
        self
    }

    pub fn log_handler(self, _handler: impl Fn(LogLevel, &str) + Send + Sync + 'static) -> Self {
        self
    }

    pub fn tls(mut self, v: bool) -> Self {
        self.tls = v;
        self
    }

    pub fn realtime_host(mut self, host: impl Into<String>) -> Self {
        self.realtime_host = host.into();
        self
    }

    pub fn port(mut self, port: u32) -> Self {
        self.port = port;
        self
    }

    pub fn auto_connect(mut self, v: bool) -> Self {
        self.auto_connect = v;
        self
    }

    pub fn echo_messages(mut self, v: bool) -> Self {
        self.echo_messages = v;
        self
    }

    pub fn queue_messages(mut self, v: bool) -> Self {
        self.queue_messages = v;
        self
    }

    pub fn transport_params(mut self, params: Vec<(String, String)>) -> Self {
        self.transport_params = params;
        self
    }

    pub fn disconnected_retry_timeout(mut self, timeout: Duration) -> Self {
        self.disconnected_retry_timeout = timeout;
        self
    }

    pub fn suspended_retry_timeout(mut self, timeout: Duration) -> Self {
        self.suspended_retry_timeout = timeout;
        self
    }

    pub fn realtime_request_timeout(mut self, timeout: Duration) -> Self {
        self.realtime_request_timeout = timeout;
        self
    }

    pub fn rest(mut self) -> Result<rest::Rest> {
        // Validate credentials
        self.validate_for_rest()?;

        // Use the provided http_client if any, otherwise create a reqwest-based one
        let client: Box<dyn crate::http_client::HttpClient> = if let Some(c) = self.http_client.take() {
            c
        } else {
            Box::new(crate::http_client::ReqwestHttpClient::new())
        };
        self.build_rest(client)
    }

    pub fn realtime(self) -> Result<crate::realtime::Realtime> {
        todo!()
    }

    pub(crate) fn rest_with_http_client(
        mut self,
        client: Box<dyn crate::http_client::HttpClient>,
    ) -> Result<rest::Rest> {
        self.validate_for_rest()?;
        self.http_client = None; // ignore any previously set http_client
        self.build_rest(client)
    }

    fn validate_for_rest(&self) -> Result<()> {
        // RSC1b: Empty token should be rejected
        match &self.credential {
            auth::Credential::TokenDetails(td) if td.token.is_empty() => {
                return Err(ErrorInfo::new(
                    ErrorCode::UnableToObtainCredentialsFromGivenParameters.code(),
                    "No valid credentials provided",
                ));
            }
            _ => {}
        }

        // RSC18: Basic auth over non-TLS is rejected
        if !self.tls {
            if let auth::Credential::Key(_) = &self.credential {
                if !self.use_token_auth && self.client_id.is_none() {
                    return Err(ErrorInfo::new(
                        ErrorCode::InvalidUseOfBasicAuthOverNonTLSTransport.code(),
                        "Basic auth is not permitted over non-TLS transport",
                    ));
                }
            }
        }

        Ok(())
    }

    fn build_rest(self, client: Box<dyn crate::http_client::HttpClient>) -> Result<rest::Rest> {
        // Pre-populate cached token if credential is TokenDetails
        let cached_token = match &self.credential {
            auth::Credential::TokenDetails(td) => Some(td.clone()),
            _ => None,
        };
        let inner = rest::RestInner {
            opts: self,
            http_client: client,
            auth_state: std::sync::Mutex::new(rest::AuthState {
                cached_token,
                saved_token_params: None,
            }),
            fallback_state: std::sync::Mutex::new(None),
        };
        Ok(rest::Rest {
            inner: std::sync::Arc::new(inner),
        })
    }

    pub(crate) fn token_source(token: Credential) -> Self {
        Self {
            credential: token,
            tls: true,
            client_id: None,
            use_token_auth: false,
            environment: None,
            idempotent_rest_publishing: false,
            fallback_hosts: vec![
                "a.ably-realtime.com".to_string(),
                "b.ably-realtime.com".to_string(),
                "c.ably-realtime.com".to_string(),
                "d.ably-realtime.com".to_string(),
                "e.ably-realtime.com".to_string(),
            ],
            format: rest::Format::MessagePack,
            query_time: false,
            default_token_params: None,
            auto_connect: true,
            rest_host: REST_HOST.to_string(),
            realtime_host: "realtime.ably.io".to_string(),
            port: 80,
            tls_port: 443,
            echo_messages: true,
            queue_messages: true,
            transport_params: Vec::new(),
            disconnected_retry_timeout: Duration::from_secs(15),
            suspended_retry_timeout: Duration::from_secs(30),
            channel_retry_timeout: Duration::from_secs(15),
            http_open_timeout: Duration::from_secs(4),
            http_request_timeout: Duration::from_secs(10),
            realtime_request_timeout: Duration::from_secs(10),
            http_max_retry_count: 3,
            http_max_retry_duration: Duration::from_secs(15),
            max_message_size: 64 * 1024,
            max_frame_size: 512 * 1024,
            fallback_retry_timeout: Duration::from_secs(10 * 60),
            add_request_ids: false,
            http_client: None,
        }
    }
}
