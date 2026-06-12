use std::sync::Arc;
use std::time::Duration;

use crate::auth::{self, AuthCallback, Credential};
use crate::error::{ErrorCode, ErrorInfo, Result};
use crate::rest;

/// REC1a: the default primary domain.
pub(crate) static DEFAULT_PRIMARY_DOMAIN: &str = "main.realtime.ably.net";

/// RSC2: the installed log sink.
pub type LogHandler = Arc<dyn Fn(LogLevel, &str) + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    None = 0,
    Error = 1,
    Major = 2,
    Minor = 3,
    Micro = 4,
}

pub struct ClientOptions {
    pub(crate) credential: Credential,
    pub(crate) tls: bool,
    pub(crate) client_id: Option<String>,
    pub(crate) use_token_auth: bool,
    pub(crate) endpoint: Option<String>,
    pub(crate) environment: Option<String>,
    pub(crate) idempotent_rest_publishing: bool,
    /// REC2a: explicit fallback hosts. None means derive per REC2c.
    pub(crate) fallback_hosts: Option<Vec<String>>,
    pub(crate) format: rest::Format,
    pub(crate) query_time: bool,
    pub(crate) auth_method: Option<String>,
    pub(crate) auth_headers: Vec<(String, String)>,
    pub(crate) auth_params: Vec<(String, String)>,
    pub(crate) default_token_params: Option<auth::TokenParams>,
    pub(crate) auto_connect: bool,
    /// Deprecated REC1d1 override. None means derive per REC1.
    pub(crate) rest_host: Option<String>,
    pub(crate) realtime_host: Option<String>,
    /// The REC1 primary domain, resolved at build time.
    pub(crate) primary_host: String,
    /// The REC2 fallback domains, resolved at build time.
    pub(crate) resolved_fallback_hosts: Vec<String>,
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
    /// RTN14e default; the server value from ConnectionDetails overrides it.
    pub(crate) connection_state_ttl: Duration,
    pub(crate) http_max_retry_count: usize,
    pub(crate) http_max_retry_duration: Duration,
    pub(crate) max_message_size: u64,
    pub(crate) max_frame_size: u64,
    pub(crate) fallback_retry_timeout: Duration,
    pub(crate) add_request_ids: bool,
    pub(crate) http_client: Option<Box<dyn crate::http_client::HttpClient>>,
    /// RSC2: minimum severity that is emitted. Defaults to Error.
    pub(crate) log_level: LogLevel,
    pub(crate) log_handler: Option<LogHandler>,
}

/// How the REC1 primary domain was determined — drives REC2c fallback derivation.
enum PrimaryDomainSource {
    Default,
    Hostname,
    ProdPolicy(String),
    NonprodPolicy(String),
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

    /// AO2d/TO3j7: HTTP method for authUrl requests. Defaults to GET.
    pub fn auth_method(mut self, method: impl Into<String>) -> Self {
        self.auth_method = Some(method.into());
        self
    }

    /// AO2e/TO3j8: headers sent with authUrl requests.
    pub fn auth_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.auth_headers = headers;
        self
    }

    /// AO2f/TO3j9: params merged into authUrl requests.
    pub fn auth_params(mut self, params: Vec<(String, String)>) -> Self {
        self.auth_params = params;
        self
    }

    /// AO2g/TO3j10: query the server clock when creating token requests (RSA9d).
    pub fn query_time(mut self, v: bool) -> Self {
        self.query_time = v;
        self
    }

    pub fn token_details(mut self, td: auth::TokenDetails) -> Self {
        self.credential = Credential::TokenDetails(td);
        self
    }

    /// REC1b: the endpoint option — a routing policy ID ("main"),
    /// a non-production routing policy ID ("nonprod:sandbox"), or a hostname.
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Result<Self> {
        // REC1b1: endpoint is mutually exclusive with the deprecated options
        if self.environment.is_some() || self.rest_host.is_some() || self.realtime_host.is_some() {
            return Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "endpoint cannot be combined with environment, rest_host or realtime_host",
            ));
        }
        self.endpoint = Some(endpoint.into());
        Ok(self)
    }

    /// Deprecated (REC1c): use `endpoint` with a routing policy ID instead.
    pub fn environment(mut self, env: impl Into<String>) -> Result<Self> {
        if self.endpoint.is_some() {
            return Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "endpoint cannot be combined with environment",
            ));
        }
        // REC1c1: environment is mutually exclusive with host overrides
        if self.rest_host.is_some() || self.realtime_host.is_some() {
            return Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "Cannot set both environment and rest_host/realtime_host",
            ));
        }
        self.environment = Some(env.into());
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

    /// Deprecated (REC1d1): use `endpoint` with a hostname instead.
    pub fn rest_host(mut self, host: impl Into<String>) -> Result<Self> {
        if self.environment.is_some() || self.endpoint.is_some() {
            return Err(ErrorInfo::new(
                ErrorCode::BadRequest.code(),
                "Cannot set both rest_host and environment/endpoint",
            ));
        }
        self.rest_host = Some(host.into());
        Ok(self)
    }

    /// REC2a2: explicit fallback hosts override the derived set.
    pub fn fallback_hosts(mut self, hosts: Vec<String>) -> Self {
        self.fallback_hosts = Some(hosts);
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

    /// TO3b: the minimum severity emitted to the log handler (RSC2).
    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.log_level = level;
        self
    }

    /// TO3c: a custom log handler receiving (level, message) events (RSC2c).
    pub fn log_handler(mut self, handler: impl Fn(LogLevel, &str) + Send + Sync + 'static) -> Self {
        self.log_handler = Some(Arc::new(handler));
        self
    }

    pub fn tls(mut self, v: bool) -> Self {
        self.tls = v;
        self
    }

    /// Deprecated (REC1d2): use `endpoint` with a hostname instead.
    pub fn realtime_host(mut self, host: impl Into<String>) -> Self {
        self.realtime_host = Some(host.into());
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

    /// TO3l10: how long a successful fallback host is preferred (RSC15f).
    pub fn fallback_retry_timeout(mut self, timeout: Duration) -> Self {
        self.fallback_retry_timeout = timeout;
        self
    }

    pub fn disconnected_retry_timeout(mut self, timeout: Duration) -> Self {
        self.disconnected_retry_timeout = timeout;
        self
    }

    /// TO3l7-shaped: delay between channel reattach retries (RTL13b).
    pub fn channel_retry_timeout(mut self, timeout: Duration) -> Self {
        self.channel_retry_timeout = timeout;
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

    /// RTN14e: how long a connection may remain DISCONNECTED before being
    /// SUSPENDED. The server's ConnectionDetails value overrides this.
    pub fn connection_state_ttl(mut self, ttl: Duration) -> Self {
        self.connection_state_ttl = ttl;
        self
    }

    pub fn rest(mut self) -> Result<rest::Rest> {
        // Validate credentials
        self.validate_for_rest()?;

        // Use the provided http_client if any, otherwise create a reqwest-based one
        let client: Box<dyn crate::http_client::HttpClient> =
            if let Some(c) = self.http_client.take() {
                c
            } else {
                Box::new(crate::http_client::ReqwestHttpClient::new(
                    self.http_open_timeout,
                ))
            };
        self.build_rest(client)
    }

    pub fn realtime(self) -> Result<crate::realtime::Realtime> {
        crate::realtime::Realtime::new(&self)
    }

    /// Clone the options for embedding in a realtime client. Everything is
    /// cloned except an injected HTTP client (test-only), which cannot be.
    pub(crate) fn clone_for_realtime(&self) -> ClientOptions {
        ClientOptions {
            credential: self.credential.clone(),
            tls: self.tls,
            client_id: self.client_id.clone(),
            use_token_auth: self.use_token_auth,
            endpoint: self.endpoint.clone(),
            environment: self.environment.clone(),
            idempotent_rest_publishing: self.idempotent_rest_publishing,
            fallback_hosts: self.fallback_hosts.clone(),
            format: self.format,
            query_time: self.query_time,
            auth_method: self.auth_method.clone(),
            auth_headers: self.auth_headers.clone(),
            auth_params: self.auth_params.clone(),
            default_token_params: self.default_token_params.clone(),
            auto_connect: self.auto_connect,
            rest_host: self.rest_host.clone(),
            realtime_host: self.realtime_host.clone(),
            primary_host: self.primary_host.clone(),
            resolved_fallback_hosts: self.resolved_fallback_hosts.clone(),
            port: self.port,
            tls_port: self.tls_port,
            echo_messages: self.echo_messages,
            queue_messages: self.queue_messages,
            transport_params: self.transport_params.clone(),
            disconnected_retry_timeout: self.disconnected_retry_timeout,
            suspended_retry_timeout: self.suspended_retry_timeout,
            channel_retry_timeout: self.channel_retry_timeout,
            http_open_timeout: self.http_open_timeout,
            http_request_timeout: self.http_request_timeout,
            realtime_request_timeout: self.realtime_request_timeout,
            connection_state_ttl: self.connection_state_ttl,
            http_max_retry_count: self.http_max_retry_count,
            http_max_retry_duration: self.http_max_retry_duration,
            max_message_size: self.max_message_size,
            max_frame_size: self.max_frame_size,
            fallback_retry_timeout: self.fallback_retry_timeout,
            add_request_ids: self.add_request_ids,
            http_client: None,
            log_level: self.log_level,
            log_handler: self.log_handler.clone(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))] // test-injection path
    pub(crate) fn rest_with_http_client(
        mut self,
        client: Box<dyn crate::http_client::HttpClient>,
    ) -> Result<rest::Rest> {
        self.validate_for_rest()?;
        self.http_client = None;
        self.build_rest(client)
    }

    #[cfg(test)]
    pub(crate) fn rest_with_mock(
        self,
        mock: crate::mock_http::MockHttpClient,
    ) -> Result<rest::Rest> {
        let handle = mock.clone();
        let mut rest = self.rest_with_http_client(Box::new(mock))?;
        std::sync::Arc::get_mut(&mut rest.inner)
            .unwrap()
            .mock_handle = Some(handle);
        Ok(rest)
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

        // RSC18: Basic auth over non-TLS is rejected. A key with a clientId
        // still uses basic auth (RSA7e2), so it is rejected too.
        if !self.tls {
            if let auth::Credential::Key(_) = &self.credential {
                if !self.use_token_auth {
                    return Err(ErrorInfo::new(
                        ErrorCode::InvalidUseOfBasicAuthOverNonTLSTransport.code(),
                        "Basic auth is not permitted over non-TLS transport",
                    ));
                }
            }
        }

        // RSA15a: a TokenDetails clientId must be compatible with the
        // configured clientId ("*" is compatible with anything).
        if let (auth::Credential::TokenDetails(td), Some(opt_cid)) =
            (&self.credential, &self.client_id)
        {
            if let Some(tok_cid) = &td.client_id {
                if tok_cid != "*" && tok_cid != opt_cid {
                    return Err(ErrorInfo::with_status(
                        ErrorCode::IncompatibleCredentials.code(),
                        401,
                        format!(
                            "Token clientId '{}' is incompatible with configured clientId '{}'",
                            tok_cid, opt_cid
                        ),
                    ));
                }
            }
        }

        Ok(())
    }

    /// REC1: resolve the primary domain from endpoint/deprecated options.
    fn resolve_primary_domain(&self) -> (String, PrimaryDomainSource) {
        if let Some(ep) = &self.endpoint {
            // REC1b2: a hostname contains '.', "::", or is "localhost"
            if ep.contains('.') || ep.contains("::") || ep == "localhost" {
                return (ep.clone(), PrimaryDomainSource::Hostname);
            }
            // REC1b3: non-production routing policy "nonprod:[id]"
            if let Some(id) = ep.strip_prefix("nonprod:") {
                return (
                    format!("{}.realtime.ably-nonprod.net", id),
                    PrimaryDomainSource::NonprodPolicy(id.to_string()),
                );
            }
            // REC1b4: production routing policy
            return (
                format!("{}.realtime.ably.net", ep),
                PrimaryDomainSource::ProdPolicy(ep.clone()),
            );
        }
        // REC1c2 (deprecated): environment is a production routing policy ID
        if let Some(env) = &self.environment {
            return (
                format!("{}.realtime.ably.net", env),
                PrimaryDomainSource::ProdPolicy(env.clone()),
            );
        }
        // REC1d (deprecated): explicit host overrides
        if let Some(host) = &self.rest_host {
            return (host.clone(), PrimaryDomainSource::Hostname);
        }
        if let Some(host) = &self.realtime_host {
            return (host.clone(), PrimaryDomainSource::Hostname);
        }
        // REC1a: the default
        (
            DEFAULT_PRIMARY_DOMAIN.to_string(),
            PrimaryDomainSource::Default,
        )
    }

    /// REC1 + REC2: resolve the primary domain and fallback domains.
    pub(crate) fn resolve_hosts(&mut self) {
        let (primary, source) = self.resolve_primary_domain();
        // REC2a2: explicit fallbackHosts win
        let fallbacks = if let Some(hosts) = &self.fallback_hosts {
            hosts.clone()
        } else {
            match source {
                // REC2c1: default fallback domains
                PrimaryDomainSource::Default => ('a'..='e')
                    .map(|c| format!("main.{}.fallback.ably-realtime.com", c))
                    .collect(),
                // REC2c2/REC2c6: explicit hostname — no fallbacks
                PrimaryDomainSource::Hostname => Vec::new(),
                // REC2c3: nonprod routing policy fallbacks
                PrimaryDomainSource::NonprodPolicy(id) => ('a'..='e')
                    .map(|c| format!("{}.{}.fallback.ably-realtime-nonprod.com", id, c))
                    .collect(),
                // REC2c4/REC2c5: production routing policy fallbacks
                PrimaryDomainSource::ProdPolicy(id) => ('a'..='e')
                    .map(|c| format!("{}.{}.fallback.ably-realtime.com", id, c))
                    .collect(),
            }
        };
        self.primary_host = primary;
        self.resolved_fallback_hosts = fallbacks;
    }

    fn build_rest(mut self, client: Box<dyn crate::http_client::HttpClient>) -> Result<rest::Rest> {
        self.resolve_hosts();
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
                saved_auth_options: None,
                forced_token_auth: false,
                time_offset_ms: None,
            }),
            fallback_state: std::sync::Mutex::new(None),
            #[cfg(test)]
            mock_handle: None,
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
            endpoint: None,
            environment: None,
            idempotent_rest_publishing: true, // TO3n: default true for >= 1.2
            fallback_hosts: None,
            format: rest::Format::MessagePack,
            query_time: false,
            auth_method: None,
            auth_headers: Vec::new(),
            auth_params: Vec::new(),
            default_token_params: None,
            auto_connect: true,
            rest_host: None,
            realtime_host: None,
            primary_host: DEFAULT_PRIMARY_DOMAIN.to_string(),
            resolved_fallback_hosts: Vec::new(),
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
            connection_state_ttl: Duration::from_secs(120),
            http_max_retry_count: 3,
            http_max_retry_duration: Duration::from_secs(15),
            max_message_size: 64 * 1024,
            max_frame_size: 512 * 1024,
            fallback_retry_timeout: Duration::from_secs(10 * 60),
            add_request_ids: false,
            http_client: None,
            log_level: LogLevel::Error,
            log_handler: None,
        }
    }
}

impl ClientOptions {
    /// RSC2: emit a log event if a handler is configured and `level` is at
    /// or below the configured severity threshold.
    pub(crate) fn log(&self, level: LogLevel, msg: &str) {
        self.logger().log(level, msg);
    }

    /// A cheap, cloneable logging handle (DESIGN.md Observability policy).
    pub(crate) fn logger(&self) -> Logger {
        Logger {
            level: self.log_level,
            handler: self.log_handler.clone(),
        }
    }
}

/// The library's logging handle: level-gated, lazily formatted, and (with
/// the `tracing` feature) bridged to the `tracing` crate when no explicit
/// handler is installed.
#[derive(Clone)]
pub(crate) struct Logger {
    level: LogLevel,
    handler: Option<LogHandler>,
}

impl Logger {
    pub fn enabled(&self, level: LogLevel) -> bool {
        if level == LogLevel::None || self.level == LogLevel::None || level > self.level {
            return false;
        }
        if self.handler.is_some() {
            return true;
        }
        cfg!(feature = "tracing")
    }

    pub fn log(&self, level: LogLevel, msg: &str) {
        if !self.enabled(level) {
            return;
        }
        if let Some(handler) = &self.handler {
            handler(level, msg);
            return;
        }
        let _ = msg; // used only by the tracing bridge below
        #[cfg(feature = "tracing")]
        match level {
            LogLevel::Error => tracing::error!(target: "ably", "{}", msg),
            LogLevel::Major => tracing::info!(target: "ably", "{}", msg),
            LogLevel::Minor => tracing::debug!(target: "ably", "{}", msg),
            LogLevel::Micro => tracing::trace!(target: "ably", "{}", msg),
            LogLevel::None => {}
        }
    }

    /// Lazily formatted logging: the closure runs only when the level is
    /// enabled — use for Micro/Minor hot paths.
    pub fn lazy(&self, level: LogLevel, f: impl FnOnce() -> String) {
        if self.enabled(level) {
            self.log(level, &f());
        }
    }

    pub fn error(&self, f: impl FnOnce() -> String) {
        self.lazy(LogLevel::Error, f);
    }
    pub fn major(&self, f: impl FnOnce() -> String) {
        self.lazy(LogLevel::Major, f);
    }
    pub fn minor(&self, f: impl FnOnce() -> String) {
        self.lazy(LogLevel::Minor, f);
    }
    pub fn micro(&self, f: impl FnOnce() -> String) {
        self.lazy(LogLevel::Micro, f);
    }
}
