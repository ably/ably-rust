use std::sync::Arc;
use std::time::Duration;

use crate::auth::{AuthCallback, TokenSource};
use crate::error::*;
use crate::{auth, http, rest, Result};

static REST_HOST: &str = "rest.ably.io";

/// [Ably client options] for initialising a REST or Realtime client.
///
/// [Ably client options]: https://ably.com/documentation/rest/types#client-options
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub(crate) token: auth::TokenSource,

    /// The HTTP method to use when requesting a token from auth_url. Defaults
    /// to GET.
    pub(crate) auth_method: http::Method,

    /// The HTTP headers to include when requesting a token from auth_url.
    pub(crate) auth_headers: Option<http::HeaderMap>,

    /// The HTTP params to use when requesting a token from auth_url, which are
    /// included in the query string when auth_method is GET, or in the
    /// form-encoded body when auth_method is POST.
    pub(crate) auth_params: Option<http::UrlQuery>,

    /// Use TLS for all connections. Defaults to true.
    pub(crate) tls: bool,

    /// A client ID, used for identifying this client when publishing messages
    /// or for presence purposes.
    pub(crate) client_id: Option<String>,

    /// Always use token authentication, even if an Ably API key is set.
    pub(crate) use_token_auth: bool,

    /// An optional custom environment used to construct API URLs.
    pub(crate) environment: Option<String>,

    /// Enable idempotent REST publishing. Defaults to false.
    ///
    /// See https://faqs.ably.com/what-is-idempotent-publishing
    pub(crate) idempotent_rest_publishing: bool,

    /// The list of fallback hosts to use in the case of an error necessitating
    /// the use of an alternative host. Defaults to [a-e].ably-realtime.com.
    pub(crate) fallback_hosts: Option<Vec<String>>,

    /// Encode requests using the binary msgpack encoding (true), or the JSON
    /// encoding (false). Defaults to true.
    pub(crate) use_binary_protocol: bool,
    pub(crate) format: rest::Format,

    /// Query the Ably system for the current time when issuing tokens.
    /// Defaults to false.
    pub(crate) query_time: bool,

    /// Override the default parameters used to request Ably tokens.
    pub(crate) default_token_params: Option<auth::TokenParams>,

    /// Automatically connect when the Realtime library is instantiated.
    /// Defaults to true.
    pub(crate) auto_connect: bool,

    // pub queue_messages: bool,
    // pub echo_messages: bool,
    // pub recover: Option<String>,
    /// The hostname used in the REST API URL. Defaults to rest.ably.io.
    pub(crate) rest_host: String,

    /// The hostname used in the Realtime API URL. Defaults to
    /// realtime.ably.io.
    pub(crate) realtime_host: String,

    /// The TCP port for non-TLS requests. Defaults to 80.
    pub(crate) port: u32,

    /// The TCP port for TLS requests. Defaults to 443.
    pub(crate) tls_port: u32,

    /// How long to wait before attempting to re-establish a connection which
    /// is in the DISCONNECTED state. Defaults to 15s.
    pub(crate) disconnected_retry_timeout: Duration,

    /// How long to wait before attempting to re-establish a connection which
    /// is in the SUSPENDED state. Defaults to 30s.
    pub(crate) suspended_retry_timeout: Duration,

    /// How long to wait before attempting to re-attach a channel which is in
    /// the SUSPENDED state following a server initiated detach. Defaults to
    /// 15s.
    pub(crate) channel_retry_timeout: Duration,

    /// How long to wait for a TCP connection to be established. Defaults to
    /// 4s.
    pub(crate) http_open_timeout: Duration,

    /// How long to wait for a HTTP request to be sent and a response to be
    /// received. Defaults to 10s.
    pub(crate) http_request_timeout: Duration,

    /// The maximum number of fallback hosts to try when the primary host is
    /// unreachable or it indicates that the request is unserviceable.
    pub(crate) http_max_retry_count: usize,

    /// How long to wait for fallback requests to succeed before considering
    /// the request as failed. Defaults to 15s.
    pub(crate) http_max_retry_duration: Duration,

    /// The maximum size of messages that can be published in a single request.
    /// Defaults to 64KiB.
    pub(crate) max_message_size: u64,

    /// The maximum size of a single POST body or WebSocket frame. Defaults to
    /// 512KiB.
    pub(crate) max_frame_size: u64,

    /// How long to wait before switching back to the primary host after a
    /// successful request to a fallback endpoint. Defaults to 10m.
    pub(crate) fallback_retry_timeout: Duration,

    /// Include a random request_id in the query string of all API requests.
    /// Defaults to false.
    pub(crate) add_request_ids: bool,

    error: Option<ErrorInfo>,
}

impl ClientOptions {
    pub fn new(s: &str) -> Self {
        match auth::Key::new(s) {
            Ok(k) => Self::key(k),
            Err(_) => Self::token(s.to_string()),
        }
    }

    pub fn auth_url(url: reqwest::Url) -> Self {
        Self::token_source(TokenSource::Url(url))
    }

    pub fn auth_callback(callback: Arc<dyn AuthCallback>) -> Self {
        Self::token_source(TokenSource::Callback(callback))
    }

    /// Sets the API key.
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() -> ably::Result<()> {
    /// let client = ably::ClientOptions::new()
    ///     .key("aaaaaa.bbbbbb:cccccc")
    ///     .client()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn key(key: auth::Key) -> Self {
        Self::token_source(TokenSource::Key(key))
    }

    pub fn token(token: String) -> Self {
        Self::token_source(TokenSource::TokenDetails(auth::TokenDetails::token(token)))
    }

    /// Set the client ID, used for identifying this client when publishing
    /// messages or for presence purposes. Can be any utf-8 string except the
    /// reserved wildcard string '*'.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        let client_id = client_id.into();

        if client_id == "*" {
            self.error = Some(error!(
                40012,
                "Can’t use '*' as a clientId as that string is reserved"
            ));
        } else {
            self.client_id = Some(client_id);
        }

        self
    }

    /// Indicates whether token authentication should be used even if an API
    /// key is present.
    pub fn use_token_auth(mut self, v: bool) -> Self {
        self.use_token_auth = v;
        self
    }

    /// Sets the environment. See [TO3k1].
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() -> ably::Result<()> {
    /// let client = ably::ClientOptions::new()
    ///     .key("aaaaaa.bbbbbb:cccccc")
    ///     .environment("sandbox")
    ///     .client()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Fails if rest_host is already set or if the environment cannot be used
    /// in the REST API URL.
    ///
    /// [T03k1]: https://docs.ably.io/client-lib-development-guide/features/#TO3k1
    pub fn environment(mut self, environment: impl Into<String>) -> Self {
        // Only allow the environment to be set if rest_host is the default.
        if self.rest_host != REST_HOST {
            self.error = Some(error!(40000, "Cannot set both environment and rest_host"));
            return self;
        }

        let environment = environment.into();

        self.rest_host = format!("{}-rest.ably.io", environment);

        // Generate the fallback hosts.
        self.fallback_hosts = Some(vec![
            format!("{}-a-fallback.ably-realtime.com", environment),
            format!("{}-b-fallback.ably-realtime.com", environment),
            format!("{}-c-fallback.ably-realtime.com", environment),
            format!("{}-d-fallback.ably-realtime.com", environment),
            format!("{}-e-fallback.ably-realtime.com", environment),
        ]);

        // Track that the environment was set.
        self.environment = Some(environment);

        self
    }

    /// Sets the message format to MessagePack if the argument is true, or JSON
    /// if the argument is false.
    pub fn use_binary_protocol(mut self, v: bool) -> Self {
        self.use_binary_protocol = v;
        self.format = if v {
            rest::Format::MessagePack
        } else {
            rest::Format::JSON
        };
        self
    }

    /// Set the default TokenParams.
    pub fn default_token_params(mut self, params: auth::TokenParams) -> Self {
        self.default_token_params = Some(params);
        self
    }

    /// Sets the rest_host. See [TO3k2].
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() -> ably::Result<()> {
    /// let client = ably::ClientOptions::new()
    ///     .key("aaaaaa.bbbbbb:cccccc")
    ///     .rest_host("sandbox-rest.ably.io")
    ///     .client()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Fails if environment is already set or if the rest_host cannot be used
    /// in the REST API URL.
    ///
    /// [T03k2]: https://docs.ably.io/client-lib-development-guide/features/#TO3k2
    pub fn rest_host(mut self, rest_host: impl Into<String>) -> Self {
        // Only allow the rest_host to be set if environment isn't set.
        if self.environment.is_some() {
            self.error = Some(error!(40000, "Cannot set both environment and rest_host"));
            return self;
        }

        // TODO: only unset these if they're the defaults
        self.fallback_hosts = None;

        // Track that the rest_host was set.
        self.rest_host = rest_host.into();

        self
    }

    /// Sets the fallback hosts.
    pub fn fallback_hosts(mut self, hosts: Vec<String>) -> Self {
        self.fallback_hosts = Some(hosts);
        self
    }

    /// Sets the HTTP request timeout.
    pub fn http_request_timeout(mut self, timeout: Duration) -> Self {
        self.http_request_timeout = timeout;
        self
    }

    /// Sets the maximum number of HTTP retries.
    pub fn http_max_retry_count(mut self, count: usize) -> Self {
        self.http_max_retry_count = count;
        self
    }

    /// Returns a Rest client using the ClientOptions.
    ///
    /// # Errors
    ///
    /// This method fails if the ClientOptions are not valid:
    ///
    /// - a valid credential must be provided ([RSC1b])
    /// - the REST API URL must be valid
    ///
    /// [RSC1b]: https://docs.ably.io/client-lib-development-guide/features/#RSC1b
    pub fn client(self) -> Result<rest::Rest> {
        if let Some(err) = self.error {
            return Err(err);
        }

        let rest_url = if self.tls {
            format!("https://{}", self.rest_host)
        } else {
            format!("http://{}", self.rest_host)
        };
        let rest_url = reqwest::Url::parse(&rest_url)?;

        let mut default_headers = http::HeaderMap::new();
        default_headers.insert("X-Ably-Version", http::HeaderValue::from_static("1.2"));

        if let Some(client_id) = &self.client_id {
            default_headers.insert("X-Ably-ClientId", base64::encode(client_id).parse()?);
        }

        let http_client = reqwest::Client::builder()
            .default_headers(default_headers)
            .timeout(self.http_request_timeout)
            .connect_timeout(self.http_open_timeout)
            .build()?;

        Ok(rest::Rest::create(http_client, self, rest_url))
    }

    pub fn token_source(token: TokenSource) -> Self {
        Self {
            token,
            auth_method: http::Method::GET,
            auth_headers: None,
            auth_params: None,
            tls: true,
            client_id: None,
            use_token_auth: false,
            environment: None,
            idempotent_rest_publishing: false,
            fallback_hosts: Some(vec![
                "a.ably-realtime.com".to_string(),
                "b.ably-realtime.com".to_string(),
                "c.ably-realtime.com".to_string(),
                "d.ably-realtime.com".to_string(),
                "e.ably-realtime.com".to_string(),
            ]),
            use_binary_protocol: true,
            format: rest::Format::MessagePack,
            query_time: false,
            default_token_params: None,
            auto_connect: true,
            rest_host: REST_HOST.to_string(),
            realtime_host: "realtime.ably.io".to_string(),
            port: 80,
            tls_port: 443,
            disconnected_retry_timeout: Duration::from_secs(15),
            suspended_retry_timeout: Duration::from_secs(30),
            channel_retry_timeout: Duration::from_secs(15),
            http_open_timeout: Duration::from_secs(4),
            http_request_timeout: Duration::from_secs(10),
            http_max_retry_count: 3,
            http_max_retry_duration: Duration::from_secs(15),
            max_message_size: 64 * 1024,
            max_frame_size: 512 * 1024,
            fallback_retry_timeout: Duration::from_secs(10 * 60),
            add_request_ids: false,
            error: None,
        }
    }
}
