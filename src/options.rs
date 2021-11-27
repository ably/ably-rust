use crate::error::*;
use crate::{auth, http, rest, Result};

use std::convert::TryInto;
use std::time::Duration;

/// [Ably client options] for initialising a REST or Realtime client.
///
/// [Ably client options]: https://ably.com/documentation/rest/types#client-options
#[derive(Clone, Debug)]
pub struct ClientOptions {
    /// Holds either an API key or a token.
    credential: Result<auth::Credential>,

    /// The message format (either MessagePack or JSON).
    format: rest::Format,

    /// An optional custom environment used to construct the endpoint URLs.
    environment: Option<String>,

    /// Override the hostname used in the REST API URL.
    rest_host: Option<String>,

    /// Override the list of fallback hosts.
    fallback_hosts: Option<Vec<String>>,

    /// The REST API URL which is constructed as options are set. Any error
    /// encountered when updating rest_url will be returned from client().
    rest_url: Result<reqwest::Url>,

    http_request_timeout: Duration,

    /// The maximum number of fallback hosts to try when the primary host is
    /// unreachable or it indicates that the request is unserviceable.
    http_max_retry_count: u32,
}

const DEFAULT_HTTP_MAX_RETRY_COUNT: u32 = 3;
const DEFAULT_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

impl ClientOptions {
    /// Returns ClientOptions with default values.
    pub fn new() -> Self {
        Self {
            credential:           Err(error!(40106, "must provide either an API key or a token")),
            format:               rest::DEFAULT_FORMAT,
            environment:          None,
            rest_host:            None,
            fallback_hosts:       Some(Self::default_fallback_hosts()),
            rest_url:             Ok(reqwest::Url::parse("https://rest.ably.io").unwrap()),
            http_request_timeout: DEFAULT_HTTP_REQUEST_TIMEOUT,
            http_max_retry_count: DEFAULT_HTTP_MAX_RETRY_COUNT,
        }
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
    pub fn key<T>(mut self, key: T) -> Self
    where
        T: TryInto<auth::Key>,
        T::Error: Into<ErrorInfo>,
    {
        self.credential = key
            .try_into()
            .map(|k| auth::Credential::Key(k))
            .map_err(Into::into);
        self
    }

    /// Sets the token.
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() -> ably::Result<()> {
    /// let client = ably::ClientOptions::new()
    ///     .token("aaaaaa.dddddddddddd")
    ///     .client()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn token(mut self, token: &str) -> Self {
        self.credential = Ok(auth::Credential::Token(String::from(token)));
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
    pub fn environment(mut self, environment: &str) -> Self {
        // Only allow the environment to be set if rest_host isn't set.
        if self.rest_host.is_some() {
            self.rest_url = Err(error!(40000, "Cannot set both environment and rest_host"));
            return self;
        }

        // Update the host in the URL if we haven't yet encountered an error.
        if let Ok(ref mut url) = self.rest_url {
            let host = format!("{}-rest.ably.io", environment);

            if let Err(err) = url.set_host(Some(host.as_ref())) {
                self.rest_url = Err(error!(
                    40000,
                    format!("Invalid environment '{}' ({})", environment, err)
                ));
                return self;
            }
        }

        // Generate the fallback hosts
        self.fallback_hosts = Some(vec![
            format!("{}-a-fallback.ably-realtime.com", environment),
            format!("{}-b-fallback.ably-realtime.com", environment),
            format!("{}-c-fallback.ably-realtime.com", environment),
            format!("{}-d-fallback.ably-realtime.com", environment),
            format!("{}-e-fallback.ably-realtime.com", environment),
        ]);

        // Track that the environment was set.
        self.environment = Some(String::from(environment));

        self
    }

    /// Sets the message format to MessagePack if the argument is true, or JSON
    /// if the argument is false.
    pub fn use_binary_protocol(mut self, binary: bool) -> Self {
        if binary {
            self.format = rest::Format::MessagePack;
        } else {
            self.format = rest::Format::JSON;
        }
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
    pub fn rest_host(mut self, rest_host: &str) -> Self {
        // Only allow the rest_host to be set if environment isn't set.
        if self.environment.is_some() {
            self.rest_url = Err(error!(40000, "Cannot set both environment and rest_host"));
            return self;
        }

        // Update the host in the URL if we haven't yet encountered an error.
        if let Ok(ref mut url) = self.rest_url {
            if let Err(err) = url.set_host(Some(rest_host)) {
                self.rest_url = Err(error!(
                    40000,
                    format!("Invalid rest_host '{}' ({})", rest_host, err)
                ));
                return self;
            }
        }

        // TODO: only unset these if they're the defaults
        self.fallback_hosts = None;

        // Track that the rest_host was set.
        self.rest_host = Some(String::from(rest_host));

        self
    }

    pub fn fallback_hosts(mut self, hosts: Vec<String>) -> Self {
        self.fallback_hosts = Some(hosts);
        self
    }

    pub fn http_request_timeout(mut self, timeout: Duration) -> Self {
        self.http_request_timeout = timeout;
        self
    }

    pub fn http_max_retry_count(mut self, count: u32) -> Self {
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
        let credential = self.credential?;
        let url = self.rest_url.clone()?;
        let http = http::Client::new(
            reqwest::Client::builder()
                .timeout(self.http_request_timeout)
                .build()?,
            url.clone(),
            self.fallback_hosts,
        );
        let auth = auth::Auth::new(credential, http.clone());
        let client = rest::Client::new(auth.clone(), http, self.format);
        let channels = rest::Channels::new(client.clone());

        Ok(rest::Rest {
            auth,
            channels,
            client,
        })
    }

    fn default_fallback_hosts() -> Vec<String> {
        vec![
            "a.ably-realtime.com".to_string(),
            "b.ably-realtime.com".to_string(),
            "c.ably-realtime.com".to_string(),
            "d.ably-realtime.com".to_string(),
            "e.ably-realtime.com".to_string(),
        ]
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
    /// let options = ably::ClientOptions::from("uTNfLQ.ms51fw:****************");
    /// ```
    ///
    /// ```
    /// // Initialise ClientOptions with a token.
    /// let options = ably::ClientOptions::from("uTNfLQ.Gup2lu*********PYcwUb");
    /// ```
    ///
    /// [RSC1a]: https://docs.ably.io/client-lib-development-guide/features/#RSC1a
    fn from(s: &str) -> Self {
        let options = Self::new();

        match s.find(':') {
            Some(_) => options.key(s),
            None => options.token(s),
        }
    }
}
