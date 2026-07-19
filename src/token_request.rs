//! The Ably native token-request mechanism (createTokenRequest / requestToken against /keys/.../requestToken). Expected to be deprecated in favour of JWT; isolating it makes that excision clean.

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::auth::{AuthConfig, Key, TokenDetails, TokenParams, TokenRequest};
use crate::error::Result;
use crate::rest::Rest;

type HmacSha256 = Hmac<Sha256>;

impl Rest {
    /// The timestamp for a token request (RSA9d): an explicit timestamp wins;
    /// with queryTime the server clock is used (cached offset if available);
    /// otherwise the local clock.
    pub(crate) async fn token_request_timestamp(
        &self,
        params: &TokenParams,
        cfg: &AuthConfig,
    ) -> Result<i64> {
        if let Some(ts) = params.timestamp {
            return Ok(ts.timestamp_millis());
        }
        if cfg.query_time {
            let cached_offset = self.inner.auth_state.lock().unwrap().time_offset_ms;
            return Ok(match cached_offset {
                Some(offset) => Utc::now().timestamp_millis() + offset,
                None => self.server_time_ms().await?,
            });
        }
        Ok(Utc::now().timestamp_millis())
    }

    /// POST a signed TokenRequest to /keys/{keyName}/requestToken. The signed
    /// request is self-authenticating; no Authorization header is sent.
    pub(crate) async fn exchange_token_request(&self, tr: &TokenRequest) -> Result<TokenDetails> {
        let body = self.serialize_body(tr)?;
        let path = format!("/keys/{}/requestToken", tr.key_name);
        let resp = self
            .do_request_internal("POST", &path, &[], &[], Some(body), None)
            .await?;
        self.deserialize_response(&resp)
    }
}

impl Key {
    /// Sign a TokenRequest (RSA9). Fields not specified in `params` are
    /// omitted from the request (RSA5/RSA6) and signed as empty strings.
    /// `timestamp_ms` must already be resolved (local or server time, RSA9d).
    pub(crate) fn sign_with_timestamp(
        &self,
        params: &TokenParams,
        timestamp_ms: i64,
    ) -> Result<TokenRequest> {
        // RSA5/RSA6: ttl and capability are signed as empty strings and
        // omitted from the TokenRequest when unspecified, so Ably applies
        // the key defaults server-side.
        let ttl_text = params.ttl.map(|t| t.to_string()).unwrap_or_default();
        let capability = params.capability.as_deref().unwrap_or("");
        let client_id = params.client_id.as_deref().unwrap_or("");

        let nonce = match &params.nonce {
            Some(n) => n.clone(),
            None => {
                let mut nonce_bytes = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
                base64::encode(nonce_bytes)
            }
        };

        let sign_text = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n",
            self.name, ttl_text, capability, client_id, timestamp_ms, nonce,
        );

        let mut mac = HmacSha256::new_from_slice(self.value.as_bytes())?;
        mac.update(sign_text.as_bytes());
        let mac_b64 = base64::encode(mac.finalize().into_bytes());

        Ok(TokenRequest {
            key_name: self.name.clone(),
            ttl: params.ttl,
            capability: params.capability.clone(),
            client_id: if client_id.is_empty() {
                None
            } else {
                Some(client_id.to_string())
            },
            timestamp: Some(timestamp_ms),
            nonce,
            mac: mac_b64,
        })
    }

    /// Sign a TokenRequest using the local clock (or the explicit timestamp
    /// in `params`).
    pub fn sign(&self, params: &TokenParams) -> Result<TokenRequest> {
        let timestamp = params
            .timestamp
            .map(|t| t.timestamp_millis())
            .unwrap_or_else(|| Utc::now().timestamp_millis());
        self.sign_with_timestamp(params, timestamp)
    }
}
