/// Delta decoding support for Realtime message compression.
///
/// Spec points: PC3, VD1, VD2.

/// Trait for VCDiff delta decoders. Implementations decode a binary delta
/// against a binary base payload to produce the original message.
pub(crate) trait DeltaDecoder: Send + Sync {
    fn decode(&self, base: &[u8], delta: &[u8]) -> Result<Vec<u8>, String>;
}

/// Real VCDiff decoder using the `vcdiff` crate. Only available when the
/// `vcdiff-deltas` feature is enabled.
#[cfg(feature = "vcdiff-deltas")]
pub(crate) struct RealDecoder;

#[cfg(feature = "vcdiff-deltas")]
impl DeltaDecoder for RealDecoder {
    fn decode(&self, base: &[u8], delta: &[u8]) -> Result<Vec<u8>, String> {
        vcdiff::decode(base, delta).map_err(|e| format!("vcdiff decode error: {}", e))
    }
}

// ---------------------------------------------------------------------------
// Mock encoder/decoder for unit tests (follows UTS mock_vcdiff.md algorithm)
// ---------------------------------------------------------------------------

/// Mock VCDiff encoder for constructing test delta payloads.
/// Uses URL-encoding-based format: `encode(base)/encode(value)`.
#[cfg(test)]
pub(crate) struct MockVcdiffEncoder;

#[cfg(test)]
impl MockVcdiffEncoder {
    /// Encode a string delta: `url_encode(base) + "/" + url_encode(value)`.
    pub fn encode_string(base: &str, value: &str) -> String {
        let encoded_base = url_encode(base);
        let encoded_value = url_encode(value);
        format!("{}/{}", encoded_base, encoded_value)
    }

    /// Encode a binary delta: `base64url(base) + "/" + base64url(value)` as UTF-8 bytes.
    #[allow(dead_code)]
    pub fn encode_binary(base: &[u8], value: &[u8]) -> Vec<u8> {
        let encoded_base = base64url_encode(base);
        let encoded_value = base64url_encode(value);
        format!("{}/{}", encoded_base, encoded_value).into_bytes()
    }
}

/// Mock VCDiff decoder for unit tests. Validates base matches the delta's
/// encoded base, then returns the encoded value.
#[cfg(test)]
pub(crate) struct MockVcdiffDecoder;

#[cfg(test)]
impl DeltaDecoder for MockVcdiffDecoder {
    fn decode(&self, base: &[u8], delta: &[u8]) -> Result<Vec<u8>, String> {
        let delta_str =
            std::str::from_utf8(delta).map_err(|e| format!("Invalid UTF-8 in delta: {}", e))?;
        let parts: Vec<&str> = delta_str.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err("Invalid delta format: expected base/value".to_string());
        }

        // Try string decoding (URL-encoded) first
        if let (Ok(decoded_base), Ok(decoded_value)) = (url_decode(parts[0]), url_decode(parts[1]))
        {
            if decoded_base.as_bytes() == base {
                return Ok(decoded_value.into_bytes());
            }
        }

        // Try binary decoding (base64url-encoded)
        if let (Ok(decoded_base), Ok(decoded_value)) =
            (base64url_decode(parts[0]), base64url_decode(parts[1]))
        {
            if decoded_base == base {
                return Ok(decoded_value);
            }
        }

        Err("Base mismatch: expected base does not match delta".to_string())
    }
}

/// A decoder that always fails, for testing RTL18 recovery.
#[cfg(test)]
pub(crate) struct FailingDecoder;

#[cfg(test)]
impl DeltaDecoder for FailingDecoder {
    fn decode(&self, _base: &[u8], _delta: &[u8]) -> Result<Vec<u8>, String> {
        Err("Simulated vcdiff decode failure".to_string())
    }
}

// ---------------------------------------------------------------------------
// URL encoding/decoding helpers (for mock vcdiff algorithm)
// ---------------------------------------------------------------------------

#[cfg(test)]
fn url_encode(s: &str) -> String {
    let mut encoded = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", b));
            }
        }
    }
    encoded
}

#[cfg(test)]
fn url_decode(s: &str) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut chars = s.bytes().peekable();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next().ok_or("Incomplete percent-encoding")?;
            let h2 = chars.next().ok_or("Incomplete percent-encoding")?;
            let hex = format!("{}{}", h1 as char, h2 as char);
            let byte = u8::from_str_radix(&hex, 16)
                .map_err(|_| format!("Invalid percent-encoding: %{}", hex))?;
            bytes.push(byte);
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 after decoding: {}", e))
}

#[cfg(test)]
fn base64url_encode(data: &[u8]) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

#[cfg(test)]
fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::decode_config(s, base64::URL_SAFE_NO_PAD)
        .map_err(|e| format!("Invalid base64url: {}", e))
}
