pub use serde_json::Value;

/// A convenient type alias for a JSON object with string keys.
pub type Map = serde_json::Map<String, Value>;
