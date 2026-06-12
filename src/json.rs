pub use serde_json::Value;

/// A convenient type alias for a JSON object with string keys.
#[cfg_attr(not(test), allow(dead_code))] // test-facing alias
pub type Map = serde_json::Map<String, Value>;
