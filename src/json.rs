pub use serde_json::Value;

/// A convenient type alias for a JSON object with string keys.
pub use serde_json::Map as GenericMap;
pub type Map = GenericMap<String, Value>;
