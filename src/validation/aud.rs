use serde::*;

/// Audience identifier.
#[derive(Debug, derive_more::Display, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Aud(pub String);

impl Aud {
    /// Creates a new [Aud] with the given value.
    pub fn new<T: Into<String>>(value: T) -> Aud {
        Aud(value.into())
    }
}
