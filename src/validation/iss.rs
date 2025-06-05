use serde::*;

/// Issuer identifier.
#[derive(Debug, derive_more::Display, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Iss(pub String);

impl Iss {
    /// Creates a new [Iss] with the given value.
    pub fn new<T: Into<String>>(value: T) -> Iss {
        Iss(value.into())
    }
}
