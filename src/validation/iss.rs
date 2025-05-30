use serde::*;

/// Issuer identifier.
#[derive(Debug, derive_more::Display, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Iss(pub String);
