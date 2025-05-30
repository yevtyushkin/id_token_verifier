use serde::*;

/// Audience identifier.
#[derive(Debug, derive_more::Display, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Aud(pub String);
