use crate::client::*;
use crate::validation::*;

/// Top-level error when verifying an ID token.
#[derive(Debug, thiserror::Error)]
pub enum IdTokenVerifierError {
    /// Something went wrong when fetching the JWKS.
    #[error("Client error: {0}")]
    Client(#[from] JwksClientError),

    /// Something went wrong when validating the ID token.
    #[error("Verification error: {0}")]
    Validation(#[from] ValidationError),
}
