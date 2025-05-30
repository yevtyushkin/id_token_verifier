/// Possible errors when validating an ID token.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// Invalid ID token header.
    #[error("Invalid ID token header: {0}")]
    InvalidHeader(jsonwebtoken::errors::Error),

    /// ID token is missing the `kid` header.
    #[error("`kid` header is missing")]
    MissingKeyId,

    /// Failed to find JWK with the given ID token's `kid` header in the JWKS.
    #[error("Key is not found")]
    KeyNotFound,

    /// JWK is missing the `alg` parameter, required for the internally used [jsonwebtoken::Validation].
    ///
    /// Consider [crate::validation::ValidationConfig]'s `allow_missing_jwk_alg_header` to skip this validation.
    #[error("Missing JWK `alg` parameter")]
    MissingJwkAlgParameter,

    /// JWK has an unsupported (by the internally used [jsonwebtoken::Validation]) algorithm.
    #[error("Unsupported JWK algorithm")]
    UnsupportedJwkAlgorithm,

    /// JWK is invalid.
    #[error("Invalid JWK: {0}")]
    InvalidKey(jsonwebtoken::errors::Error),

    /// Invalid ID token.
    #[error("Invalid ID token: {0}")]
    InvalidIdToken(jsonwebtoken::errors::Error),

    /// ID token did not pass the verification.
    #[error("ID token verification failed: {0}")]
    ValidationFailed(jsonwebtoken::errors::Error),

    /// An unclassified error.
    #[error("Unclassified error: {0}")]
    Unknown(jsonwebtoken::errors::Error),
}
