/// An error that can occur when verifying the ID token.
#[derive(Debug)]
pub enum Error {
    /// An error that indicates a failed decoding/validation of the ID token.
    IdTokenError {
        /// An [IdTokenErrorKind] of this error.
        kind: IdTokenErrorKind,

        /// An optional source of this error.
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },

    /// An error that indicates a failed fetch of the JWK Set for signature verification.
    JwkSetError {
        /// A [JwkSetErrorKind] of this error.
        kind: JwkSetErrorKind,

        /// An optional source of this error.
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// An error occurred during acquiring the internal cache.
    CacheError,
}

/// A kind of [Error::IdTokenError].
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum IdTokenErrorKind {
    /// An error kind that indicates the header of the ID token is malformed.
    MalformedHeader,

    /// An error kind that indicates the ID token's header is missing the key ID (`kid` claim) to use for signature verification.
    MissingKeyId,

    /// An error kind that indicates the given ID token's signature verification key is not found.
    UnknownSigningKey,

    /// An error kind that indicates the given ID token has failed the validation.
    ValidationError,

    /// An error kind that indicates the given ID token has an invalid payload.
    InvalidPayload,

    /// An error kind for other unexpected errors.
    Unexpected,
}

/// A kind of [Error::JwkSetError].
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum JwkSetErrorKind {
    /// An error kind that indicates a failed request to the auto discovery endpoint.
    AutoDiscoverRequestFailed,

    /// An error kind that indicates a failed request to the JWK Set endpoint.
    JwkSetRequestFailed,

    /// An error kind that indicates one of the returned JWKs is invalid.
    InvalidJwk,
}
