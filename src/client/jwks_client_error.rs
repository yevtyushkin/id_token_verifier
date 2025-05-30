/// Possible errors when fetching the JWKS.
#[derive(Debug, thiserror::Error)]
pub enum JwksClientError {
    /// OIDC provider metadata request failed.
    ///
    /// Possible reasons:
    /// - Network error.
    /// - Wrong OIDC provider metadata URL.
    /// - OIDC provider metadata provider is not available.
    #[error("OIDC provider metadata request failed: {0}")]
    OidcProviderMetadataRequestFailed(reqwest::Error),

    /// OIDC provider metadata request succeeded, but it does not match the expected OIDC provider
    /// metadata schema (`response_body["jwks_uri"]` is missing, or is not a valid URL).
    #[error("Invalid OIDC provider metadata response: {0}")]
    InvalidOidcProviderMetadataResponse(reqwest::Error),

    /// JWKS request failed.
    ///
    /// Possible reasons:
    /// - Network error.
    /// - Wrong JWKS URL.
    /// - JWKS provider is not available.
    #[error("JWKS request failed: {0}")]
    JwksRequestFailed(reqwest::Error),

    /// JWKS request succeeded, but it does not match the expected JWKS schema.
    #[error("Invalid JWKS response: {0}")]
    InvalidJwksResponse(reqwest::Error),
}
