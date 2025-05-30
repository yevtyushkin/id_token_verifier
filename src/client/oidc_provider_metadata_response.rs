use serde::*;

/// Minimum required structure of the OIDC provider metadata response.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OidcProviderMetadataResponse {
    /// Direct [url::Url] to fetch the JWKS.
    pub jwks_uri: url::Url,
}
