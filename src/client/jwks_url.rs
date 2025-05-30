use serde::*;

/// Possible types of URIs JWKS can be fetched from.
#[derive(Clone, derive_more::Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JwksUrl {
    /// Discover JWKS URL through OIDC provider metadata document (`metadata["jwks_uri"]`).
    Discover(#[debug("{}", _0)] url::Url),

    /// Direct JWKS URL.
    Direct(#[debug("{}", _0)] url::Url),
}

impl AsRef<url::Url> for JwksUrl {
    fn as_ref(&self) -> &url::Url {
        match self {
            JwksUrl::Discover(uri) => uri,
            JwksUrl::Direct(uri) => uri,
        }
    }
}
