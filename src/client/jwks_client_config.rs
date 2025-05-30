use crate::client::JwksUrl;
use backoff_config::BackoffConfig;
use serde::Deserialize;

/// JWKS client configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, bon::Builder)]
pub struct JwksClientConfig {
    /// [JwksUrl] where JWKS can be retrieved.
    ///
    /// Mandatory during deserialization.
    pub jwks_url: JwksUrl,

    /// [BackoffConfig] to apply when fetching the JWKS.
    ///
    /// Defaults to [BackoffConfig::NoBackoff] during deserialization.
    #[serde(default = "default_backoff")]
    #[builder(default = default_backoff())]
    pub backoff: BackoffConfig,
}

/// Default value for [BackoffConfig].
pub const fn default_backoff() -> BackoffConfig {
    BackoffConfig::NoBackoff
}
