use duration_str;
use serde::Deserialize;
use std::time::Duration;

/// JWKS cache configuration.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, bon::Builder)]
pub struct JwksCacheConfig {
    /// Whether cache is enabled.
    ///
    /// Defaults to `false` during deserialization.
    ///
    /// Defaults to `true` when using with [JwksCacheConfigBuilder].
    #[serde(default)]
    #[builder(default = true, setters(vis = ""))]
    pub enabled: bool,

    /// [Duration] for cache entries to expire.
    ///
    /// Defaults to `5 minutes` during deserialization.
    #[serde(
        default = "default_expiration_duration",
        deserialize_with = "duration_str::deserialize_duration"
    )]
    #[builder(default = default_expiration_duration())]
    pub expiration_duration: Duration,

    /// Interval [Duration] of the cache refresh job.
    ///
    /// Defaults to `None` during deserialization.
    #[serde(default, deserialize_with = "deserialize_optional_duration")]
    pub background_refresh_interval: Option<Duration>,

    /// Whether to reload JWKS cache when the JWK not found.
    ///
    /// Defaults to `false` during deserialization.
    #[serde(default)]
    #[builder(default = false)]
    pub reload_on_jwk_not_found: bool,
}

impl Default for JwksCacheConfig {
    fn default() -> JwksCacheConfig {
        JwksCacheConfig {
            enabled: false,
            expiration_duration: default_expiration_duration(),
            background_refresh_interval: None,
            reload_on_jwk_not_found: false,
        }
    }
}

/// Default value of JWKS cache expiration duration.
pub const fn default_expiration_duration() -> Duration {
    Duration::from_secs(60 * 5)
}

/// [serde::Deserializer] for `Option::<Duration>` using [duration_str].
fn deserialize_optional_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt_str: Option<String> = Option::deserialize(deserializer)?;
    match opt_str {
        Some(s) => duration_str::parse_std(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}
