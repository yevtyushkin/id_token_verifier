use crate::cache::*;
use crate::client::*;
use crate::validation::*;
use serde::Deserialize;

/// ID token verifier configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, bon::Builder)]
pub struct IdTokenVerifierConfig {
    /// JWKS client configuration.
    ///
    /// See [JwksClientConfig] for deserialization semantics.
    pub client: JwksClientConfig,

    /// ID token verifier validation configuration.
    ///
    /// See [ValidationConfig] for deserialization semantics.
    pub validation: ValidationConfig,

    /// JWKS cache configuration.
    ///
    /// Disabled by default. See [JwksCacheConfig] for additional deserialization semantics.
    #[serde(default)]
    #[builder(default)]
    pub cache: JwksCacheConfig,

    /// Name of this verifier to show in traces.
    ///
    /// Defaults to `None`.
    #[cfg(feature = "tracing")]
    pub verifier_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::cache::*;
    use crate::client::*;
    use crate::util::OneOrVec;
    use crate::validation::*;
    use crate::verifier::IdTokenVerifierConfig;
    use backoff_config::*;
    use figment::Figment;
    use figment::providers::Env;
    use std::time::Duration;

    fn from_env() -> figment::Result<IdTokenVerifierConfig> {
        Figment::new()
            .merge(Env::prefixed("PREFIX__").split("__"))
            .extract()
    }

    #[test]
    fn from_env_with_all_variables_set() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("PREFIX__CLIENT__JWKS_URL__Direct", "http://direct.uri");

            jail.set_env("PREFIX__CLIENT__BACKOFF__STRATEGY", "Exponential");
            jail.set_env("PREFIX__CLIENT__BACKOFF__INITIAL_DELAY", "100 ms");
            jail.set_env("PREFIX__CLIENT__BACKOFF__FACTOR", "1.5");
            jail.set_env("PREFIX__CLIENT__BACKOFF__MAX_DELAY", "15 seconds");
            jail.set_env("PREFIX__CLIENT__BACKOFF__MAX_RETRIES", "10");
            jail.set_env("PREFIX__CLIENT__BACKOFF__MAX_TOTAL_DELAY", "100 seconds");
            jail.set_env("PREFIX__CLIENT__BACKOFF__JITTER_ENABLED", "true");
            jail.set_env("PREFIX__CLIENT__BACKOFF__JITTER_SEED", "123");

            jail.set_env("PREFIX__CACHE__ENABLED", "true");
            jail.set_env("PREFIX__CACHE__EXPIRATION_DURATION", "123 seconds");
            jail.set_env("PREFIX__CACHE__BACKGROUND_REFRESH_INTERVAL", "456 seconds");
            jail.set_env("PREFIX__CACHE__RELOAD_ON_JWK_NOT_FOUND", "true");

            jail.set_env("PREFIX__VALIDATION__ALLOWED_ISS", "iss");
            jail.set_env("PREFIX__VALIDATION__ALLOWED_AUD", "[aud, aud2]");
            jail.set_env("PREFIX__VALIDATION__VALIDATE_EXP", "true");
            jail.set_env("PREFIX__VALIDATION__VALIDATE_NBF", "true");
            jail.set_env("PREFIX__VALIDATION__LEEWAY_SECONDS", "789");
            jail.set_env(
                "PREFIX__VALIDATION__ALLOW_MISSING_JWK_ALG_PARAMETER",
                "true",
            );

            jail.set_env("PREFIX__VERIFIER_NAME", "verifier_name");

            assert_eq!(
                from_env()?,
                IdTokenVerifierConfig {
                    client: JwksClientConfig {
                        jwks_url: JwksUrl::Direct("http://direct.uri".parse().unwrap()),
                        backoff: ExponentialBackoffConfig {
                            initial_delay: Duration::from_millis(100),
                            factor: 1.5,
                            max_delay: Duration::from_secs(15),
                            max_retries: 10,
                            max_total_delay: Duration::from_secs(100),
                            jitter_enabled: true,
                            jitter_seed: Some(123),
                        }
                        .into(),
                    },
                    cache: JwksCacheConfig {
                        enabled: true,
                        expiration_duration: Duration::from_secs(123),
                        background_refresh_interval: Some(Duration::from_secs(456)),
                        reload_on_jwk_not_found: true,
                    },
                    validation: ValidationConfig {
                        allowed_iss: OneOrVec::One(Iss("iss".into())),
                        allowed_aud: OneOrVec::Vec(vec![Aud("aud".into()), Aud("aud2".into())]),
                        validate_exp: true,
                        validate_nbf: true,
                        leeway_seconds: 789,
                        allow_missing_jwk_alg_parameter: true,
                    },
                    #[cfg(feature = "tracing")]
                    verifier_name: Some("verifier_name".into()),
                }
            );

            Ok(())
        });
    }

    #[test]
    fn from_env_with_defaults() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("PREFIX__CLIENT__JWKS_URL__Discover", "http://discover.uri");

            jail.set_env("PREFIX__VALIDATION__ALLOWED_ISS", "iss");
            jail.set_env("PREFIX__VALIDATION__ALLOWED_AUD", "[aud, aud2]");

            assert_eq!(
                from_env()?,
                IdTokenVerifierConfig {
                    client: JwksClientConfig {
                        jwks_url: JwksUrl::Discover("http://discover.uri".parse().unwrap()),
                        backoff: default_backoff(),
                    },
                    cache: JwksCacheConfig {
                        enabled: false,
                        expiration_duration: default_expiration_duration(),
                        background_refresh_interval: None,
                        reload_on_jwk_not_found: false,
                    },
                    validation: ValidationConfig {
                        allowed_iss: OneOrVec::One(Iss("iss".into())),
                        allowed_aud: OneOrVec::Vec(vec![Aud("aud".into()), Aud("aud2".into())]),
                        validate_exp: true,
                        validate_nbf: false,
                        leeway_seconds: 60,
                        allow_missing_jwk_alg_parameter: false,
                    },
                    #[cfg(feature = "tracing")]
                    verifier_name: None
                }
            );

            Ok(())
        });
    }

    #[test]
    #[cfg(feature = "tracing")]
    fn builder_with_all_fields_set() {
        let config = IdTokenVerifierConfig::builder()
            .client(
                JwksClientConfig::builder()
                    .jwks_url(JwksUrl::Direct("http://direct.uri".parse().unwrap()))
                    .backoff(
                        ExponentialBackoffConfig {
                            initial_delay: Duration::from_millis(100),
                            factor: 1.5,
                            max_delay: Duration::from_secs(15),
                            max_retries: 10,
                            max_total_delay: Duration::from_secs(100),
                            jitter_enabled: true,
                            jitter_seed: Some(123),
                        }
                        .into(),
                    )
                    .build(),
            )
            .validation(
                ValidationConfig::builder()
                    .allowed_iss(OneOrVec::One(Iss("iss".into())))
                    .allowed_aud(OneOrVec::Vec(vec![Aud("aud".into()), Aud("aud2".into())]))
                    .validate_exp(true)
                    .validate_nbf(true)
                    .leeway_seconds(789)
                    .allow_missing_jwk_alg_parameter(true)
                    .build(),
            )
            .cache(
                JwksCacheConfig::builder()
                    .expiration_duration(Duration::from_secs(123))
                    .background_refresh_interval(Duration::from_secs(456))
                    .reload_on_jwk_not_found(true)
                    .build(),
            )
            .verifier_name("verifier_name".into())
            .build();

        assert_eq!(
            config,
            IdTokenVerifierConfig {
                client: JwksClientConfig {
                    jwks_url: JwksUrl::Direct("http://direct.uri".parse().unwrap()),
                    backoff: ExponentialBackoffConfig {
                        initial_delay: Duration::from_millis(100),
                        factor: 1.5,
                        max_delay: Duration::from_secs(15),
                        max_retries: 10,
                        max_total_delay: Duration::from_secs(100),
                        jitter_enabled: true,
                        jitter_seed: Some(123),
                    }
                    .into(),
                },
                cache: JwksCacheConfig {
                    enabled: true,
                    expiration_duration: Duration::from_secs(123),
                    background_refresh_interval: Some(Duration::from_secs(456)),
                    reload_on_jwk_not_found: true,
                },
                validation: ValidationConfig {
                    allowed_iss: OneOrVec::One(Iss("iss".into())),
                    allowed_aud: OneOrVec::Vec(vec![Aud("aud".into()), Aud("aud2".into())]),
                    validate_exp: true,
                    validate_nbf: true,
                    leeway_seconds: 789,
                    allow_missing_jwk_alg_parameter: true,
                },
                verifier_name: Some("verifier_name".into()),
            }
        );
    }

    #[test]
    #[cfg(feature = "tracing")]
    fn builder_with_default_fields() {
        let config = IdTokenVerifierConfig::builder()
            .client(
                JwksClientConfig::builder()
                    .jwks_url(JwksUrl::Direct("http://direct.uri".parse().unwrap()))
                    .build(),
            )
            .validation(
                ValidationConfig::builder()
                    .allowed_iss(OneOrVec::One(Iss("iss".into())))
                    .allowed_aud(OneOrVec::Vec(vec![Aud("aud".into()), Aud("aud2".into())]))
                    .build(),
            )
            .build();

        assert_eq!(
            config,
            IdTokenVerifierConfig {
                client: JwksClientConfig {
                    jwks_url: JwksUrl::Direct("http://direct.uri".parse().unwrap()),
                    backoff: BackoffConfig::NoBackoff,
                },
                cache: JwksCacheConfig::default(),
                validation: ValidationConfig {
                    allowed_iss: OneOrVec::One(Iss("iss".into())),
                    allowed_aud: OneOrVec::Vec(vec![Aud("aud".into()), Aud("aud2".into())]),
                    validate_exp: default_validate_exp(),
                    validate_nbf: false,
                    leeway_seconds: default_leeway_seconds(),
                    allow_missing_jwk_alg_parameter: false,
                },
                verifier_name: None,
            }
        );
    }
}
