use crate::common::{AUD, AUD2, ISS};
use id_token_verifier::cache::{JwksCacheConfig, default_expiration_duration};
use id_token_verifier::client::{JwksClientConfig, default_backoff, JwksUrl};
use id_token_verifier::util::OneOrVec;
use id_token_verifier::validation::{Aud, Iss, ValidationConfig};
use id_token_verifier::verifier::IdTokenVerifierConfig;

/// Default [IdTokenVerifierConfig] to use in tests.
pub fn default_config(jwks_url: JwksUrl, verifier_name: &str) -> IdTokenVerifierConfig {
    IdTokenVerifierConfig {
        client: JwksClientConfig {
            jwks_url,
            backoff: default_backoff(),
        },
        validation: ValidationConfig {
            allowed_iss: OneOrVec::One(Iss(ISS.into())),
            allowed_aud: OneOrVec::Vec(vec![Aud(AUD.into()), Aud(AUD2.into())]),
            validate_exp: true,
            validate_nbf: true,
            leeway_seconds: 60,
            allow_missing_jwk_alg_parameter: false,
        },
        cache: JwksCacheConfig {
            enabled: false,
            expiration_duration: default_expiration_duration(),
            background_refresh_interval: None,
            reload_on_jwk_not_found: false,
        },
        #[cfg(feature = "tracing")]
        verifier_name: Some(verifier_name.into()),
    }
}
