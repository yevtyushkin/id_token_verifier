use crate::cache::*;
use crate::client::*;
use crate::util::*;
use crate::validation::*;
use crate::verifier::*;

use jsonwebtoken as jwt;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::errors::ErrorKind;
use serde::de::DeserializeOwned;
use std::str::FromStr;
use std::sync::Arc;

/// ID token verifier.
pub trait IdTokenVerifier {
    /// Verifies the given `token` and returns the extracted claims type.
    fn verify<Claims: DeserializeOwned>(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<Claims, IdTokenVerifierError>> + Send;
}

impl IdTokenVerifier for IdTokenVerifierDefault {
    async fn verify<Claims: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<Claims, IdTokenVerifierError> {
        self.verify(token).await
    }
}

/// Default implementation of the ID token verifier.
#[derive(Clone)]
pub struct IdTokenVerifierDefault {
    /// Internal structure of the [IdTokenVerifierDefault].
    inner: Arc<Inner>,
}

/// Internal structure of the [IdTokenVerifierDefault].
struct Inner {
    /// [JwksClient] for fetching JWKS.
    client: JwksClient,

    /// [JwksCache] for caching JWKS.
    cache: Option<JwksCache>,

    /// Whether to reload JWKS cache when a JWK is not found. Works in combination with
    /// `cache`.
    reload_jwks_cache_on_jwk_not_found: bool,

    /// [ValidationConfig] with the validation specification.
    config: ValidationConfig,

    #[cfg(feature = "tracing")]
    /// Name of this verifier to show in traces.
    verifier_name: Option<String>,
}

impl IdTokenVerifierDefault {
    /// Creates a new [IdTokenVerifierDefault] with the given `config` and `http_client`.
    pub fn new(
        config: IdTokenVerifierConfig,
        http_client: reqwest::Client,
    ) -> IdTokenVerifierDefault {
        #[cfg(feature = "tracing")]
        let verifier_name = config.verifier_name;

        let client = JwksClient::new(http_client, config.client);

        let cache = if config.cache.enabled {
            let state = Arc::new(tokio::sync::RwLock::new(None));

            let background_refresh_job_handle =
                config.cache.background_refresh_interval.map(|interval| {
                    jwks_cache_refresh_job(
                        state.clone(),
                        interval,
                        client.clone(),
                        #[cfg(feature = "tracing")]
                        verifier_name.clone(),
                    )
                });

            Some(JwksCache::new(
                state,
                config.cache.expiration_duration,
                background_refresh_job_handle,
            ))
        } else {
            None
        };

        let reload_jwks_cache_on_jwk_not_found = config.cache.reload_on_jwk_not_found;
        let config = config.validation;

        IdTokenVerifierDefault {
            inner: Arc::new(Inner {
                client,
                cache,
                reload_jwks_cache_on_jwk_not_found,
                config,
                #[cfg(feature = "tracing")]
                verifier_name,
            }),
        }
    }
}

impl IdTokenVerifierDefault {
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(
            name = "id_token_verifier",
            skip(self, token),
            fields(verifier_name = self.inner.verifier_name)
        )
    )]
    pub async fn verify<Claims>(&self, token: &str) -> Result<Claims, IdTokenVerifierError>
    where
        Claims: DeserializeOwned,
    {
        let header = jwt::decode_header(token).map_err(|e| {
            #[cfg(feature = "tracing")]
            tracing::warn!("Invalid header: {e}");

            ValidationError::InvalidHeader(e)
        })?;

        let key_id = header.kid.ok_or_else(|| {
            #[cfg(feature = "tracing")]
            tracing::warn!("Missing Key ID (kid)");

            ValidationError::MissingKeyId
        })?;

        #[cfg(feature = "tracing")]
        tracing::debug!("Key ID: {key_id}");

        let fetch_jwks = || async { Ok(self.inner.client.fetch().await?) };
        let mut jwks = {
            if let Some(ref cache) = self.inner.cache {
                SharedOrOwned::Shared(cache.get_or_load(fetch_jwks).await?)
            } else {
                SharedOrOwned::Owned(fetch_jwks().await?)
            }
        };

        #[cfg(feature = "tracing")]
        tracing::debug!("JWKS: {:?}", *jwks);

        let jwk = match (jwks.find(&key_id), &self.inner.cache) {
            (Some(jwk), _) => jwk,

            (None, Some(cache)) if self.inner.reload_jwks_cache_on_jwk_not_found => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Key {key_id} not found, reloading JWKS");

                jwks = SharedOrOwned::Shared(cache.reload_with(fetch_jwks).await?);

                jwks.find(&key_id).ok_or_else(|| {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Key {key_id} not found after reload");

                    ValidationError::KeyNotFound
                })?
            }

            _ => {
                #[cfg(feature = "tracing")]
                tracing::warn!("Key {key_id} not found");

                Err(ValidationError::KeyNotFound)?
            }
        };

        let algorithm = match jwk.common.key_algorithm {
            None if self.inner.config.allow_missing_jwk_alg_parameter => {
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    "JWK does not contain `alg` parameter, defaulting to {:?}",
                    header.alg
                );

                header.alg
            }
            None => {
                #[cfg(feature = "tracing")]
                tracing::error!("JWK does not contain the `alg` parameter");

                Err(ValidationError::MissingJwkAlgParameter)?
            }
            Some(key_algorithm) => jwt::Algorithm::from_str(key_algorithm.to_string().as_str())
                .map_err(|e| {
                    #[cfg(feature = "tracing")]
                    tracing::error!("JWK has unsupported algorithm: {e}");

                    ValidationError::UnsupportedJwkAlgorithm
                })?,
        };

        let validation = {
            let mut validation = jwt::Validation::new(algorithm);
            self.inner.config.apply_into(&mut validation);
            validation
        };

        #[cfg(feature = "tracing")]
        tracing::debug!("Using jsonwebtoken::Validation: {validation:?}");

        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| {
            #[cfg(feature = "tracing")]
            tracing::error!("Failed to create DecodingKey from JWK: {e}");

            ValidationError::InvalidKey(e)
        })?;

        let claims = jwt::decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    "Failed to verify/deserialize claims as {}: {e}",
                    std::any::type_name::<Claims>()
                );

                match e.kind() {
                    ErrorKind::InvalidToken | ErrorKind::Base64(_) | ErrorKind::Utf8(_) => {
                        ValidationError::InvalidIdToken(e)
                    }

                    ErrorKind::InvalidSignature
                    | ErrorKind::Json(_)
                    | ErrorKind::MissingRequiredClaim(_)
                    | ErrorKind::ExpiredSignature
                    | ErrorKind::InvalidIssuer
                    | ErrorKind::InvalidAudience
                    | ErrorKind::InvalidSubject
                    | ErrorKind::ImmatureSignature
                    | ErrorKind::InvalidAlgorithm
                    | ErrorKind::MissingAlgorithm => ValidationError::ValidationFailed(e),

                    ErrorKind::InvalidEcdsaKey
                    | ErrorKind::InvalidRsaKey(_)
                    | ErrorKind::RsaFailedSigning
                    | ErrorKind::InvalidAlgorithmName
                    | ErrorKind::InvalidKeyFormat => ValidationError::InvalidKey(e),

                    _ => ValidationError::Unknown(e),
                }
            })?
            .claims;

        Ok(claims)
    }
}
