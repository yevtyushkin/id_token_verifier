use crate::client::*;
use backon::Retryable;
use jsonwebtoken::jwk::JwkSet;
use std::sync::Arc;

/// [JwkSet] client based on [reqwest::Client].
#[derive(Clone)]
pub(crate) struct JwksClient {
    /// Inner structure of the [JwksClient].
    inner: Arc<Inner>,
}

impl JwksClient {
    /// Creates a new [JwksClient] with the given parameters.
    pub(crate) fn new(client: reqwest::Client, config: JwksClientConfig) -> JwksClient {
        JwksClient {
            inner: Arc::new(Inner { client, config }),
        }
    }
}

/// Internal structure of the [JwksClient].
struct Inner {
    /// [reqwest::Client] for HTTP requests.
    client: reqwest::Client,

    /// Configuration of this [JwksClient].
    config: JwksClientConfig,
}

impl JwksClient {
    /// Fetches the [JwkSet] from the configured [JwksUrl], applying the configured [BackoffConfig].
    pub(crate) async fn fetch(&self) -> Result<JwkSet, JwksClientError> {
        let fetch_fn = || async { self.fetch_inner().await };

        fetch_fn
            .retry(self.inner.config.backoff)
            .notify(|_, d| {
                #[cfg(feature = "tracing")]
                tracing::warn!("Retrying in {}ms", d.as_millis());
            })
            .await
    }

    /// Single attempt fetch [JwkSet] from the configured [JwksUrl] without retries.
    async fn fetch_inner(&self) -> Result<JwkSet, JwksClientError> {
        let jwks_url = match self.inner.config.jwks_url.clone() {
            JwksUrl::Discover(uri) => {
                #[cfg(feature = "tracing")]
                tracing::debug!("Fetching OIDC provider metadata from {uri}");

                self.inner
                    .client
                    .get(uri)
                    .send()
                    .await
                    .map_err(|e| {
                        #[cfg(feature = "tracing")]
                        tracing::error!("OIDC provider metadata request failed: {e}");

                        JwksClientError::OidcProviderMetadataRequestFailed(e)
                    })?
                    .json::<OidcProviderMetadataResponse>()
                    .await
                    .map_err(|e| {
                        #[cfg(feature = "tracing")]
                        tracing::error!("Invalid OIDC provider metadata response: {e}");

                        JwksClientError::InvalidOidcProviderMetadataResponse(e)
                    })?
                    .jwks_uri
            }
            JwksUrl::Direct(uri) => uri,
        };

        #[cfg(feature = "tracing")]
        tracing::debug!("Fetching JWKS from {jwks_url}");

        let jwks = self
            .inner
            .client
            .get(jwks_url)
            .send()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("JWKS request failed: {e}");

                JwksClientError::JwksRequestFailed(e)
            })?
            .json::<JwkSet>()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Invalid JWKS response: {e}");

                JwksClientError::InvalidJwksResponse(e)
            })?;

        Ok(jwks)
    }
}
