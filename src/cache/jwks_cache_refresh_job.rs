use crate::cache::*;
use crate::client::JwksClient;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Starts a [JwksCache] refresh job in background fetching a [jsonwebtoken::jwk::JwkSet]
/// every `refresh_interval` and writing it to the corresponding [JwksCache]'s `state`.
pub(crate) fn jwks_cache_refresh_job(
    state: Arc<RwLock<Option<JwksCacheState>>>,
    refresh_interval: Duration,
    client: JwksClient,
    #[cfg(feature = "tracing")] verifier_name: Option<String>,
) -> tokio::task::JoinHandle<()> {
    #[cfg(feature = "tracing")]
    tracing::info!(
        verifier_name = verifier_name,
        "Starting JWKS cache refresh job",
    );

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(refresh_interval);

        loop {
            interval.tick().await;

            let start = Instant::now();

            match client.fetch().await {
                Ok(jwks) => {
                    let mut state = state.write().await;

                    *state = Some(JwksCacheState {
                        jwks: Arc::new(jwks),
                        created_at: Instant::now(),
                    });

                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        verifier_name = verifier_name,
                        "JWKS cache successfully refreshed in {}ms",
                        start.elapsed().as_millis()
                    );
                }
                Err(e) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        verifier_name = verifier_name,
                        "Failed to refresh JWKS cache, took {}ms, error: {e:?}",
                        start.elapsed().as_millis()
                    );
                }
            }
        }
    })
}
