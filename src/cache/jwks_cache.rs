use crate::verifier::*;
use jsonwebtoken::jwk::JwkSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

/// Caches [JwkSet]s.
#[derive(Clone)]
pub(crate) struct JwksCache {
    /// Inner structure of the [JwksCache].
    inner: Arc<Inner>,
}

impl JwksCache {
    /// Creates a new [JwksCache] with the given parameters.
    pub(crate) fn new(
        state: Arc<RwLock<Option<JwksCacheState>>>,
        expiration_duration: Duration,
        refresh_job_handle: Option<JoinHandle<()>>,
    ) -> JwksCache {
        JwksCache {
            inner: Arc::new(Inner {
                state,
                expiration_duration,
                refresh_job_handle,
            }),
        }
    }
}

/// Inner structure of the [JwksCache].
struct Inner {
    /// Stores [JwksCacheState] of the [JwksCache].
    state: Arc<RwLock<Option<JwksCacheState>>>,

    /// [Duration] for a [JwksCacheState] to expire.
    expiration_duration: Duration,

    /// [crate::cache::jwks_cache_refresh_job]'s [JoinHandle].
    refresh_job_handle: Option<JoinHandle<()>>,
}

/// State of the [JwksCache].
pub(crate) struct JwksCacheState {
    /// Cached [JwkSet].
    pub jwks: Arc<JwkSet>,

    /// Creation [Instant] of this [JwksCacheState].
    pub created_at: Instant,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Aborts the background refresh job if it is defined.
        self.refresh_job_handle.iter().for_each(JoinHandle::abort);
    }
}

impl JwksCache {
    /// Loads the [JwkSet] from cache. If [JwkSet] is not in cache, or it is expired, loads a
    /// [JwkSet] with the given `load` fn, and puts the result into the cache.
    pub(crate) async fn get_or_load<F, Fut>(
        &self,
        load: F,
    ) -> Result<Arc<JwkSet>, IdTokenVerifierError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<JwkSet, IdTokenVerifierError>>,
    {
        {
            let state = self.inner.state.read().await;
            if let Some(ref cache_state) = *state {
                if cache_state.created_at.elapsed() < self.inner.expiration_duration {
                    return Ok(cache_state.jwks.clone());
                }
            }
        }

        #[cfg(feature = "tracing")]
        tracing::debug!("Expired/missing JWKS cache, reloading");

        let mut state = self.inner.state.write().await;
        let jwks = Arc::new(load().await?);
        *state = Some(JwksCacheState {
            jwks: jwks.clone(),
            created_at: Instant::now(),
        });

        Ok(jwks)
    }

    /// Loads a [JwkSet] with the given `load` fn, and puts the result into the cache.
    pub(crate) async fn reload_with<F, Fut>(
        &self,
        load: F,
    ) -> Result<Arc<JwkSet>, IdTokenVerifierError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<JwkSet, IdTokenVerifierError>>,
    {
        let jwks = Arc::new(load().await?);

        let mut state = self.inner.state.write().await;
        *state = Some(JwksCacheState {
            jwks: jwks.clone(),
            created_at: Instant::now(),
        });

        Ok(jwks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn get_or_load_caches_jwks() -> anyhow::Result<()> {
        let load_count = Arc::new(AtomicUsize::new(0));
        let jwks = JwkSet { keys: Vec::new() };

        let cache = JwksCache::new(Arc::new(RwLock::new(None)), Duration::from_secs(60), None);

        let load = || async {
            load_count.fetch_add(1, Ordering::Relaxed);
            Ok(jwks.clone())
        };

        let result = cache.get_or_load(load).await?;
        assert_eq!(*result, jwks);
        assert_eq!(load_count.load(Ordering::Relaxed), 1);

        for _ in 0..100 {
            let result = cache.get_or_load(load).await?;
            assert_eq!(*result, jwks);
        }
        assert_eq!(load_count.load(Ordering::Relaxed), 1);

        Ok(())
    }

    #[tokio::test]
    async fn get_or_load_reloads_on_expiry() -> anyhow::Result<()> {
        let load_count = Arc::new(AtomicUsize::new(0));
        let jwks = JwkSet { keys: Vec::new() };

        let cache = JwksCache::new(Arc::new(RwLock::new(None)), Duration::from_micros(1), None);

        let load = || async {
            load_count.fetch_add(1, Ordering::Relaxed);
            Ok(jwks.clone())
        };

        let result = cache.get_or_load(load).await?;
        assert_eq!(*result, jwks);
        assert_eq!(load_count.load(Ordering::Relaxed), 1);

        tokio::time::sleep(Duration::from_millis(1)).await;

        let result = cache.get_or_load(load).await?;
        assert_eq!(*result, jwks);
        assert_eq!(load_count.load(Ordering::Relaxed), 2);

        Ok(())
    }

    #[tokio::test]
    async fn reload_with_always_reloads() -> anyhow::Result<()> {
        let load_count = Arc::new(AtomicUsize::new(0));
        let jwks = JwkSet { keys: Vec::new() };

        let cache = JwksCache::new(Arc::new(RwLock::new(None)), Duration::from_secs(60), None);

        let load = || async {
            load_count.fetch_add(1, Ordering::Relaxed);
            Ok(jwks.clone())
        };

        let result = cache.get_or_load(load).await?;
        assert_eq!(*result, jwks);
        assert_eq!(load_count.load(Ordering::Relaxed), 1);

        let result = cache.reload_with(load).await?;
        assert_eq!(*result, jwks);
        assert_eq!(load_count.load(Ordering::Relaxed), 2);

        Ok(())
    }

    #[tokio::test]
    async fn drop_aborts_background_refresh_job_handle() -> anyhow::Result<()> {
        let count = Arc::new(AtomicUsize::new(0));

        let handle = tokio::spawn({
            let count = count.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(100));
                loop {
                    interval.tick().await;
                    count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        let cache = JwksCache::new(
            Arc::new(RwLock::new(None)),
            Duration::from_secs(60),
            Some(handle),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(count.load(Ordering::Relaxed), 1);

        drop(cache);

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(count.load(Ordering::Relaxed), 1);

        Ok(())
    }
}
