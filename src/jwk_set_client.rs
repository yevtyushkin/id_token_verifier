use std::sync::Arc;

use jsonwebtoken::jwk::JwkSet;
use reqwest::{Client as HttpClient, Url};
use serde::Deserialize;

use crate::prelude::*;

/// A base trait for [JwkSet] clients.
pub trait JwkSetClient {
    /// Fetches the [JwkSet].
    async fn fetch(&self) -> Result<JwkSet, Error>;
}

/// An [HttpClient]-based implementation of the [JwkSetClient].
pub struct HttpBasedJwkSetClient {
    /// An internal state of the [HttpBasedJwkSetClient].
    inner: Arc<HttpBasedJwkSetClientInner>,
}

impl HttpBasedJwkSetClient {
    /// Returns a new instance of the [HttpBasedJwkSetClient] with the given [HttpClient] and [FetchSource].
    pub fn new(http_client: HttpClient, fetch_source: FetchSource) -> Self {
        Self {
            inner: Arc::new(HttpBasedJwkSetClientInner {
                http_client,
                fetch_source,
            }),
        }
    }
}

impl JwkSetClient for HttpBasedJwkSetClient {
    async fn fetch(&self) -> Result<JwkSet, Error> {
        let url = match &self.inner.fetch_source {
            FetchSource::AutoDiscover { url } => self.auto_discover_jwk_set_url(url).await?,
            FetchSource::Direct { url } => url.clone(),
        };

        let response =
            self.inner
                .http_client
                .get(url)
                .send()
                .await
                .map_err(|e| Error::JwkSetError {
                    kind: JwkSetErrorKind::JwkSetRequestFailed,
                    source: e.into(),
                })?;

        let jwk_set = response
            .json::<JwkSet>()
            .await
            .map_err(|e| Error::JwkSetError {
                kind: JwkSetErrorKind::JwkSetRequestFailed,
                source: e.into(),
            })?;

        Ok(jwk_set)
    }
}

impl HttpBasedJwkSetClient {
    /// Attempts to auto discover the request [Url] for fetching [JwkSet]s.
    async fn auto_discover_jwk_set_url(&self, url: &Url) -> Result<Url, Error> {
        let response = self
            .inner
            .http_client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| Error::JwkSetError {
                kind: JwkSetErrorKind::AutoDiscoverRequestFailed,
                source: e.into(),
            })?;

        let jwks_uri_response =
            response
                .json::<JwksUriResponse>()
                .await
                .map_err(|e| Error::JwkSetError {
                    kind: JwkSetErrorKind::AutoDiscoverRequestFailed,
                    source: e.into(),
                })?;

        let url = Url::parse(&jwks_uri_response.jwks_uri).map_err(|e| Error::JwkSetError {
            kind: JwkSetErrorKind::AutoDiscoverRequestFailed,
            source: e.into(),
        })?;

        Ok(url)
    }
}

/// A response from the [FetchSource::AutoDiscover].
#[derive(Deserialize)]
struct JwksUriResponse {
    /// A raw [Url] to follow for fetching [JwkSet]s.
    jwks_uri: String,
}

/// An internal state of the [HttpBasedJwkSetClient].
struct HttpBasedJwkSetClientInner {
    /// An [HttpClient] for fetching [JwkSet]s.
    http_client: HttpClient,

    /// A [FetchSource] for fetching [JwkSet]s.
    fetch_source: FetchSource,
}

/// A source for fetching JWK sets.
pub enum FetchSource {
    /// A [FetchSource] that follows the `jwks_uri` field from the response for fetching [JwkSet]s (see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
    AutoDiscover { url: Url },

    /// A direct URL [FetchSource].
    Direct { url: Url },
}

#[cfg(test)]
mod tests {
    use crate::jwk_set_client::*;
    use crate::prelude::Error;
    use axum::routing::get;
    use axum::{Json, Router};
    use jsonwebtoken::jwk::*;
    use reqwest::Client;
    use std::sync::Arc;
    use url::Url;

    #[tokio::test]
    #[serial_test::serial]
    async fn test_direct_happy_path() {
        let app = Router::new().route("/jwks", get(valid_jwk_set_endpoint));
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = HttpBasedJwkSetClient {
            inner: Arc::new(HttpBasedJwkSetClientInner {
                http_client: Client::new(),
                fetch_source: FetchSource::Direct {
                    url: Url::parse("http://0.0.0.0:3000/jwks").unwrap(),
                },
            }),
        };

        let result = client.fetch().await.unwrap();

        assert_eq!(result, test_jwk_set());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_direct_jwk_set_endpoint_returns_invalid_response() {
        let app = Router::new().route("/jwks", get(invalid_jwk_set_endpoint));
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = HttpBasedJwkSetClient {
            inner: Arc::new(HttpBasedJwkSetClientInner {
                http_client: Client::new(),
                fetch_source: FetchSource::Direct {
                    url: Url::parse("http://0.0.0.0:3000/jwks").unwrap(),
                },
            }),
        };

        let result = client.fetch().await;

        assert!(matches!(
            result,
            Err(Error::JwkSetError {
                source: _,
                kind: JwkSetErrorKind::JwkSetRequestFailed
            })
        ));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_auto_discover_happy_path() {
        let app = Router::new()
            .route("/auto-discover", get(valid_auto_discover_endpoint))
            .route("/jwks", get(valid_jwk_set_endpoint));
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = HttpBasedJwkSetClient {
            inner: Arc::new(HttpBasedJwkSetClientInner {
                http_client: Client::new(),
                fetch_source: FetchSource::AutoDiscover {
                    url: Url::parse("http://0.0.0.0:3000/auto-discover").unwrap(),
                },
            }),
        };

        let result = client.fetch().await.unwrap();

        assert_eq!(result, test_jwk_set());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_auto_discover_auto_discover_endpoint_returns_invalid_response() {
        let app = Router::new()
            .route("/auto-discover", get(invalid_auto_discover_endpoint))
            .route("/jwks", get(valid_jwk_set_endpoint));
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = HttpBasedJwkSetClient {
            inner: Arc::new(HttpBasedJwkSetClientInner {
                http_client: Client::new(),
                fetch_source: FetchSource::AutoDiscover {
                    url: Url::parse("http://0.0.0.0:3000/auto-discover").unwrap(),
                },
            }),
        };

        let result = client.fetch().await;

        assert!(matches!(
            result,
            Err(Error::JwkSetError {
                source: _,
                kind: JwkSetErrorKind::AutoDiscoverRequestFailed
            })
        ));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_auto_discover_url_invalid_jwks_uri() {
        let app = Router::new()
            .route(
                "/auto-discover",
                get(invalid_jwks_uri_auto_discover_endpoint),
            )
            .route("/jwks", get(valid_jwk_set_endpoint));
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = HttpBasedJwkSetClient {
            inner: Arc::new(HttpBasedJwkSetClientInner {
                http_client: Client::new(),
                fetch_source: FetchSource::AutoDiscover {
                    url: Url::parse("http://0.0.0.0:3000/auto-discover").unwrap(),
                },
            }),
        };

        let result = client.fetch().await;

        assert!(matches!(
            result,
            Err(Error::JwkSetError {
                source: _,
                kind: JwkSetErrorKind::AutoDiscoverRequestFailed
            })
        ));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_auto_discover_url_invalid_jwk_set_response() {
        let app = Router::new()
            .route("/auto-discover", get(valid_auto_discover_endpoint))
            .route("/jwks", get(invalid_jwk_set_endpoint));
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = HttpBasedJwkSetClient {
            inner: Arc::new(HttpBasedJwkSetClientInner {
                http_client: Client::new(),
                fetch_source: FetchSource::AutoDiscover {
                    url: Url::parse("http://0.0.0.0:3000/auto-discover").unwrap(),
                },
            }),
        };

        let result = client.fetch().await;

        assert!(matches!(
            result,
            Err(Error::JwkSetError {
                source: _,
                kind: JwkSetErrorKind::JwkSetRequestFailed
            })
        ));
    }

    /// An arbitrary [JwkSet] to use in tests.
    fn test_jwk_set() -> JwkSet {
        JwkSet {
            keys: vec![
                Jwk {
                    common: CommonParameters {
                        public_key_use: Some(PublicKeyUse::Signature),
                        key_algorithm: Some(KeyAlgorithm::RS256),
                        key_id: Some("48a63bc4767f8550a532dc630cf7eb49ff397e7c".to_string()),
                        key_operations: None,
                        x509_url: None,
                        x509_chain: None,
                        x509_sha1_fingerprint: None,
                        x509_sha256_fingerprint: None,
                    },
                    algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                        key_type: RSAKeyType::RSA,
                        n: "qwrzl06fwB6OIm62IxNG7NXNIDmgdBrvf09ob2Gsp6ZmAXgU4trHPUYrdBaAlU5aHpchXCf_mVL-U5dzRqeVFQsVqsj4PEIE6E5OPw8EwumP2fzLQSswpkKmJJKFcdncfQ730QBonRUEhKkIbiYdicJl5yTkORd0_BmfdLV98r-sEwEHN4lzTJ15-yw90ob_R6vAH4wPyCSN3Xe5_zV6R4ENL2NlKn2HT9lbV7HhtQongea8wfnthUhdZH38kI4SS5nAaCVNxEAzlvJtUIdCpSgjUgcbah-DwY39l4D800kLxkcF2CGXPSmpF8GPs1aWSsYupY8sTSy9qCFJFPFx8Q".to_string(),
                        e: "AQAB".to_string(),
                    }),
                },
                Jwk {
                    common: CommonParameters {
                        public_key_use: Some(PublicKeyUse::Signature),
                        key_algorithm: Some(KeyAlgorithm::RS256),
                        key_id: Some("85e55107466b7e29836199c58c7581f5b923be44".to_string()),
                        key_operations: None,
                        x509_url: None,
                        x509_chain: None,
                        x509_sha1_fingerprint: None,
                        x509_sha256_fingerprint: None,
                    },
                    algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                        key_type: RSAKeyType::RSA,
                        n: "4tVDrq5RbeDtlJ2Xh2dikE840LWflr89Cm3cGI9mQGlskTigV0anoViOH92Z1sqWAp5e1aRkLlCm-KAWc69uvOW_X70jEhzDJVREeB3h-RAnzxYrbUgDEgltiUaM8Zxtt8hiVh_GDAudRmSP9kDxXL5xnJETF1gnwAHa0j7cM4STLKbtwKi73CEmTjTLqGAES8XVnXp8VWGb6IuQzdmBIJkfcFog4Inq93F4Cj_SXsSjECG3j56VxgwnloPCHTXVn_xS1s3OjoBCOvOVSJfg2nSTWNi93JGR9pWZevh7Sq8Clw8H2lvIAPV_HYdxvsucWg8sJuTa6ZZSxT1WmBkW6Q".to_string(),
                        e: "AQAB".to_string(),
                    }),
                },
            ]
        }
    }

    /// Returns a valid [JwkSet] response.
    async fn valid_jwk_set_endpoint() -> Json<JwkSet> {
        Json(test_jwk_set())
    }

    /// Returns an invalid [JwkSet] response.
    async fn invalid_jwk_set_endpoint() -> &'static str {
        r#"{ "someKey1234": [ ] }"#
    }

    /// Returns a valid auto discover response.
    async fn valid_auto_discover_endpoint() -> &'static str {
        r#" { "jwks_uri" : "http://0.0.0.0:3000/jwks" } "#
    }

    /// Returns an auto discover response with the invalid structure.
    async fn invalid_auto_discover_endpoint() -> &'static str {
        r#" { "123jwksUUri" : "http://0.0.0.0:3000/jwks" } "#
    }

    /// Returns an auto discover response with the invalid `jwks_uri` value.
    async fn invalid_jwks_uri_auto_discover_endpoint() -> &'static str {
        r#" { "jwks_uri" : "http: 0.0.0.0:3000 / jwks" } "#
    }
}
