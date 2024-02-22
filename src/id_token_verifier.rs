use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use reqwest::Client as HttpClient;
use serde::de::DeserializeOwned;

use crate::jwk_set_client::{FetchSource, HttpBasedJwkSetClient, JwkSetClient};
use crate::prelude::*;

/// A base trait for ID Token verifiers that receive an ID token and return the [Payload] if verifications succeeds.
pub trait IdTokenVerifier<Payload> {
    /// Verifies the given `id_token`.
    ///
    /// Returns [Ok(Payload)] if verification succeeds or an [Err(Error)] otherwise.
    async fn verify(&self, id_token: &str) -> Result<Payload, Error>;
}

/// A JWT ID token verifier based on the internal [JwkSetClient] for fetching JWK sets for token signature verification.
pub struct JwkBasedJwtIdTokenVerifier<Client>
where
    Client: JwkSetClient,
{
    /// An inner state of this verifier.
    inner: Arc<JwkBasedJwtIdTokenVerifierInner<Client>>,
}

/// A builder that helps to construct a [JwkBasedJwtIdTokenVerifier].
pub struct JwkBasedJwtIdTokenVerifierBuilder {
    /// A [FetchSource] for the [JwkSetClient].
    fetch_source: FetchSource,

    /// A custom [HttpClient] for the [JwkSetClient].
    custom_http_client: Option<HttpClient>,

    /// A [ValidationConfig] with the token validation rules.
    validation_config: ValidationConfig,

    /// An optional [Duration] for the [Cache].
    cache_ttl: Option<Duration>,
}

impl JwkBasedJwtIdTokenVerifierBuilder {
    /// Returns a new instance of the [JwkBasedJwtIdTokenVerifierBuilder] with the given `source`.
    pub fn new(fetch_source: FetchSource) -> JwkBasedJwtIdTokenVerifierBuilder {
        JwkBasedJwtIdTokenVerifierBuilder {
            fetch_source,
            custom_http_client: None,
            validation_config: ValidationConfig {
                valid_issuers: vec![],
                valid_audience: vec![],
            },
            cache_ttl: None,
        }
    }

    /// Applies the given custom [HttpClient] to this builder.
    pub fn with_http_client(
        mut self,
        http_client: HttpClient,
    ) -> JwkBasedJwtIdTokenVerifierBuilder {
        self.custom_http_client = Some(http_client);
        self
    }

    /// Applies the given validation options to this builder.
    pub fn with_validation_options(
        mut self,
        valid_issuers: Vec<String>,
        valid_audience: Vec<String>,
    ) -> JwkBasedJwtIdTokenVerifierBuilder {
        self.validation_config.valid_issuers = valid_issuers;
        self.validation_config.valid_audience = valid_audience;
        self
    }

    /// Applies the given cache options to this builder.
    pub fn with_cache(mut self, cache_ttl: Duration) -> JwkBasedJwtIdTokenVerifierBuilder {
        self.cache_ttl = Some(cache_ttl);
        self
    }

    pub fn build(self) -> JwkBasedJwtIdTokenVerifier<HttpBasedJwkSetClient> {
        let http_client = self.custom_http_client.unwrap_or_else(HttpClient::new);
        let client = HttpBasedJwkSetClient::new(http_client, self.fetch_source);
        let cache = self.cache_ttl.map(|ttl| Cache {
            state: Mutex::new(None),
            ttl,
        });

        JwkBasedJwtIdTokenVerifier {
            inner: Arc::new(JwkBasedJwtIdTokenVerifierInner {
                client,
                validation_config: self.validation_config,
                cache,
            }),
        }
    }
}

/// An inner state of the [JwkBasedJwtIdTokenVerifier].
struct JwkBasedJwtIdTokenVerifierInner<Client>
where
    Client: JwkSetClient,
{
    /// A [JwkSetClient] for fetching [JwkSet]s.
    client: Client,

    /// A [ValidationConfig] with the token validation rules.
    validation_config: ValidationConfig,

    /// An optional [Cache] to limit the number of [JwkSetClient] calls.
    cache: Option<Cache>,
}

impl<Client, Payload> IdTokenVerifier<Payload> for JwkBasedJwtIdTokenVerifier<Client>
where
    Client: JwkSetClient,
    Payload: DeserializeOwned,
{
    async fn verify(&self, token: &str) -> Result<Payload, Error> {
        let header = decode_header(token).map_err(|e| Error::IdTokenError {
            kind: IdTokenErrorKind::MalformedHeader,
            source: Some(e.into()),
        })?;

        let key_id = match header.kid {
            Some(key_id) => key_id,
            None => {
                return Err(Error::IdTokenError {
                    kind: IdTokenErrorKind::MissingKeyId,
                    source: None,
                });
            }
        };

        let jwk_set = match &self.inner.cache {
            Some(cache) => {
                let mut cache_state = cache.state.lock().map_err(|_| Error::CacheError)?;

                match cache_state.deref() {
                    Some(cache_state) if &Utc::now() <= &cache_state.expire_after => {
                        cache_state.jwk_set.clone()
                    }
                    _ => {
                        let jwk_set = Arc::new(self.inner.client.fetch().await?);
                        let expire_after = Utc::now() + cache.ttl.clone();

                        *cache_state.deref_mut() = Some(CacheState {
                            jwk_set: jwk_set.clone(),
                            expire_after,
                        });

                        jwk_set
                    }
                }
            }
            None => Arc::new(self.inner.client.fetch().await?),
        };

        let jwk = match jwk_set.find(&key_id) {
            Some(jwk) => jwk,
            None => {
                return Err(Error::IdTokenError {
                    kind: IdTokenErrorKind::UnknownSigningKey,
                    source: None,
                });
            }
        };

        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| Error::JwkSetError {
            kind: JwkSetErrorKind::InvalidJwk,
            source: e.into(),
        })?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&self.inner.validation_config.valid_issuers);
        validation.set_audience(&self.inner.validation_config.valid_audience);
        validation.leeway = 0;

        let payload: Payload = decode(token, &decoding_key, &validation)
            .map_err(|e| {
                let kind = match e.kind() {
                    ErrorKind::InvalidSignature
                    | ErrorKind::MissingRequiredClaim(_)
                    | ErrorKind::InvalidToken
                    | ErrorKind::ExpiredSignature
                    | ErrorKind::InvalidIssuer
                    | ErrorKind::InvalidAudience
                    | ErrorKind::InvalidSubject
                    | ErrorKind::ImmatureSignature => IdTokenErrorKind::ValidationError,

                    ErrorKind::Json(_) => IdTokenErrorKind::InvalidPayload,

                    _ => IdTokenErrorKind::Unexpected,
                };

                Error::IdTokenError {
                    kind,
                    source: Some(e.into()),
                }
            })?
            .claims;

        Ok(payload)
    }
}

/// A cache used by [JwkBasedJwtIdTokenVerifier].
struct Cache {
    /// An internal state of this cache.
    state: Mutex<Option<CacheState>>,

    /// A [Duration] for calculating when the cached values are expired.
    ttl: Duration,
}

/// An internal state of [Cache].
struct CacheState {
    /// A cached [JwkSet].
    jwk_set: Arc<JwkSet>,

    /// A [DateTime] when the `value` expires.
    expire_after: DateTime<Utc>,
}

/// A configuration of the token payload validation.
pub struct ValidationConfig {
    /// Issuers that are considered valid.
    valid_issuers: Vec<String>,

    /// Audience that is considered valid.
    valid_audience: Vec<String>,
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use std::sync::atomic::{AtomicI8, Ordering};
    use std::sync::{Arc, Mutex};

    use jsonwebtoken::jwk::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::{Deserialize, Serialize};

    use crate::id_token_verifier::{Cache, JwkBasedJwtIdTokenVerifierInner};
    use crate::jwk_set_client::JwkSetClient;
    use crate::prelude::*;

    #[tokio::test]
    async fn test_verification_happy_path() {
        let client = TestJwkSetClient {
            number_of_fetches: Arc::new(AtomicI8::new(0)),
            stub_result: || Ok(jwk_set()),
        };

        let iss = String::from("jwk_id_token_verifier_test_iss");
        let aud = String::from("jwk_id_token_verifier_test_aud");
        let verifier = JwkBasedJwtIdTokenVerifier {
            inner: Arc::new(JwkBasedJwtIdTokenVerifierInner {
                client,
                validation_config: ValidationConfig {
                    valid_issuers: vec![iss.clone()],
                    valid_audience: vec![aud.clone()],
                },
                cache: None,
            }),
        };

        let payload = TestIdTokenPayload {
            exp: Utc::now().timestamp() + 60,
            sub: "user_id_1234509876".into(),
            iss,
            aud,
        };

        let id_token = encode_id_token(&payload);

        let id_token_payload: TestIdTokenPayload = verifier.verify(&id_token).await.unwrap();

        assert_eq!(id_token_payload, payload);
    }

    #[tokio::test]
    async fn test_verification_caching() {
        let mut number_of_fetches = Arc::new(AtomicI8::new(0));
        let client = TestJwkSetClient {
            number_of_fetches: number_of_fetches.clone(),
            stub_result: || Ok(jwk_set()),
        };

        let iss = String::from("jwk_id_token_verifier_test_iss");
        let aud = String::from("jwk_id_token_verifier_test_aud");
        let verifier = JwkBasedJwtIdTokenVerifier {
            inner: Arc::new(JwkBasedJwtIdTokenVerifierInner {
                client,
                validation_config: ValidationConfig {
                    valid_issuers: vec![iss.clone()],
                    valid_audience: vec![aud.clone()],
                },
                cache: Some(Cache {
                    state: Mutex::new(None),
                    ttl: Duration::seconds(3000),
                }),
            }),
        };

        let payload = TestIdTokenPayload {
            exp: Utc::now().timestamp() + 60,
            sub: "user_id_1234509876".into(),
            iss,
            aud,
        };

        let id_token = encode_id_token(&payload);

        let id_token_payload: TestIdTokenPayload = verifier.verify(&id_token).await.unwrap();
        assert_eq!(id_token_payload, payload);
        assert_eq!(number_of_fetches.load(Ordering::Relaxed), 1);

        let id_token_payload: TestIdTokenPayload = verifier.verify(&id_token).await.unwrap();
        assert_eq!(id_token_payload, payload);
        assert_eq!(number_of_fetches.load(Ordering::Relaxed), 1);
    }

    /// Test implementation of [JwkSetClient].
    struct TestJwkSetClient<F>
    where
        F: Fn() -> Result<JwkSet, Error>,
    {
        /// The number of [JwkSetClient::fetch] invocations.
        number_of_fetches: Arc<AtomicI8>,

        /// The stub result to return in [JwkSetClient::fetch] implementation.
        stub_result: F,
    }

    impl<F> JwkSetClient for TestJwkSetClient<F>
    where
        F: Fn() -> Result<JwkSet, Error>,
    {
        async fn fetch(&self) -> Result<JwkSet, Error> {
            self.number_of_fetches.fetch_add(1, Ordering::Relaxed);

            (self.stub_result)()
        }
    }

    /// Test ID Token payload to use in tests.
    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct TestIdTokenPayload {
        /// An issuer of this ID token payload.
        iss: String,

        /// An audience of this ID token payload.
        aud: String,

        /// An expiration timestamp of this ID token payload.
        exp: i64,

        /// A subject of this ID token payload.
        sub: String,
    }

    /// Encodes the given [TestIdTokenPayload] using [encoding_key].
    fn encode_id_token(payload: &TestIdTokenPayload) -> String {
        let encoding_key = encoding_key();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_id().into());

        encode(&header, &payload, &encoding_key).unwrap()
    }

    /// A PEM encoded private key for signing [TestIdTokenPayload]s in tests.
    fn encoding_key() -> EncodingKey {
        EncodingKey::from_rsa_pem(
            r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+E3G+lw8XfDTu
7I/c1ssDwETfYKWwVShEqeBoO98glXKGhBFG4qhV9JluCEzUOFNug4/k7yfRJGLS
QDMAyxX/1R78q+yLZfaOG6YS704jMl+6Cv+h6PDXT4wMcVKFejX+oQZidpLjLq1I
B/y43x6/2HunIp1QsTkWHLDxVflIIXRLQutxFzlbFosRXKjY7aHXgTOZylhsVDnQ
GUcEzZYMD0pQGWSy7ueMrLpF6crqy9yVoZdFUpvA5kJUewfKb40mbkPjqf/TdVSg
N/tGY8YJSJjg1ZxCc853+FcocwDH0GIqMBKjfnYabPGAKTnhKHUCky2gC0UlcT8O
GXnfdKxtAgMBAAECggEAQbqpn9XPAzkRePnXOfARHkfzySc7xMF9/licYI8rtrHX
e8rZyqCAw9Ck6hb2soCT4WifbvSA2WLyxXAr8v9HqUOCxq+RShdFbpkDEhMs+yDl
V4mMIupRtrMsY/UgK0Y6u8XlVlFYtDUk+P7CFxAZKxBqmj5vFkNi0VG0opAvdxB4
3xhz3CDsSGyrU9U7PaZxtEUcBBowmIR8y+KiZVR29zEZ9nf71HADY+w03SdWwG+S
XLmhvxwbetyk83M5YXfz8hEZTJqlyKDCZXvnNDVqDKf3FIn1TWszh/WaGboYC8zG
7eaMdufCQnX7ad7w+XmQ872Utvcn2P54G1DPZM4dQQKBgQD491j+vAUWfO/VIfiZ
CpCmyda+pDdzWlxbWrN2mUGfD/RgyB3EC+K5nunjT4WkQnIfJRo68eVGSZi0rlrx
GlblxB7cvZtaRX/oxWSFnp5HzGVx+dMk4C1WMIF4NDOGMmD8fkONQvOIOjj7mCd9
NoehKAstNsqdr+yNYqHmF/zuXQKBgQDDciwEiQIAPeVsRMJhzgFa8qjLCxQ21WMb
8C4FMfYqeb/JPa3FxCi0IBPpwT3TLuGwYMsnUSK6kKkzDev7ersBevI1DfPH0sR2
41+oNvl2fO9mVa/WmrzuVM2oMAkDKgkJTutDVf1guwCwj+fcFk5uG4txFP9gge3T
Aa2+niQ1UQKBgQDSZ2ek0I2UNb4SZ4VLAWzCKC3+K5ZZPHJ1GjA0+MxGextSd40A
U/MmYDDV1CzjZuw/egGy8x+KyUPu3rMos9PglmBmuS8DmVzCAaA0dJrbntfU/Qb+
UR6/inrAdY1dylHA0YyRY5Wg+WOS7UHiRiVVgxv++CFAJp9J1aNxa7BsWQKBgA0U
fQGosauWeN4wE9o70Tdm+gjsquOokEN0ZYAPgewBzeYH7LNJl3fGlc6VEjAp+Qy2
zaHJ+ksGF2zFR7/CzPUiZ0dJscDzyBY0zVgSpctaPSNaJLR2EqLYphLVdCT0ETrA
P1p4TMbGfRtT5i6Ch6kyyrg8sYKh72qpuBkDuGShAoGBALqQMH+GH882WcyPLgVi
nbN+H0S1NecLZmFWqEg0Vqp9nBdvlPSKkK+Hk3Yu3iYJ3jqB1ogOm7o6NviCK8Ck
ke4653EQJTNaI1JEmtWxfvS2w80S8PxaVfTrkriyc5Kl1GZgtrGSdIbVAVjVFPz1
cJaX/iTiU0KDr93B9Ao2vCkC
-----END PRIVATE KEY-----"#
                .as_bytes(),
        )
        .unwrap()
    }

    /// A [JwkSet] to use in tests.
    fn jwk_set() -> JwkSet {
        JwkSet {
            keys: vec![
                Jwk {
                    common: CommonParameters {
                        public_key_use: Some(PublicKeyUse::Signature),
                        key_algorithm: Some(KeyAlgorithm::RS256),
                        key_id: Some(key_id().to_string()),
                        key_operations: None,
                        x509_url: None,
                        x509_chain: None,
                        x509_sha1_fingerprint: None,
                        x509_sha256_fingerprint: None,
                    },
                    algorithm: AlgorithmParameters::RSA(
                        RSAKeyParameters {
                            key_type: RSAKeyType::RSA,
                            n: "vhNxvpcPF3w07uyP3NbLA8BE32ClsFUoRKngaDvfIJVyhoQRRuKoVfSZbghM1DhTboOP5O8n0SRi0kAzAMsV_9Ue_Kvsi2X2jhumEu9OIzJfugr_oejw10-MDHFShXo1_qEGYnaS4y6tSAf8uN8ev9h7pyKdULE5Fhyw8VX5SCF0S0LrcRc5WxaLEVyo2O2h14EzmcpYbFQ50BlHBM2WDA9KUBlksu7njKy6RenK6svclaGXRVKbwOZCVHsHym-NJm5D46n_03VUoDf7RmPGCUiY4NWcQnPOd_hXKHMAx9BiKjASo352GmzxgCk54Sh1ApMtoAtFJXE_Dhl533SsbQ".to_string(),
                            e: "AQAB".to_string(),
                        }
                    ),
                }
            ]
        }
    }

    /// A key id of the single [Jwk] in [jwk_set].
    fn key_id() -> &'static str {
        "a87fcc83-e46d-4875-a711-0bd8b745a21c"
    }
}
