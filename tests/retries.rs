mod common;

use crate::common::*;
use axum::Json;
use backoff_config::BackoffConfig;
use id_token_verifier::verifier::IdTokenVerifierDefault;
use jsonwebtoken::Header;
use reqwest::Client;
use serde_json::json;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn retries_when_oidc_metadata_request_fails() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let uris = server.start(test_keys.jwks.clone()).await?;
    let counter = Arc::new(AtomicUsize::new(0));
    let failure = TestServerResponse::Failure(axum::http::StatusCode::NOT_FOUND);
    server.set_oidc_provider_metadata_response(TestServerResponse::Sequence {
        counter: counter.clone(),
        sequence: vec![
            failure.clone(),
            failure.clone(),
            failure.clone(),
            failure.clone(),
            TestServerResponse::Success(Json(json!({
                "jwks_uri": uris.direct_jwks_url.as_ref()
            }))),
        ],
    });

    let http_client = Client::new();
    let mut config = default_config(uris.discover_jwks_url, "retries");
    config.client.backoff = BackoffConfig::Constant {
        delay: Duration::from_millis(200),
        max_retries: 5,
        jitter_enabled: true,
        jitter_seed: None,
    };

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::valid();

    let key = test_keys.encoding_keys[0].clone();

    let mut header = Header::new(key.algorithm);
    header.kid = Some(key.key_id.clone());

    let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

    let id_token_decoded = verifier
        .verify::<TestIdToken>(&id_token_encoded)
        .await?;

    assert_eq!(id_token_decoded, id_token);
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 5);

    Ok(())
}

#[tokio::test]
async fn retries_when_jwks_request_fails() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let uris = server.start(test_keys.jwks.clone()).await?;
    let counter = Arc::new(AtomicUsize::new(0));
    let failure = TestServerResponse::Failure(axum::http::StatusCode::NOT_FOUND);
    server.set_jwks_response(TestServerResponse::Sequence {
        counter: counter.clone(),
        sequence: vec![
            failure.clone(),
            failure.clone(),
            failure.clone(),
            failure.clone(),
            TestServerResponse::Success(Json(serde_json::to_value(test_keys.jwks)?)),
        ],
    });

    let http_client = Client::new();
    let mut config = default_config(uris.discover_jwks_url, "retries");
    config.client.backoff = BackoffConfig::Constant {
        delay: Duration::from_millis(200),
        max_retries: 5,
        jitter_enabled: true,
        jitter_seed: None,
    };

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::valid();

    let key = test_keys.encoding_keys[0].clone();

    let mut header = Header::new(key.algorithm);
    header.kid = Some(key.key_id.clone());

    let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

    let id_token_decoded = verifier
        .verify::<TestIdToken>(&id_token_encoded)
        .await?;

    assert_eq!(id_token_decoded, id_token);
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 5);

    Ok(())
}
