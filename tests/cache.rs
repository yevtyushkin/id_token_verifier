mod common;

use crate::common::*;
use axum::Json;
use id_token_verifier::verifier::{ IdTokenVerifierDefault};
use jsonwebtoken::Header;
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

#[tokio::test]
async fn background_refresh_job() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let uris = server.start(test_keys.jwks).await?;

    let counter = Arc::new(AtomicUsize::new(0));
    // first request succeeds, further ones fail
    server.set_oidc_provider_metadata_response(TestServerResponse::Sequence {
        counter: counter.clone(),
        sequence: vec![
            TestServerResponse::Success(Json(json!({
                "jwks_uri": uris.direct_jwks_url.as_ref()
            }))),
            TestServerResponse::Failure(axum::http::StatusCode::NOT_FOUND),
        ],
    });

    let http_client = Client::new();
    let mut config = default_config(uris.discover_jwks_url, "background-refresh-job");
    config.cache.enabled = true;
    config.cache.background_refresh_interval = Some(Duration::from_secs(30));

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::valid();

    let key = test_keys.encoding_keys[0].clone();

    let mut header = Header::new(key.algorithm);
    header.kid = Some(key.key_id.clone());

    let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

    tokio::time::sleep(Duration::from_secs(1)).await;
    // Background refresh job should have already refreshed the cache
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 1);

    let id_token_decoded = verifier
        .verify::<TestIdToken>(&id_token_encoded)
        .await?;

    assert_eq!(id_token_decoded, id_token);
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 1);

    Ok(())
}

#[tokio::test]
async fn regular_cache() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let uris = server.start(test_keys.jwks).await?;

    let counter = Arc::new(AtomicUsize::new(0));
    // first request succeeds, further ones fail
    server.set_oidc_provider_metadata_response(TestServerResponse::Sequence {
        counter: counter.clone(),
        sequence: vec![
            TestServerResponse::Success(Json(json!({
                "jwks_uri": uris.direct_jwks_url.as_ref()
            }))),
            TestServerResponse::Failure(axum::http::StatusCode::NOT_FOUND),
        ],
    });

    let http_client = Client::new();
    let mut config = default_config(uris.discover_jwks_url, "regular-cache");
    config.cache.enabled = true;
    config.cache.expiration_duration = Duration::from_secs(30);

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
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 1);

    let mut id_token2 = TestIdToken::valid();
    id_token2.aud = Some(AUD2.into());

    let id_token_encoded = jsonwebtoken::encode(&header, &id_token2, &key.encoding_key)?;

    let id_token_decoded2 = verifier
        .verify::<TestIdToken>(&id_token_encoded)
        .await?;

    assert_eq!(id_token_decoded2, id_token2);
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 1);

    Ok(())
}

#[tokio::test]
async fn regular_cache_reload_on_jwk_not_found() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let test_keys_new = TestKeys::rsa()?;
    let uris = server.start(test_keys.jwks.clone()).await?;

    let counter = Arc::new(AtomicUsize::new(0));
    // first request succeeds, further ones fail
    server.set_jwks_response(TestServerResponse::Sequence {
        counter: counter.clone(),
        sequence: vec![
            TestServerResponse::Success(Json(serde_json::to_value(test_keys.jwks)?)),
            TestServerResponse::Success(Json(serde_json::to_value(test_keys_new.jwks)?)),
        ],
    });

    let http_client = Client::new();
    let mut config = default_config(
        uris.discover_jwks_url,
        "regular-cache-reload-on-jwk-not-found",
    );
    config.cache.enabled = true;
    config.cache.expiration_duration = Duration::from_secs(30);
    config.cache.reload_on_jwk_not_found = true;

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::valid();

    let key = test_keys_new.encoding_keys[0].clone();

    let mut header = Header::new(key.algorithm);
    header.kid = Some(key.key_id.clone());

    let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

    let id_token_decoded = verifier
        .verify::<TestIdToken>(&id_token_encoded)
        .await?;

    assert_eq!(id_token_decoded, id_token);
    assert_eq!(counter.load(std::sync::atomic::Ordering::Relaxed), 2);

    Ok(())
}
