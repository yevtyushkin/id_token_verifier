use crate::common::*;
use id_token_verifier::validation::ValidationError;
use id_token_verifier::verifier::*;
use jsonwebtoken::Header;
use reqwest::Client;

mod common;

#[tokio::test]
async fn valid_token_discover_jwks_url() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let uris = server.start(test_keys.jwks).await?;

    let http_client = Client::new();
    let config = default_config(uris.discover_jwks_url, "valid-token-discover-jwks-uri");

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::valid();

    for key in &test_keys.encoding_keys {
        let mut header = Header::new(key.algorithm);
        header.kid = Some(key.key_id.clone());

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

        let id_token_decoded = verifier.verify::<TestIdToken>(&id_token_encoded).await?;

        assert_eq!(id_token_decoded, id_token);
    }

    Ok(())
}

#[tokio::test]
async fn valid_token_direct_jwks_url() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let uris = server.start(test_keys.jwks).await?;

    let http_client = Client::new();
    let config = default_config(uris.direct_jwks_url, "valid-token-direct-jwks-uri");

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::valid();

    for key in &test_keys.encoding_keys {
        let mut header = Header::new(key.algorithm);
        header.kid = Some(key.key_id.clone());

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

        let id_token_decoded = verifier.verify::<TestIdToken>(&id_token_encoded).await?;

        assert_eq!(id_token_decoded, id_token);
    }

    Ok(())
}

#[tokio::test]
async fn invalid_or_missing_issuer() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let uris = server.start(test_keys.jwks).await?;

    let http_client = Client::new();
    let config = default_config(uris.discover_jwks_url, "invalid-or-missing-issuer");

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::invalid_iss();

    for key in &test_keys.encoding_keys {
        let mut header = Header::new(key.algorithm);
        header.kid = Some(key.key_id.clone());

        // Invalid issuer
        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;
        let result = verifier.verify::<TestIdToken>(&id_token_encoded).await;
        assert!(
            matches!(result, Err(IdTokenVerifierError::Validation(ValidationError::ValidationFailed(e))) if e.kind() == &jsonwebtoken::errors::ErrorKind::InvalidIssuer)
        );

        // Missing issuer
        let mut id_token = id_token.clone();
        id_token.iss = None;

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;
        let result = verifier.verify::<TestIdToken>(&id_token_encoded).await;
        assert!(
            matches!(result, Err(IdTokenVerifierError::Validation(ValidationError::ValidationFailed(e))) if e.kind() == &jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("iss".into()))
        );
    }

    Ok(())
}

#[tokio::test]
async fn invalid_or_missing_audience() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let uris = server.start(test_keys.jwks).await?;

    let http_client = Client::new();
    let config = default_config(uris.discover_jwks_url, "invalid-or-missing-audience");

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::invalid_aud();

    for key in &test_keys.encoding_keys {
        let mut header = Header::new(key.algorithm);
        header.kid = Some(key.key_id.clone());

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

        let result = verifier.verify::<TestIdToken>(&id_token_encoded).await;
        assert!(
            matches!(result, Err(IdTokenVerifierError::Validation(ValidationError::ValidationFailed(e))) if e.kind() == &jsonwebtoken::errors::ErrorKind::InvalidAudience)
        );

        // Missing audience
        let mut id_token = id_token.clone();
        id_token.aud = None;

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;
        let result = verifier.verify::<TestIdToken>(&id_token_encoded).await;
        assert!(
            matches!(result, Err(IdTokenVerifierError::Validation(ValidationError::ValidationFailed(e))) if e.kind() == &jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("aud".into()))
        );
    }

    Ok(())
}

#[tokio::test]
async fn expired_or_missing_token() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let uris = server.start(test_keys.jwks).await?;

    let http_client = Client::new();
    let config = default_config(uris.discover_jwks_url, "expired-or-missing-signature");

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::expired();

    for key in &test_keys.encoding_keys {
        let mut header = Header::new(key.algorithm);
        header.kid = Some(key.key_id.clone());

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

        let result = verifier.verify::<TestIdToken>(&id_token_encoded).await;
        assert!(
            matches!(result, Err(IdTokenVerifierError::Validation(ValidationError::ValidationFailed(e))) if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature)
        );

        // Missing exp
        let mut id_token = id_token.clone();
        id_token.exp = None;

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;
        let result = verifier.verify::<TestIdToken>(&id_token_encoded).await;
        assert!(
            matches!(result, Err(IdTokenVerifierError::Validation(ValidationError::ValidationFailed(e))) if e.kind() == &jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("exp".into()))
        );
    }

    Ok(())
}

#[tokio::test]
async fn nbf_missing_or_in_future() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let test_keys = TEST_RSA_KEYS.clone();
    let uris = server.start(test_keys.jwks).await?;

    let http_client = Client::new();
    let config = default_config(uris.discover_jwks_url, "nbf-missing-or-in-future");

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::from_future();

    for key in &test_keys.encoding_keys {
        let mut header = Header::new(key.algorithm);
        header.kid = Some(key.key_id.clone());

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

        let result = verifier.verify::<TestIdToken>(&id_token_encoded).await;
        assert!(
            matches!(result, Err(IdTokenVerifierError::Validation(ValidationError::ValidationFailed(e))) if e.kind() == &jsonwebtoken::errors::ErrorKind::ImmatureSignature)
        );

        // Missing nbf
        let mut id_token = id_token.clone();
        id_token.nbf = None;

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;
        let result = verifier.verify::<TestIdToken>(&id_token_encoded).await;
        assert!(
            matches!(result, Err(IdTokenVerifierError::Validation(ValidationError::ValidationFailed(e))) if e.kind() == &jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("nbf".into()))
        );
    }

    Ok(())
}

#[tokio::test]
async fn jwk_alg_missing() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let mut test_keys = TEST_RSA_KEYS.clone();
    test_keys.jwks.keys.iter_mut().for_each(|jwk| {
        jwk.common.key_algorithm = None;
    });
    let uris = server.start(test_keys.jwks).await?;

    let http_client = Client::new();
    let config = default_config(uris.discover_jwks_url, "jwk-alg-missing");

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::valid();

    for key in &test_keys.encoding_keys {
        let mut header = Header::new(key.algorithm);
        header.kid = Some(key.key_id.clone());

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

        let result = verifier.verify::<TestIdToken>(&id_token_encoded).await;

        assert!(matches!(
            result,
            Err(IdTokenVerifierError::Validation(
                ValidationError::MissingJwkAlgParameter
            ))
        ));
    }

    Ok(())
}

#[tokio::test]
async fn jwk_alg_missing_allowed_in_config() -> anyhow::Result<()> {
    init_logging();

    let server = TestServer::new();
    let mut test_keys = TEST_RSA_KEYS.clone();
    test_keys.jwks.keys.iter_mut().for_each(|jwk| {
        jwk.common.key_algorithm = None;
    });
    let uris = server.start(test_keys.jwks).await?;

    let http_client = Client::new();
    let mut config = default_config(uris.discover_jwks_url, "jwk-alg-missing-allowed-in-config");
    config.validation.allow_missing_jwk_alg_parameter = true;

    let verifier = IdTokenVerifierDefault::new(config, http_client);
    let id_token = TestIdToken::valid();

    for key in &test_keys.encoding_keys {
        let mut header = Header::new(key.algorithm);
        header.kid = Some(key.key_id.clone());

        let id_token_encoded = jsonwebtoken::encode(&header, &id_token, &key.encoding_key)?;

        let id_token_decoded = verifier.verify::<TestIdToken>(&id_token_encoded).await?;

        assert_eq!(id_token_decoded, id_token);
    }

    Ok(())
}
