use backoff_config::ExponentialBackoffConfig;
use id_token_verifier::cache::JwksCacheConfig;
use id_token_verifier::client::*;
use id_token_verifier::validation::*;
use id_token_verifier::*;
use serde::Deserialize;
use std::time::Duration;

/// The target claims we want to receive as a result of ID token verification.
#[derive(Deserialize, Debug)]
pub struct GoogleClaims {
    pub iss: Option<String>,
    pub sub: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub picture: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(feature = "tracing")]
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let client_config = JwksClientConfig::builder()
        // Verifier will discover JWKS url from the OIDC provider metadata document.
        // Alternatively, you may provide a direct JWKS url.
        .jwks_url(JwksUrl::discover(
            "https://accounts.google.com/.well-known/openid-configuration",
        )?)
        // Sets exponential backoff strategy.
        // See [backoff_config] crate for other strategies.
        .backoff(
            ExponentialBackoffConfig {
                initial_delay: Duration::from_millis(500),
                factor: 2.0,
                max_delay: Duration::from_secs(8),
                ..Default::default()
            }
            .into(),
        )
        .build();

    let validation_config = ValidationConfig::builder()
        // As per https://developers.google.com/identity/gsi/web/guides/verify-google-id-token `iss` may be either
        // "accounts.google.com" or "https://accounts.google.com".
        //
        // Play around with `allowed_iss` and see what happens if neither of the provided values
        // matches the actual `iss` claim.
        // Spoiler: it will fail with the following error: 'ID token verification failed: InvalidIssuer'.
        .allowed_iss(vec![
            Iss::new("wrong-iss"),
            // Iss::new("accounts.google.com"),
            // Iss::new("https://accounts.google.com"),
        ])
        // This is very unsafe to leave `allowed_aud` empty. This library allows to leave it empty,
        // but it makes sure the user does it explicitly, and never defaults to an empty value.
        // You may run this example with your own `allowed_aud` by providing it below.
        .allowed_aud(vec![
            // Aud::new("<paste_your_aud_here>"),
        ])
        .build();

    let cache = JwksCacheConfig::builder()
        // Sets JWKS cache expiration to 5 minutes.
        .expiration_duration(Duration::from_secs(60 * 5))
        // Forces JWKS cache reload if a signing JWK is not found.
        .reload_on_jwk_not_found(true)
        // Enables JWKS cache background refresh each 1 minute.
        .background_refresh_interval(Duration::from_secs(60))
        .build();

    let config = IdTokenVerifierConfig::builder()
        .client(client_config)
        .validation(validation_config)
        .cache(cache)
        .build();

    let verifier = IdTokenVerifierDefault::new(config, reqwest::Client::new());

    let result = verifier
        .verify::<GoogleClaims>("<paste_your_id_token_here>")
        .await?;

    #[cfg(feature = "tracing")]
    tracing::info!("Result: {result:#?}");

    Ok(())
}
