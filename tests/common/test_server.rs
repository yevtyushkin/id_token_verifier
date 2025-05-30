use crate::common::test_server_response::TestServerResponse;
use crate::common::test_server_state::TestServerState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Json, Router};
use id_token_verifier::client::JwksUrl;
use jsonwebtoken::jwk::JwkSet;
use serde_json::json;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Test server that emulates OIDC provider metadata / JWKS responses.
#[derive(Clone)]
pub struct TestServer {
    /// State of the [TestServer] with OIDC provider metadata / JWKS responses.
    pub state: Arc<RwLock<TestServerState>>,
}

impl TestServer {
    /// Creates a new [TestServer] with the empty [TestServerState].
    pub fn new() -> TestServer {
        TestServer {
            state: Arc::new(RwLock::new(TestServerState::empty())),
        }
    }

    /// Sets the OIDC provider metadata response to the given `response`.
    pub fn set_oidc_provider_metadata_response(
        &self,
        response: TestServerResponse<Json<serde_json::Value>>,
    ) {
        self.state.write().unwrap().oidc_provider_metadata_response = response;
    }

    /// Sets the OIDC provider metadata response to the given `response`.
    pub fn set_jwks_response(&self, response: TestServerResponse<Json<serde_json::Value>>) {
        self.state.write().unwrap().jwks_response = response;
    }

    /// Starts the test HTTP server, and returns the test server URL.
    pub async fn start(&self, jwks: JwkSet) -> anyhow::Result<TestServerUris> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = url::Url::parse(&format!("http://{}", listener.local_addr()?))?;

        tokio::spawn({
            let state = self.state.clone();
            async move {
                axum::serve(
                    listener,
                    Router::new()
                        .route("/metadata", axum::routing::get(Self::get_metadata))
                        .route("/jwks", axum::routing::get(Self::get_jwks))
                        .route("/health_check", axum::routing::get(Self::health_check))
                        .with_state(state),
                )
                .await
                .expect("Failed to start test server");
            }
        });

        let mut health_check_url = url.clone();
        health_check_url.set_path("/health_check");
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        while let Err(_) = reqwest::get(health_check_url.clone()).await {
            interval.tick().await;
        }

        let mut discover_jwks_url = url.clone();
        discover_jwks_url.set_path("/metadata");
        let discover_jwks_url = JwksUrl::Discover(discover_jwks_url);

        let mut direct_jwks_url = url.clone();
        direct_jwks_url.set_path("/jwks");

        // Mock OIDC provider metadata response.
        let oidc_metadata = json!({
            "jwks_uri": direct_jwks_url.as_ref(),
        });
        let response = TestServerResponse::Success(Json(oidc_metadata));
        self.set_oidc_provider_metadata_response(response);

        let direct_jwks_url = JwksUrl::Direct(direct_jwks_url);

        // Mock JWKS response.
        let response = TestServerResponse::Success(Json(serde_json::to_value(jwks)?));
        self.set_jwks_response(response);

        Ok(TestServerUris {
            discover_jwks_url: discover_jwks_url,
            direct_jwks_url: direct_jwks_url,
        })
    }

    /// HTTP GET handler for OIDC provider metadata request.
    async fn get_metadata(State(state): State<Arc<RwLock<TestServerState>>>) -> impl IntoResponse {
        state
            .read()
            .unwrap()
            .clone()
            .oidc_provider_metadata_response
            .into_response()
    }

    /// HTTP GET handler for JWKS request.
    async fn get_jwks(State(state): State<Arc<RwLock<TestServerState>>>) -> impl IntoResponse {
        state.read().unwrap().clone().jwks_response.into_response()
    }

    /// HTTP GET handler for health check request.
    async fn health_check() -> impl IntoResponse {
        StatusCode::OK
    }
}

/// URIs of the test server endpoints.
pub struct TestServerUris {
    /// [JwksUrl::Discover] of this test server.
    pub discover_jwks_url: JwksUrl,

    /// [JwksUrl::Direct] of this test server.
    pub direct_jwks_url: JwksUrl,
}
