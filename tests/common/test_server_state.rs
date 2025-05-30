use crate::common::test_server_response::TestServerResponse;
use axum::Json;
use reqwest::StatusCode;

/// State of the [TestServer] with OIDC provider metadata / JWKS responses.
#[derive(Clone)]
pub struct TestServerState {
    /// OIDC provider metadata [TestServerResponse].
    pub oidc_provider_metadata_response: TestServerResponse<Json<serde_json::Value>>,

    /// JWKS [TestServerResponse].
    pub jwks_response: TestServerResponse<Json<serde_json::Value>>,
}

impl TestServerState {
    /// Returns an empty [TestServerState] that fails each request with `StatusCode::NOT_FOUND`.
    pub fn empty() -> TestServerState {
        TestServerState {
            oidc_provider_metadata_response: TestServerResponse::Failure(StatusCode::NOT_FOUND),
            jwks_response: TestServerResponse::Failure(StatusCode::NOT_FOUND),
        }
    }
}
