use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

/// Predefined [TestServer] response.
#[derive(Clone)]
pub enum TestServerResponse<T> {
    /// Fails with the given [axum::http::StatusCode].
    Failure(axum::http::StatusCode),

    /// Responds with the given [T].
    Success(T),

    /// A sequence of responses that may fail (`TestServerResponse::Failure`) or succeed
    /// (`TestServerResponse::Success`) plus the request counter that.
    Sequence {
        /// A sequence of responses that may fail (`TestServerResponse::Failure`) or succeed
        /// (`TestServerResponse::Success`).
        sequence: Vec<TestServerResponse<T>>,

        /// Request counter to get the number of already processed requests.
        counter: Arc<AtomicUsize>,
    },
}

impl<T> IntoResponse for TestServerResponse<T>
where
    T: IntoResponse + Clone,
{
    fn into_response(self) -> Response {
        match self {
            TestServerResponse::Failure(code) => code.into_response(),
            TestServerResponse::Success(value) => value.into_response(),
            TestServerResponse::Sequence { sequence, counter } => {
                let index = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                if index >= sequence.len() {
                    return sequence
                        .last()
                        .cloned()
                        .unwrap_or(TestServerResponse::Failure(
                            axum::http::StatusCode::NOT_FOUND,
                        ))
                        .into_response();
                }

                sequence[index].clone().into_response()
            }
        }
    }
}
