use crate::common::*;
use chrono::Utc;
use serde::*;

/// Test ID token to use in tests.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TestIdToken {
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
}

impl TestIdToken {
    /// An ID token which is valid (validity based on [test_data]).
    pub fn valid() -> TestIdToken {
        TestIdToken {
            iss: Some(ISS.into()),
            aud: Some(AUD.into()),
            exp: Some(Utc::now().timestamp() + 300),
            nbf: Some(Utc::now().timestamp() - 300),
        }
    }

    /// An ID token with an invalid `iss`.
    pub fn invalid_iss() -> TestIdToken {
        let mut token = TestIdToken::valid();
        token.iss = Some(WRONG_ISS.into());
        token
    }

    /// An ID token with an invalid `aud`.
    pub fn invalid_aud() -> TestIdToken {
        let mut token = TestIdToken::valid();
        token.aud = Some(WRONG_AUD.into());
        token
    }

    /// An ID token which is expired.
    pub fn expired() -> TestIdToken {
        let mut token = TestIdToken::valid();
        token.exp = Some(Utc::now().timestamp() - 300);
        token
    }

    /// An ID token with `nbf` from future (fails `nbf` validation).
    pub fn from_future() -> TestIdToken {
        let mut token = TestIdToken::valid();
        token.nbf = Some(Utc::now().timestamp() + 300);
        token
    }
}
