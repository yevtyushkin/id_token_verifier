# 🔎 id_token_verifier ✅

[![crates.io](https://img.shields.io/crates/v/id_token_verifier.svg)](https://crates.io/crates/id_token_verifier)
[![codecov](https://codecov.io/gh/yevtyushkin/id_token_verifier/graph/badge.svg?token=KG76XN3GAR)](https://codecov.io/gh/yevtyushkin/id_token_verifier)

A feature-rich, highly configurable OpenID Connect ID token verifier in Rust — empowering you to validate ID tokens as
easily as this, while handling retries, caching, and more under the hood:

```rust
use id_token_verifier::*;
use id_token_verifier::client::*;

#[derive(serde::Deserialize)]
struct MyClaims { 
  sub: String,
  email: Option<String>,
  email_verified: Option<bool>,
}

async fn verify(
  token: &str,
  id_token_verifier: &IdTokenVerifierDefault
) -> Result<MyClaims, IdTokenVerifierError> {
  id_token_verifier.verify(token).await
}
```

### ✨ Features

- 🔁 Configurable JWKS caching, including background refresh.
- 🛠 Pluggable retry logic via [backoff_config](https://github.com/yevtyushkin/backoff_config)
  and [backon](https://github.com/Xuanwo/backon).
- ⚙️ Flexible validation settings.
- 🧩 [serde](https://github.com/serde-rs/serde)-friendly configuration — load from config files or environment variables,
  or use the provided config `Builder`s.
- 📈 [tracing](https://github.com/tokio-rs/tracing) support via the optional tracing `feature` flag.

## 📚 Examples

- ✅ [Validating Google ID tokens](examples/google)  
  Includes full setup for retries, JWKS caching, and validation settings.
