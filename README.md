# 🔎 id_token_verifier ✅

[![codecov](https://codecov.io/gh/yevtyushkin/id_token_verifier/graph/badge.svg?token=KG76XN3GAR)](https://codecov.io/gh/yevtyushkin/id_token_verifier)

[tokio](https://github.com/tokio-rs/tokio)-friendly, highly configurable, batteries-included OpenID Connect ID Token
Verifier in Rust.

### Features:

- Direct or discovery-based JWKS.

- Caching with fixed expiry and background refresh.

- Pluggable retry strategy via [backoff-config](https://github.com/yevtyushkin/backoff-config).

- [serde](https://github.com/serde-rs/serde)-friendly configuration (loadable from env or other sources).

- Optional [tracing](https://github.com/tokio-rs/tracing) to dig into the verification flow.

### Usage:

1. Create an instance of [IdTokenVerifierDefault](src/verifier/id_token_verifier.rs) using an [IdTokenVerifierConfig](src/verifier/id_token_verifier_config.rs) and a [reqwest::Client](https://github.com/seanmonstar/reqwest).
2. Define the target claims type with [Deserialize](https://docs.serde.rs/serde/trait.Deserialize.html):
```rust
#[derive(Debug, Deserialize)]
struct MyClaims {
    pub id: String,
    pub email: String,
    pub email_verified: bool
}
```
3. Call `IdTokenVerifier#verify::<MyClaims>` and get the claims, or handle the error:

```rust
match verifier.verify::<MyClaims>(id_token).await {
    Ok(claims) => println!("Claims: {claims:?}"),
    Err(error) => println!("Error: {error}")
}
```
