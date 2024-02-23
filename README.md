### id_token_verifier

A tiny library for declarative verification of ID tokens.

### Examples

#### Verifying an ID token issued by Google

Full example can be found [here](examples/google_id_token.rs).

1. Go to [Google OAuth 2.0 Playground](https://developers.google.com/oauthplayground/). 
   1. Select `profile, email` scopes.
   2. Press `Exchange authorization code for tokens`.
   3. Copy the `id_token` from the response and open it in [jwt.io](https://jwt.io/).
   4. You will need to use the `aud` claim from the token in the next steps to use in the validation config. NOTE: in real app, this should be your app's client IDs.

2. Define the `FetchSource` to use for fetching JWK Sets:
```rust
let fetch_source = FetchSource::AutoDiscover {
    url: "https://accounts.google.com/.well-known/openid-configuration"
        .parse()
        .unwrap(),
};
```

3. Instantiate the ID token verifier:
```rust
let id_token_verifier = JwkBasedJwtIdTokenVerifierBuilder::new(fetch_source)
    .with_http_client(Client::new())
    .with_cache(Duration::seconds(10))
    .with_validation_options(
        vec![String::from("https://accounts.google.com")],
        vec![
            // In real app, this should be your app's client IDs, but for this example - copy `aud` from OAuth playground
            String::from("paste"),
        ],
    )
    .build();
```

4. Define the payload structure and verify the ID token:
```rust
#[derive(Deserialize, Debug)]
struct Payload {
   iat: i64,
   exp: i64,
   name: String,
   sub: String,
   email: String,
}

let id_token = "paste the id_token here";
let result: Result<Payload, Error> = id_token_verifier.verify(id_token).await;

println!("{:?}", result); // Ok(Payload { iat: 1708709876, exp: 1708713476, name: "Daniyil Yevtyushkin", sub: "***", email: "daniyil.y***" })
```