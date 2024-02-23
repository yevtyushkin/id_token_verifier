use chrono::Duration;
use id_token_verifier::error::Error;
use id_token_verifier::id_token_verifier::IdTokenVerifier;
use reqwest::Client;
use serde::Deserialize;

use tokio;

use id_token_verifier::prelude::{FetchSource, JwkBasedJwtIdTokenVerifierBuilder};

#[tokio::main]
async fn main() {
    let fetch_source = FetchSource::AutoDiscover {
        url: "https://accounts.google.com/.well-known/openid-configuration"
            .parse()
            .unwrap(),
    };

    let id_token_verifier = JwkBasedJwtIdTokenVerifierBuilder::new(fetch_source)
        .with_http_client(Client::new())
        .with_cache(Duration::seconds(10))
        .with_validation_options(
            vec![String::from("https://accounts.google.com")],
            vec![
                // In real app, this should be your app's client IDs, but for this example - copy `aud` from OAuth playground
                String::from("paste aud here"),
            ],
        )
        .build();

    #[derive(Deserialize, Debug)]
    struct Payload {
        iat: i64,
        exp: i64,
        name: String,
        sub: String,
        email: String,
    }

    // Paste the token from OAuth playground here
    let id_token = "paste id token here";

    let result: Result<Payload, Error> = id_token_verifier.verify(id_token).await;

    println!("{result:?}");
}
