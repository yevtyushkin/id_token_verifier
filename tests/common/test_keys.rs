use base64::Engine;
use jsonwebtoken::jwk::*;
use jsonwebtoken::*;
use rsa::pkcs1::*;
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use std::str::FromStr;
use std::sync::LazyLock;
use uuid::Uuid;

/// Default [TestKeys] to use in tests.
pub static TEST_RSA_KEYS: LazyLock<TestKeys, fn() -> TestKeys> =
    LazyLock::new(|| TestKeys::rsa().unwrap());

/// Contains test encoding keys, as well as [JwkSet] to serve from the [crate::common::TestServer].
#[derive(Clone)]
pub struct TestKeys {
    /// [EncodingKeyWithHeader]s to use in tests.
    pub encoding_keys: Vec<EncodingKeySpec>,

    /// [JwkSet] to serve from the [crate::common::TestServer].
    pub jwks: JwkSet,
}

impl TestKeys {
    /// Generates RSA [TestKeys] for tests.
    pub fn rsa() -> anyhow::Result<TestKeys> {
        Self::generate_test_keys::<rsa::RsaPrivateKey, rsa::RsaPublicKey>(
            rsa::RsaPrivateKey::new(&mut OsRng, 2048)?,
            |private_key| rsa::RsaPublicKey::from(private_key),
            |private_key| {
                Ok(EncodingKey::from_rsa_pem(
                    private_key.to_pkcs1_pem(LineEnding::default())?.as_bytes(),
                )?)
            },
            |public_key| {
                AlgorithmParameters::RSA(RSAKeyParameters {
                    key_type: RSAKeyType::RSA,
                    n: base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(&public_key.n().to_bytes_be()),
                    e: base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(&public_key.e().to_bytes_be()),
                })
            },
            vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512],
        )
    }

    /// Takes a `private_key` [PK] and a [Vec] of signing/verifying [Algorithm]s.
    /// Converts `private_key` to a `public_key` via `public_key_fn`.
    /// For each [Algorithm], creates a corresponding [EncodingKeySpec] and an entry in the [JwkSet]
    /// to be served from [crate::common::TestServer].
    fn generate_test_keys<PK, PubK>(
        private_key: PK,
        public_key_fn: fn(&PK) -> PubK,
        encoding_key_fn: fn(&PK) -> anyhow::Result<EncodingKey>,
        algorithm_parameters_fn: fn(&PubK) -> AlgorithmParameters,
        algs: Vec<Algorithm>,
    ) -> anyhow::Result<TestKeys> {
        let public_key = public_key_fn(&private_key);

        let algs = algs
            .iter()
            .copied()
            .zip(
                algs.iter()
                    .copied()
                    .map(|alg| KeyAlgorithm::from_str(&format!("{alg:?}")).unwrap()),
            )
            .collect::<Vec<_>>();

        let mut jwks = JwkSet { keys: vec![] };
        let mut encoding_keys = vec![];
        for (alg, key_alg) in algs {
            let key_id = Uuid::now_v7();

            let jwk = Jwk {
                common: CommonParameters {
                    public_key_use: Some(PublicKeyUse::Signature),
                    key_id: Some(key_id.to_string()),
                    key_algorithm: Some(key_alg),
                    key_operations: None,
                    x509_url: None,
                    x509_chain: None,
                    x509_sha1_fingerprint: None,
                    x509_sha256_fingerprint: None,
                },
                algorithm: algorithm_parameters_fn(&public_key),
            };
            jwks.keys.push(jwk);

            let encoding_key = encoding_key_fn(&private_key)?;
            encoding_keys.push(EncodingKeySpec {
                key_id: key_id.to_string(),
                algorithm: alg,
                encoding_key,
            });
        }

        Ok(TestKeys {
            encoding_keys,
            jwks,
        })
    }
}

/// Specification of an [EncodingKey] with `key_id` and `algorithm`.
#[derive(Clone)]
pub struct EncodingKeySpec {
    /// Identifier of this key (matches the server [JwkSet]).
    pub key_id: String,

    /// [Algorithm] of this key.
    pub algorithm: Algorithm,

    /// [EncodingKey] itself to sign ID tokens in tests.
    pub encoding_key: EncodingKey,
}
