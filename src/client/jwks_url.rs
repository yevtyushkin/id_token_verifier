use reqwest::IntoUrl;
use serde::*;

/// Possible types of URIs JWKS can be fetched from.
#[derive(Clone, derive_more::Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JwksUrl {
    /// Discover JWKS URL through OIDC provider metadata document (`metadata["jwks_uri"]`).
    Discover(#[debug("{}", _0)] url::Url),

    /// Direct JWKS URL.
    Direct(#[debug("{}", _0)] url::Url),
}

impl JwksUrl {
    /// Attempts to create an instance of [JwksUrl::Discover] from the given [IntoUrl] value.
    pub fn discover<T>(value: T) -> Result<JwksUrl, reqwest::Error>
    where
        T: IntoUrl,
    {
        Ok(JwksUrl::Discover(value.into_url()?))
    }

    /// Attempts to create an instance of [JwksUrl::Direct] from the given [IntoUrl] value.
    pub fn direct<T>(value: T) -> Result<JwksUrl, reqwest::Error>
    where
        T: IntoUrl,
    {
        Ok(JwksUrl::Direct(value.into_url()?))
    }
}

impl AsRef<url::Url> for JwksUrl {
    fn as_ref(&self) -> &url::Url {
        match self {
            JwksUrl::Discover(uri) => uri,
            JwksUrl::Direct(uri) => uri,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover() -> anyhow::Result<()> {
        let url = String::from("https://example.com/jwks");
        let expected = JwksUrl::Discover(url::Url::parse("https://example.com/jwks")?);

        assert_eq!(&JwksUrl::discover(url.clone())?, &expected);
        assert_eq!(&JwksUrl::discover(&url)?, &expected);
        assert_eq!(&JwksUrl::discover(url.as_str())?, &expected);

        Ok(())
    }

    #[test]
    fn direct() -> anyhow::Result<()> {
        let url = String::from("https://example.com/jwks");
        let expected = JwksUrl::Direct(url::Url::parse("https://example.com/jwks")?);

        assert_eq!(&JwksUrl::direct(url.clone())?, &expected);
        assert_eq!(&JwksUrl::direct(&url)?, &expected);
        assert_eq!(&JwksUrl::direct(url.as_str())?, &expected);

        Ok(())
    }
}
