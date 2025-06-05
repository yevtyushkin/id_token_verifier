use crate::util::*;
use crate::validation::*;
use serde::*;
use std::collections::HashSet;

/// `exp` claim name.
const EXP_CLAIM: &str = "exp";

/// `iss` claim name.
const ISS_CLAIM: &str = "iss";

/// `aud` claim name.
const AUD_CLAIM: &str = "aud";

/// `nbf` claim name.
const NBF_CLAIM: &str = "nbf";

/// ID token verifier validation configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, bon::Builder)]
pub struct ValidationConfig {
    /// Allowed [Iss] that an ID token must match.
    ///
    /// WARNING: setting this field to an empty `OneOrVec::Vec` disables the `iss` validation.
    /// This is an insecure option, please make sure you understand what you are doing.
    ///
    /// Mandatory during deserialization.
    #[builder(into)]
    pub allowed_iss: OneOrVec<Iss>,

    /// Allowed [Aud] that an ID token must match.
    ///
    /// WARNING: setting this field to an empty `OneOrVec::Vec` disables the `aud` validation.
    /// This is an insecure option, please make sure you understand what you are doing.
    ///
    /// Mandatory during deserialization.
    #[builder(into)]
    pub allowed_aud: OneOrVec<Aud>,

    /// Whether to force `exp` field validation.
    ///
    /// WARNING: setting this field `false` disables the `exp` validation.
    // This is an insecure option, please make sure you understand what you are doing.
    ///
    /// Defaults to `true` during deserialization.
    #[serde(default = "default_validate_exp")]
    #[builder(default = default_validate_exp())]
    pub validate_exp: bool,

    /// Whether to force `nbf` field validation.
    ///
    /// Defaults to `false` during deserialization.
    #[serde(default)]
    #[builder(default = false)]
    pub validate_nbf: bool,

    /// Leeway for `exp` and `nbf` validation to account for clock skew.
    ///
    /// Default to `60` during deserialization.
    #[serde(default = "default_leeway_seconds")]
    #[builder(default = default_leeway_seconds())]
    pub leeway_seconds: u64,

    /// Whether verifier should not fail validation if the JWK lacks the `alg` parameter.
    ///
    /// You may want to set this field to `true` if the provided JWKS do not have the `alg`
    /// parameter, such as in <https://login.microsoftonline.com/common/discovery/v2.0/keys>.
    ///
    /// Defaults to `false` during deserialization.
    #[serde(default)]
    #[builder(default = false)]
    pub allow_missing_jwk_alg_parameter: bool,
}

impl ValidationConfig {
    /// Applies this configuration to the given [jsonwebtoken::Validation].
    pub(crate) fn apply_into(&self, validation: &mut jsonwebtoken::Validation) {
        let mut required_spec_claims = HashSet::new();

        if !self.allowed_iss.is_empty() {
            required_spec_claims.insert(ISS_CLAIM.into());
            match self.allowed_iss {
                OneOrVec::One(ref value) => validation.set_issuer(&[value]),
                OneOrVec::Vec(ref vec) => validation.set_issuer(vec),
            }
        }

        if !self.allowed_aud.is_empty() {
            required_spec_claims.insert(AUD_CLAIM.into());
            match self.allowed_aud {
                OneOrVec::One(ref value) => validation.set_audience(&[value]),
                OneOrVec::Vec(ref vec) => validation.set_audience(vec),
            }
        } else {
            validation.validate_aud = false;
        }

        if self.validate_exp {
            required_spec_claims.insert(EXP_CLAIM.into());
        } else {
            validation.validate_exp = false;
        }

        if self.validate_nbf {
            required_spec_claims.insert(NBF_CLAIM.into());
            validation.validate_nbf = true;
        }

        validation.leeway = self.leeway_seconds;

        validation.required_spec_claims = required_spec_claims;
    }
}

/// Default whether to validate `exp` field.
pub const fn default_validate_exp() -> bool {
    true
}

/// Default value for leeway seconds.
pub const fn default_leeway_seconds() -> u64 {
    60
}
