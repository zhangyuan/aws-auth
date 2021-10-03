use crate::saml::SAMLAssertion;

pub trait IdentityProvider {
    fn get_saml_assertion(&self) -> anyhow::Result<SAMLAssertion>;
}

pub struct MfaFactor {
    pub provider: String,
    pub factor_type: String,
    pub link: String,
}

impl MfaFactor {
    pub fn new(provider: &str, factor_type: &str, link: &str) -> Self {
        Self {
            provider: provider.to_string(),
            factor_type: factor_type.to_string(),
            link: link.to_string(),
        }
    }
}
