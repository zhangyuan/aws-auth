use crate::aws::SAMLAssertion;

pub trait IdentityProvider {
    fn get_saml_assertion(&self) -> anyhow::Result<SAMLAssertion>;
}
