pub mod ui;

pub trait IdentiyProvider {
    fn get_saml_assertion(&self) -> anyhow::Result<SAMLAssertion>;
}

pub struct SAMLAssertion {
    pub assertion: String,
}

impl SAMLAssertion {
    pub fn encoded_as_base64(&self) -> String {
        base64::encode(&self.assertion)
    }

    pub fn extract_roles(&self) -> anyhow::Result<Vec<String>> {
        let doc = roxmltree::Document::parse(&self.assertion)?;

        let element = doc
            .descendants()
            .find(|n| n.attribute("Name") == Some("https://aws.amazon.com/SAML/Attributes/Role"))
            .unwrap();

        let roles = element
            .children()
            .flat_map(|e| e.text().map(|t| t.trim().to_string()))
            .collect::<Vec<String>>();

        Ok(roles)
    }
}
