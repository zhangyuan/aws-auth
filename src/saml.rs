use base64::{engine::general_purpose, Engine as _};

pub struct AwsRole {
    pub provider_arn: String,
    pub role_arn: String,
}

impl AwsRole {
    pub fn new(provider_arn: String, role_arn: String) -> Self {
        Self {
            provider_arn,
            role_arn,
        }
    }
}

pub struct SAMLAssertion {
    pub assertion: String,
}

impl SAMLAssertion {
    pub fn encoded_as_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.assertion)
    }

    pub fn extract_roles(&self) -> anyhow::Result<Vec<AwsRole>> {
        let doc = roxmltree::Document::parse(&self.assertion)?;

        let element = doc
            .descendants()
            .find(|n| n.attribute("Name") == Some("https://aws.amazon.com/SAML/Attributes/Role"))
            .unwrap();

        let roles = element
            .children()
            .flat_map(|e| {
                e.text().map(|t| {
                    let split: Vec<&str> = t.trim().split(',').collect();
                    let split = &split;

                    let role = split.iter().find(|x| x.contains(":role/")).unwrap();
                    let provider = split
                        .iter()
                        .find(|x| x.contains(":saml-provider/"))
                        .unwrap();

                    AwsRole::new(provider.to_string(), role.to_string())
                })
            })
            .collect::<Vec<_>>();

        Ok(roles)
    }
}
