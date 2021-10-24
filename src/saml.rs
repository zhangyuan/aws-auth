pub struct AwsRole {
    pub principal_arn: String,
    pub role_arn: String,
}

impl AwsRole {
    pub fn new(principal_arn: String, role_arn: String) -> Self {
        Self {
            principal_arn,
            role_arn,
        }
    }
}

pub struct SAMLAssertion {
    pub assertion: String,
}

impl SAMLAssertion {
    pub fn encoded_as_base64(&self) -> String {
        base64::encode(&self.assertion)
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
                    let mut split = t.trim().split(',');
                    let role_arn = split.next().unwrap();
                    let principal_arn = split.next().unwrap();
                    AwsRole::new(principal_arn.to_string(), role_arn.to_string())
                })
            })
            .collect::<Vec<_>>();

        Ok(roles)
    }
}
