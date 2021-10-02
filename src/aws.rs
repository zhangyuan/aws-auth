use serde::Deserialize;

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

#[derive(Deserialize, Debug)]
pub struct Credentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,

    #[serde(rename = "Expiration")]
    pub expiration: f64,

    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,

    #[serde(rename = "SessionToken")]
    pub session_token: String,
}

#[derive(Deserialize, Debug)]
pub struct AssumeRoleWithSAMLResponseWrapper {
    #[serde(rename = "AssumeRoleWithSAMLResponse")]
    pub assume_role_with_saml_response: AssumeRoleWithSAMLResponse,
}

#[derive(Deserialize, Debug)]
pub struct AssumeRoleWithSAMLResponse {
    #[serde(rename = "AssumeRoleWithSAMLResult")]
    pub assume_role_with_saml_result: AssumeRoleWithSAMLResult,
}

#[derive(Deserialize, Debug)]
pub struct AssumeRoleWithSAMLResult {
    #[serde(rename = "Credentials")]
    pub credentials: Credentials,
}

pub struct AwsClient<'a> {
    pub http_client: &'a reqwest::blocking::Client,
}

impl AwsClient<'_> {
    pub fn get_sts_token(
        &self,
        role_arn: &str,
        principal_arn: &str,
        saml_assertion_base64: &str,
    ) -> anyhow::Result<Credentials> {
        let resp: AssumeRoleWithSAMLResponseWrapper = self
            .http_client
            .get("https://sts.cn-northwest-1.amazonaws.com.cn")
            .query(&[
                ("Version", "2011-06-15"),
                ("Action", "AssumeRoleWithSAML"),
                ("RoleArn", role_arn),
                ("PrincipalArn", principal_arn),
                ("SAMLAssertion", saml_assertion_base64),
            ])
            .header("Accept", "application/json")
            .send()?
            .json()?;

        Ok(resp
            .assume_role_with_saml_response
            .assume_role_with_saml_result
            .credentials)
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
