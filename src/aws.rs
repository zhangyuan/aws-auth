

use serde::{Deserialize};


#[derive(Deserialize, Debug)]
pub struct Credentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,

    #[serde(rename = "Expiration")]
    pub expiration: f64,

    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,

    #[serde(rename = "SessionToken")]
    pub session_token: String
}

#[derive(Deserialize, Debug)]
pub struct AssumeRoleWithSAMLResponseWrapper {
    #[serde(rename = "AssumeRoleWithSAMLResponse")]
    pub assume_role_with_saml_response: AssumeRoleWithSAMLResponse
}

#[derive(Deserialize, Debug)]
pub struct AssumeRoleWithSAMLResponse {
    #[serde(rename = "AssumeRoleWithSAMLResult")]
    pub assume_role_with_saml_result: AssumeRoleWithSAMLResult
}

#[derive(Deserialize, Debug)]
pub struct AssumeRoleWithSAMLResult {
    #[serde(rename = "Credentials")]
    pub credentials: Credentials
}



pub struct AwsClient<'a> {
    pub http_client: &'a reqwest::blocking::Client
}

impl AwsClient<'_> {
    pub fn get_sts_token(&self, role_arn: &str, principal_arn: &str, saml_assertion_base64: &str) -> anyhow::Result<Credentials> {
        let resp: AssumeRoleWithSAMLResponseWrapper = self.http_client.get("https://sts.cn-northwest-1.amazonaws.com.cn")
            .query(&[
                ("Version", "2011-06-15"),
                ("Action", "AssumeRoleWithSAML"),
                ("RoleArn", role_arn),
                ("PrincipalArn", principal_arn),
                ("SAMLAssertion", saml_assertion_base64)
            ])
            .header("Accept", "application/json")
            .send()?
            .json()?;

        Ok(resp.assume_role_with_saml_response.assume_role_with_saml_result.credentials)
    }
}