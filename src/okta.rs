use scraper::Html;
use scraper::Selector;
use serde::Deserialize;
use std::collections::HashMap;

use crate::aws::SAMLAssertion;
use crate::identity_provider::IdentityProvider;

use aws_auth::ui::UI;

#[derive(Deserialize, Debug)]
struct AuthNResponse {
    status: String,
    #[serde(rename = "stateToken")]
    state_token: String,
    #[serde(rename = "_embedded")]
    embedded: AuthNResponseEmbedded,
}

#[derive(Deserialize, Debug)]
struct AuthNResponseEmbedded {
    factors: Vec<MfaFactor>,
}

#[derive(Deserialize, Debug)]
struct MfaFactor {
    provider: String,
    #[serde(rename = "factorType")]
    factor_type: String,
    #[serde(rename = "_links")]
    links: HashMap<String, Link>,
}

#[derive(Deserialize, Debug)]
struct Link {
    href: String,
}

#[derive(Deserialize, Debug)]
struct VerifyResponse {
    status: String,
    #[serde(rename = "sessionToken")]
    session_token: String,
}

#[derive(Deserialize, Debug)]
struct CreateSessionResponse {
    id: String,
}

#[derive(Deserialize, Debug)]
struct Role {
    name: String,
}
pub struct Okta<'a> {
    pub ui: &'a dyn UI,
    pub http_client: &'a reqwest::blocking::Client,
    pub base_uri: &'a str,
    pub app_link: &'a str,
}

impl<'a> Okta<'a> {
    pub fn primary_auth(&self) -> anyhow::Result<SAMLAssertion> {
        let (username, password) = self.ui.get_username_and_password();
        let mut request_data = HashMap::new();
        request_data.insert("username", username);
        request_data.insert("password", password);

        let uri = format!("{}/api/v1/authn", self.base_uri);
        let resp: AuthNResponse = self
            .http_client
            .post(uri)
            .json(&request_data)
            .send()?
            .json()?;
        println!("{:?}", resp);

        if resp.status == "MFA_REQUIRED" {
            println!("MFA_REQUIRED");
            let state_token = &resp.state_token;

            let factor = resp
                .embedded
                .factors
                .into_iter()
                .find(|x| x.factor_type == "token:software:totp")
                .unwrap();

            println!("token:software:totp");

            let mfa_prompt = format!("{}: ", factor.provider);
            let mfa_code = self.ui.get_mfa_code(&mfa_prompt);

            let mut request_data = HashMap::new();
            request_data.insert("stateToken", state_token);
            request_data.insert("answer", &mfa_code);

            let verify_link = factor.links.get("verify").unwrap();
            let verify_url = &verify_link.href;

            println!("{}", verify_url);
            println!("{:?}", request_data);

            let resp: VerifyResponse = self
                .http_client
                .post(verify_url)
                .json(&request_data)
                .send()?
                .json()?;

            println!("{:?}", resp);

            let session_token = resp.session_token;

            let session_id = self.get_session_id(&session_token)?;

            let assertion = self.get_saml(&session_id)?;

            return Ok(assertion);
        }

        Err(anyhow::anyhow!("Error occurs"))
    }
    fn get_session_id(&self, session_token: &str) -> anyhow::Result<String> {
        let mut request_data = HashMap::new();
        request_data.insert("sessionToken", session_token);

        let uri = format!("{}/api/v1/sessions", self.base_uri);
        let resp: CreateSessionResponse = self
            .http_client
            .post(uri)
            .json(&request_data)
            .send()?
            .json()?;

        Ok(resp.id)
    }

    fn get_saml(&self, session_id: &str) -> anyhow::Result<SAMLAssertion> {
        let resp = self
            .http_client
            .get(self.app_link)
            .header("Cookie", format!("sid={}", session_id))
            .send()?
            .text()?;

        let base64_saml_assertion = get_base64_saml_assertion(&resp);

        let x = base64::decode(base64_saml_assertion)?;
        let assertion = String::from_utf8(x)?;
        Ok(SAMLAssertion { assertion })
    }
}

impl IdentityProvider for Okta<'_> {
    fn get_saml_assertion(&self) -> anyhow::Result<SAMLAssertion> {
        self.primary_auth()
    }
}

fn get_base64_saml_assertion(resp: &str) -> String {
    let document = Html::parse_document(resp);

    let selector = Selector::parse(r#"input[name="SAMLResponse"]"#).unwrap();

    let element = document.select(&selector).next().unwrap();
    let saml_response = element.value().attr("value").unwrap();
    saml_response.to_string()
}
