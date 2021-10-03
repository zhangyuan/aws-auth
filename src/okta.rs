use scraper::Html;
use scraper::Selector;
use serde::Deserialize;
use std::collections::HashMap;

use crate::identity_provider::{IdentityProvider, MfaFactor};
use crate::saml::SAMLAssertion;

use crate::ui::UI;

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
    factors: Vec<OktaMfaFactor>,
}

#[derive(Deserialize, Debug)]
pub struct OktaMfaFactor {
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
        let resp = self.authn()?;

        if resp.status == "MFA_REQUIRED" {
            log::debug!("MFA_REQUIRED");
            let state_token = &resp.state_token;

            let mfa_factors = resp
                .embedded
                .factors
                .into_iter()
                .map(|factor| {
                    let link = factor.links.get("verify").unwrap();
                    MfaFactor::new(&factor.provider, &factor.factor_type, &link.href)
                })
                .collect::<Vec<_>>();

            let mfa_factor = self.ui.get_mfa_factor(&mfa_factors);

            return self.verify_mfa_code(state_token, mfa_factor);
        }

        Err(anyhow::anyhow!("Error occurs"))
    }

    fn verify_mfa_code(
        &self,
        state_token: &str,
        mfa_factor: &MfaFactor,
    ) -> anyhow::Result<SAMLAssertion> {
        loop {
            let code = self.ui.get_mfa_code(&format!(
                "MFA Code({} - {}): ",
                mfa_factor.provider, mfa_factor.factor_type
            ));

            let mut request_data = HashMap::new();
            request_data.insert("stateToken", state_token);
            request_data.insert("answer", &code);

            let verify_url = &mfa_factor.link;

            log::debug!("verify url: {}", verify_url);
            log::debug!("verify request data: {:?}", request_data);

            let response = self
                .http_client
                .post(verify_url)
                .json(&request_data)
                .send()?;
            if response.status().is_success() {
                let resp: VerifyResponse = response.json()?;

                log::debug!("verify response: {:?}", resp);

                let session_token = resp.session_token;
                let session_id = self.get_session_id(&session_token)?;
                let assertion = self.get_saml(&session_id)?;

                return Ok(assertion);
            }

            self.ui.error(&format!(
                "MFA code verification failed! (status_code: {})",
                response.status().as_u16()
            ));
            self.ui.error(&format!("{}", response.text()?));
        }
    }

    fn authn(&self) -> anyhow::Result<AuthNResponse> {
        loop {
            let (username, password) = self.ui.get_username_and_password();
            let mut request_data = HashMap::new();
            request_data.insert("username", username);
            request_data.insert("password", password);

            let uri = format!("{}/api/v1/authn", self.base_uri);
            let response = self.http_client.post(uri).json(&request_data).send()?;
            if response.status().is_success() {
                let resp = response.json()?;
                log::debug!("authn response: {:?}", resp);
                return Ok(resp);
            }

            self.ui.error(&format!(
                "Authentication failed! (status_code: {})",
                response.status().as_u16()
            ));
            self.ui.error(&response.text()?);
        }
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
