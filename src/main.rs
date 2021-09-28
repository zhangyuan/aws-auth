use std::io::{self, Write, BufRead, Stdin};
use std::collections::HashMap;
use serde::{Deserialize};
use scraper::Html;
use scraper::Selector;

#[derive(Deserialize, Debug)]
struct AuthNResponse {
    status: String,
    #[serde(rename = "stateToken")]
    state_token: String,
    #[serde(rename = "_embedded")]
    embedded: AuthNResponseEmbedded
}


#[derive(Deserialize, Debug)]
struct AuthNResponseEmbedded {
    factors: Vec<MfaFactor>
}

#[derive(Deserialize, Debug)]
struct MfaFactor {
    provider: String,
    #[serde(rename = "factorType")]
    factor_type: String,
    #[serde(rename = "_links")]
    links: HashMap<String, Link>
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

#[derive(Deserialize, Debug)]
struct AssumeRoleWithSAMLResponseWrapper {
    #[serde(rename = "AssumeRoleWithSAMLResponse")]
    assume_role_with_saml_response: AssumeRoleWithSAMLResponse
}

#[derive(Deserialize, Debug)]
struct AssumeRoleWithSAMLResponse {
    #[serde(rename = "AssumeRoleWithSAMLResult")]
    assume_role_with_saml_result: AssumeRoleWithSAMLResult
}

#[derive(Deserialize, Debug)]
struct AssumeRoleWithSAMLResult {
    #[serde(rename = "Credentials")]
    credentials: Credentials
}

#[derive(Deserialize, Debug)]
struct Credentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,

    #[serde(rename = "Expiration")]
    expiration: f64,

    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,

    #[serde(rename = "SessionToken")]
    session_token: String
}


fn main() -> anyhow::Result<()> {
    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("aws-auth")).unwrap();
    let settings = settings.try_into::<HashMap<String, String>>().unwrap();

    let app_link = settings.get("app-link").unwrap();
    println!("app_link: {}", app_link);

    let okta_uri = settings.get("okta-uri").unwrap();
    println!("okta_uri: {}", app_link);

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > 5 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        }))
        .build()?;

    let session_token = primary_auth(&client, okta_uri)?;
    let session_id = get_session_id(&client, session_token, okta_uri)?;

    let resp = get_saml(&client, &session_id, app_link)?;

    // println!("{}", resp);

    let resp_argument = &resp;
    let base64_saml_assertion = get_base64_saml_assertion(&resp_argument);
    let x = base64::decode(base64_saml_assertion.to_string())?;
    let assertion = String::from_utf8(x).unwrap();

    let roles = extract_roles(&assertion).unwrap();

    if roles.len() == 1 {
        let mut role = roles[0].split(",");

        println!("roles[0] {}", roles[0]);

        let role_arn = role.next().unwrap();
        let principal_arn = role.next().unwrap();

        let resp: AssumeRoleWithSAMLResponseWrapper = client.get("https://sts.cn-northwest-1.amazonaws.com.cn")
            .query(&[
                ("Version", "2011-06-15"),
                ("Action", "AssumeRoleWithSAML"),
                ("RoleArn", &role_arn),
                ("PrincipalArn", &principal_arn),
                ("SAMLAssertion", &base64_saml_assertion)
            ])
            .header("Accept", "application/json")
            .send()?
            .json()?;

        println!("{:?}", resp);
    }

    return Ok(());
}

fn extract_roles(assertion: &str) -> anyhow::Result<Vec<String>> {
    let doc = roxmltree::Document::parse(&assertion)?;

    let element = doc.descendants()
        .find(|n| n.attribute("Name") == Some("https://aws.amazon.com/SAML/Attributes/Role")).unwrap();

    let roles = element.children().flat_map(|e| e.text().map(|t| t.trim().to_string())).collect::<Vec<String>>();

    Ok(roles)
}

fn get_base64_saml_assertion(resp: &str) -> String {
    let document = Html::parse_document(resp);

    let selector = Selector::parse(r#"input[name="SAMLResponse"]"#).unwrap();

    let element = document.select(&selector).next().unwrap();
    let saml_response = element.value().attr("value").unwrap();
    saml_response.to_string()
}


fn get_saml(client: &reqwest::blocking::Client, session_id: &str, app_link: &str) -> anyhow::Result<String> {
    let resp = client.get(app_link)
        .header("Cookie", format!("sid={}", session_id))
        .send()?
        .text()?;
    return Ok(resp)
}

fn get_session_id(client: &reqwest::blocking::Client, session_token: String, okta_uri: &str) -> anyhow::Result<String> {
    let mut request_data = HashMap::new();
    request_data.insert("sessionToken", session_token);

    let uri = format!("{}/api/v1/sessions", okta_uri);
    let resp: CreateSessionResponse = client.post(uri)
        .json(&request_data)
        .send()?
        .json()?;

    return Ok(resp.id)
}

fn primary_auth(client: &reqwest::blocking::Client, okta_uri: &str) -> anyhow::Result<String> {
    let stdin = io::stdin();
    let username = read_from_stdin(&stdin, "Username");
    let password = read_password_from_stdin("Password");

    let mut request_data = HashMap::new();
    request_data.insert("username", username);
    request_data.insert("password", password);

    let uri = format!("{}/api/v1/authn", okta_uri);
    let resp: AuthNResponse = client.post(uri)
        .json(&request_data)
        .send()?
        .json()?;
    println!("{:?}", resp);

    if resp.status == "MFA_REQUIRED" {
        println!("MFA_REQUIRED");
        let state_token = &resp.state_token;

        let factor = resp.embedded.factors.into_iter().find(|x| x.factor_type == "token:software:totp").unwrap();

        println!("token:software:totp");

        let mfa_prompt = format!("{}: ", factor.provider);
        let mfa_code = read_from_stdin(&stdin, &mfa_prompt);

        let mut request_data = HashMap::new();
        request_data.insert("stateToken", state_token);
        request_data.insert("answer", &mfa_code);

        let verify_link = factor.links.get("verify").unwrap();
        let verify_url = &verify_link.href;

        println!("{}", verify_url);
        println!("{:?}", request_data);

        let resp: VerifyResponse = client.post(verify_url)
            .json(&request_data)
            .send()?
            .json()?;

        println!("{:?}", resp);

        let session_token = resp.session_token;

        return Ok(session_token)
    }

    return Err(anyhow::anyhow!("Error occurs"));
}

fn read_from_stdin(stdin: &Stdin, prompt: &str) -> String {
    let mut text = String::new();
    while text.trim().is_empty() {
        print!("{}: ", prompt);
        io::stdout().flush().unwrap();
        text.clear();
        stdin.lock().read_line(&mut text).expect("Could not read username");
    }
    text.trim().to_string()
}

fn read_password_from_stdin(prompt: &str) -> String {
    loop {
        print!("{}: ", prompt);
        io::stdout().flush().unwrap();

        let pass = rpassword::read_password().unwrap();

        if pass.trim().is_empty() {
            continue
        }
        return pass.trim().to_string();
    }
}
