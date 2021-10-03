use std::collections::HashMap;
use std::io::Write;
use url::Url;

pub mod aws;
pub mod http_client;
pub mod identity_provider;
pub mod okta;
pub mod saml;
pub mod ui;

use aws::AwsClient;
use identity_provider::IdentityProvider;
use okta::Okta;
use saml::SAMLAssertion;
use ui::{StdUI, UI};
use aws::Credentials;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let settings = load_settings();

    let app_link = settings.get("app-link").unwrap();
    log::debug!("app_link: {}", app_link);

    let parsed_url = Url::parse(app_link)?;
    let identify_base_uri = format!("{}://{}", parsed_url.scheme(), parsed_url.domain().unwrap());

    log::debug!("okta_uri: {}", identify_base_uri);

    let client = http_client::create_http_client_with_redirects()?;

    let stdui = StdUI {};

    let okta = Okta {
        ui: &stdui,
        http_client: &client,
        base_uri: &identify_base_uri,
        app_link,
    };

    let aws = AwsClient {
        http_client: &http_client::create_http_client(),
    };

    let saml_assertion = get_saml_assertion(&okta)?;

    let credentials = get_sts_token(&stdui, &aws, &saml_assertion)?;

    write_credentials(&credentials)?;

    Ok(())
}

fn load_settings() -> HashMap<String, String> {
    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("aws-auth.toml"))
        .unwrap();
    let settings = settings.try_into::<HashMap<String, String>>().unwrap();
    settings
}

fn get_sts_token(ui: &dyn UI, aws: &AwsClient, saml_assertion: &SAMLAssertion) -> anyhow::Result<Credentials> {
    let roles = saml_assertion.extract_roles()?;

    let selected_role = ui.get_aws_role(&roles);

    let credentials = aws.get_sts_token(
        &selected_role.role_arn,
        &selected_role.principal_arn,
        &saml_assertion.encoded_as_base64(),
    )?;

    log::debug!("credentials: {:?}", credentials);

    Ok(credentials)
}

fn get_saml_assertion(provider: &dyn IdentityProvider) -> anyhow::Result<SAMLAssertion> {
    provider.get_saml_assertion()
}

fn write_credentials(credentials: &Credentials) -> anyhow::Result<()> {
    let credentials_file_content = format!(
        r#"
[default]
aws_access_key_id = {}
aws_secret_access_key = {}
aws_session_token = {}
        "#,
        credentials.access_key_id, credentials.secret_access_key, credentials.session_token
    );

    println!("{}", credentials_file_content);

    use std::fs::File;
    let home = std::env::var("HOME").unwrap();

    let mut file = File::create(format!("{}/.aws/credentials", home))?;
    file.write_all(credentials_file_content.as_bytes())?;

    Ok(())

}
