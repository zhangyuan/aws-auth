use std::collections::HashMap;
use std::io::Write;
use url::Url;

pub mod aws;
pub mod saml;
pub mod identity_provider;
pub mod ui;
pub mod http_client;
pub mod okta;

use identity_provider::IdentityProvider;
use ui::{StdUI, UI};
use okta::Okta;
use aws::AwsClient;
use saml::SAMLAssertion;

fn main() -> anyhow::Result<()> {
    let mut settings = config::Config::default();
    settings.merge(config::File::with_name("aws-auth.toml")).unwrap();
    let settings = settings.try_into::<HashMap<String, String>>().unwrap();

    let app_link = settings.get("app-link").unwrap();
    println!("app_link: {}", app_link);

    let parsed_url = Url::parse(app_link)?;
    let okta_uri = format!("{}://{}", parsed_url.scheme(), parsed_url.domain().unwrap());

    println!("okta_uri: {}", okta_uri);

    let client = http_client::create_http_client_with_redirects()?;

    let stdui = StdUI {};
    let okta = Okta {
        ui: &stdui,
        http_client: &client,
        base_uri: &okta_uri,
        app_link,
    };

    let aws = AwsClient {
        http_client: &http_client::create_http_client(),
    };

    let saml_assertion = get_saml_assertion(&okta)?;

    let roles= saml_assertion.extract_roles()?;

    let selected_role = stdui.get_aws_role(&roles);

    let credentials = aws.get_sts_token(
        &selected_role.role_arn,
        &selected_role.principal_arn,
        &saml_assertion.encoded_as_base64(),
    )?;

    println!("{:?}", credentials);

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

fn get_saml_assertion(provider: &dyn IdentityProvider) -> anyhow::Result<SAMLAssertion> {
    provider.get_saml_assertion()
}
