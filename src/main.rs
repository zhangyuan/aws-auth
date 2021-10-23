use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use url::Url;

pub mod http_client;
pub mod okta;
pub mod saml;
pub mod ui;

use okta::Okta;
use ui::{StdUI, UI};
use aws_sdk_sts::{Region};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = aws_config::ConfigLoader::default()
        .region(Region::new("cn-northwest-1"))
        .load().await;

    let aws_client = aws_sdk_sts::Client::new(&config);

    let sts_result = aws_client.get_caller_identity().send().await;

    log::debug!("get_caller_identity: {:?}", sts_result);

    let settings = load_settings();

    let app_link = settings.get("app-link").unwrap();
    log::debug!("app_link: {}", app_link);

    let parsed_url = Url::parse(app_link)?;
    let identify_base_uri = format!("{}://{}", parsed_url.scheme(), parsed_url.domain().unwrap());

    log::debug!("okta_uri: {}", identify_base_uri);

    let client = http_client::create_http_client_with_redirects2()?;

    let stdui = StdUI {};

    let okta = Okta {
        ui: &stdui,
        http_client: &client,
        base_uri: &identify_base_uri,
        app_link,
    };

    let saml_assertion = okta.get_saml_assertion().await?;

    let roles = saml_assertion.extract_roles()?;
    let selected_role = stdui.get_aws_role(&roles);

    println!("saml_assertion: {}", saml_assertion.assertion);

    let result = aws_client
        .assume_role_with_saml()
        .role_arn(&selected_role.role_arn)
        .principal_arn(&selected_role.principal_arn)
        .saml_assertion(&saml_assertion.encoded_as_base64())
        .send().await?;

    println!("saml_assertion: {:?}", result);


    let credentials: aws_sdk_sts::model::Credentials = result.credentials.unwrap();
    write_credentials(&credentials)?;

    Ok(())
}

fn load_settings() -> HashMap<String, String> {
    let mut settings = config::Config::default();

    let local_config_path = Path::new(".aws-auth.toml").to_path_buf();

    let home = std::env::var("HOME").unwrap();
    let global_config_path = Path::new(&home).join(".aws-auth.toml");

    let config_path = if local_config_path.is_file() {
        local_config_path
    } else if global_config_path.is_file() {
        global_config_path
    } else {
        panic!("Config file is not found.")
    };

    settings
        .merge(config::File::with_name(config_path.to_str().unwrap()))
        .unwrap();

    settings.try_into::<HashMap<String, String>>().unwrap()
}

fn write_credentials(credentials: &aws_sdk_sts::model::Credentials) -> anyhow::Result<()> {
    let access_key_id = credentials.access_key_id.as_ref().unwrap();
    let secret_access_key = credentials.secret_access_key.as_ref().unwrap();
    let session_token = credentials.session_token.as_ref().unwrap();
    let expiration = credentials.expiration.as_ref().unwrap();

    let credentials_file_content = format!(
        r#"
[default]
aws_access_key_id = {}
aws_secret_access_key = {}
aws_session_token = {}
expiration = {}
        "#,
        access_key_id,
        secret_access_key,
        session_token,
        expiration.epoch_seconds()

    );

    println!("{}", credentials_file_content);

    use std::fs::File;
    let home = std::env::var("HOME").unwrap();

    let mut file = File::create(format!("{}/.aws/credentials", home))?;
    file.write_all(credentials_file_content.as_bytes())?;

    Ok(())
}
