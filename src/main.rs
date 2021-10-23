use std::collections::HashMap;
use std::path::Path;

use url::Url;
pub mod http_client;
pub mod okta;
pub mod saml;

pub mod ui;
use okta::Okta;
use ui::{StdUI, UI};
use aws_sdk_sts::{Region, Client, Credentials};

use std::{env};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let maybe_role_to_assume = args.get(1);

    env_logger::init();

    let home = std::env::var("HOME").unwrap();
    let credentials_path = format!("{}/.aws/credentials", home);

    OpenOptions::new().create(true).write(true).open(Path::new(&credentials_path)).await?;

    let mut credentials_config = config::Config::default();
    credentials_config.merge(config::File::with_name(&credentials_path).format(config::FileFormat::Ini))?;

    let credentials = if let Ok(default_credentials) = credentials_config.get_table("default") {
        if default_credentials.contains_key("aws_access_key_id")
            && default_credentials.contains_key("aws_secret_access_key")
            && default_credentials.contains_key("aws_session_token")
        {
            let access_key_id = default_credentials.get("aws_access_key_id")
                .unwrap()
                .to_string();
            let secret_access_key = default_credentials.get("aws_secret_access_key")
                .unwrap()
                .to_string();
            let session_token = default_credentials.get("aws_session_token")
                .unwrap()
                .to_string();
            Credentials::from_keys(access_key_id, secret_access_key, Some(session_token))
        } else {
            Credentials::from_keys("", "", None)
        }
    } else {
        Credentials::from_keys("", "", None)
    };


    let config = aws_config::ConfigLoader::default()
        .credentials_provider(credentials.clone())
        .region(Region::new("cn-northwest-1"))
        .load().await;

    let aws_client = aws_sdk_sts::Client::new(&config);

    if ! &credentials.access_key_id().is_empty() && ! &credentials.secret_access_key().is_empty() {
        let sts_result = aws_client.get_caller_identity().send().await;

        if sts_result.is_ok() {
            if let Some(role_to_assume) = maybe_role_to_assume {
                assume_role(&aws_client, role_to_assume).await?;
            }
            return Ok(());
        }
    }

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

    let saml_assertion = okta.get_saml_assertion().await?;

    let roles = saml_assertion.extract_roles()?;
    let selected_role = stdui.get_aws_role(&roles);

    let result = aws_client
        .assume_role_with_saml()
        .role_arn(&selected_role.role_arn)
        .principal_arn(&selected_role.principal_arn)
        .saml_assertion(&saml_assertion.encoded_as_base64())
        .send().await?;

    let credentials = result.credentials.unwrap();
    write_credentials(&credentials).await?;

    if let Some(role_to_assume) = maybe_role_to_assume {
        let config = aws_config::ConfigLoader::default()
            .region(Region::new("cn-northwest-1"))
            .load().await;

        let aws_client = aws_sdk_sts::Client::new(&config);
        assume_role(&aws_client, role_to_assume).await?;
    }

    Ok(())
}

async fn assume_role(aws_client: &Client, role_to_assume: &String) -> anyhow::Result<()> {
    let assumed_role_output = aws_client
        .assume_role()
        .role_session_name("aws-auth")
        .role_arn(role_to_assume)
        .send()
        .await?;
    let credentials = assumed_role_output.credentials.unwrap();
    write_credentials(&credentials).await?;
    return Ok(())
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

async fn write_credentials(credentials: &aws_sdk_sts::model::Credentials) -> anyhow::Result<()> {
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

    let home = std::env::var("HOME").unwrap();

    let mut file = tokio::fs::File::create(format!("{}/.aws/credentials", home)).await?;
    let _result = file.write_all(credentials_file_content.as_bytes()).await?;
    Ok(())
}
