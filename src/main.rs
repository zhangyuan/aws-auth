use std::path::Path;

use url::Url;
pub mod aws;
pub mod http_client;
pub mod okta;
pub mod saml;

pub mod ui;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_sts::Credentials;

use okta::Okta;
use ui::{StdUI, UI};

use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let maybe_role_to_assume = args.get(1);

    let region_provider = RegionProviderChain::default_provider();

    let region = region_provider.region().await;

    if region.is_none() {
        panic!("region is not set.")
    } else {
        log::debug!("use region {}", region.unwrap());
    }

    let credentials_path = aws::touch_credential_file().await?;

    let mut credentials_config = config::Config::builder()
        .add_source(config::File::with_name(&credentials_path).format(config::FileFormat::Ini))
        .build()?;

    let maybe_credentials = aws::lookup_credentials(&mut credentials_config);

    let config = aws_config::ConfigLoader::default()
        .credentials_provider(
            maybe_credentials
                .clone()
                .unwrap_or_else(|| Credentials::from_keys("", "", None)),
        )
        .load()
        .await;

    let aws_client = aws_sdk_sts::Client::new(&config);

    if maybe_credentials.is_some() {
        let sts_result = aws::get_caller_role(&aws_client).await;

        if sts_result.is_some() {
            if let Some(role_to_assume) = maybe_role_to_assume {
                let credentials = aws::assume_role(&aws_client, role_to_assume).await?;
                aws::write_credentials(&credentials_path, &credentials).await?;
            }
            return Ok(());
        }
    }

    let settings = load_settings()?;

    let app_link = settings.get_string("app-link")?;

    let parsed_url = Url::parse(&app_link)?;
    let identify_base_uri = format!("{}://{}", parsed_url.scheme(), parsed_url.domain().unwrap());

    let client = http_client::create_http_client_with_redirects()?;

    let stdui = StdUI {};

    let okta = Okta {
        ui: &stdui,
        http_client: &client,
        base_uri: &identify_base_uri,
        app_link: &app_link,
    };

    let saml_assertion = okta.get_saml_assertion().await?;

    let roles = saml_assertion.extract_roles()?;
    let selected_role = stdui.get_aws_role(&roles);

    let credentials =
        aws::get_credentials_by_assume_role_with_saml(aws_client, &saml_assertion, selected_role)
            .await?;

    aws::write_credentials(&credentials_path, &credentials).await?;

    if let Some(role_to_assume) = maybe_role_to_assume {
        let config = aws_config::ConfigLoader::default().load().await;

        let aws_client = aws_sdk_sts::Client::new(&config);
        let credentials = aws::assume_role(&aws_client, role_to_assume).await?;
        aws::write_credentials(&credentials_path, &credentials).await?;
    }

    Ok(())
}

fn load_settings() -> anyhow::Result<config::Config> {
    let local_config_path = Path::new(".aws-auth.toml").to_path_buf();

    let home = std::env::var("HOME").unwrap();
    let global_config_path = Path::new(&home).join(".aws-auth.toml");

    let config_path = if local_config_path.is_file() {
        local_config_path
    } else if global_config_path.is_file() {
        global_config_path
    } else {
        return Err(anyhow::anyhow!("Config file is not found."));
    };

    config::Config::builder()
        .add_source(config::File::with_name(config_path.to_str().unwrap()))
        .build()
        .map_err(anyhow::Error::new)
}
