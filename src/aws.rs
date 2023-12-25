use crate::saml::{AwsRole, SAMLAssertion};
use dirs::home_dir;
use std::path::Path;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

pub fn lookup_credentials(
    credentials_config: &mut config::Config,
) -> Option<aws_sdk_sts::Credentials> {
    let maybe_credentials = if let Ok(default_credentials) = credentials_config.get_table("default")
    {
        if default_credentials.contains_key("aws_access_key_id")
            && default_credentials.contains_key("aws_secret_access_key")
            && default_credentials.contains_key("aws_session_token")
        {
            let access_key_id = default_credentials
                .get("aws_access_key_id")
                .unwrap()
                .to_string();
            let secret_access_key = default_credentials
                .get("aws_secret_access_key")
                .unwrap()
                .to_string();
            let session_token = default_credentials
                .get("aws_session_token")
                .unwrap()
                .to_string();
            Some(aws_sdk_sts::Credentials::from_keys(
                access_key_id,
                secret_access_key,
                Some(session_token),
            ))
        } else {
            None
        }
    } else {
        None
    };
    maybe_credentials
}

pub async fn get_caller_role(aws_client: &aws_sdk_sts::Client) -> Option<String> {
    let sts_result = aws_client.get_caller_identity().send().await;

    sts_result.map(|x| x.arn).ok().flatten()
}
pub async fn assume_role(
    aws_client: &aws_sdk_sts::Client,
    role_to_assume: &str,
) -> anyhow::Result<aws_sdk_sts::model::Credentials> {
    let assumed_role_output = aws_client
        .assume_role()
        .role_session_name("aws-auth")
        .role_arn(role_to_assume)
        .send()
        .await?;
    let credentials = assumed_role_output.credentials.unwrap();

    Ok(credentials)
}

pub async fn get_credentials_by_assume_role_with_saml(
    aws_client: aws_sdk_sts::Client,
    saml_assertion: &SAMLAssertion,
    selected_role: &AwsRole,
) -> anyhow::Result<aws_sdk_sts::model::Credentials> {
    let result = aws_client
        .assume_role_with_saml()
        .role_arn(&selected_role.role_arn)
        .principal_arn(&selected_role.provider_arn)
        .saml_assertion(&saml_assertion.encoded_as_base64())
        .send()
        .await?;

    let credentials = result
        .credentials
        .ok_or(anyhow::anyhow!("No credentials in response"))?;

    Ok(credentials)
}

pub async fn write_credentials(
    path: &str,
    credentials: &aws_sdk_sts::model::Credentials,
) -> anyhow::Result<()> {
    let access_key_id = credentials
        .access_key_id
        .as_ref()
        .ok_or(anyhow::anyhow!("No access key id"))?;
    let secret_access_key = credentials
        .secret_access_key
        .as_ref()
        .ok_or(anyhow::anyhow!("No secret access key"))?;
    let session_token = credentials
        .session_token
        .as_ref()
        .ok_or(anyhow::anyhow!("No session token"))?;
    let expiration = credentials
        .expiration
        .as_ref()
        .ok_or(anyhow::anyhow!("No expiration date"))?;

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
        expiration.secs(),
    );

    let mut file = tokio::fs::File::create(path).await?;
    file.write_all(credentials_file_content.as_bytes()).await?;
    Ok(())
}

pub async fn touch_credential_file() -> anyhow::Result<String> {
    let home = home_dir().ok_or(anyhow::anyhow!("Unable to get home directory"))?;
    let credentials_path = format!("{}/.aws/credentials", home.display());
    OpenOptions::new()
        .create(true)
        .write(true)
        .open(Path::new(&credentials_path))
        .await?;
    Ok(credentials_path)
}
