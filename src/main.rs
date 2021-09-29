use std::collections::HashMap;

use aws_auth::IdentiyProvider;
use aws_auth::SAMLAssertion;

mod okta;
use okta::Okta;

mod aws;
use aws::AwsClient;

mod http_client;

fn main() -> anyhow::Result<()> {
    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("aws-auth")).unwrap();
    let settings = settings.try_into::<HashMap<String, String>>().unwrap();

    let app_link = settings.get("app-link").unwrap();
    println!("app_link: {}", app_link);

    let okta_uri = settings.get("okta-uri").unwrap();
    println!("okta_uri: {}", okta_uri);

    let client = http_client::create_http_client_with_redirects()?;

    let okta = Okta {
        http_client: &client,
        base_uri: okta_uri,
        app_link: app_link
    };

    let aws = AwsClient {
        http_client: &http_client::create_http_client()
    };

    let saml_assertion = get_saml_assertion(&okta)?;

    let roles = saml_assertion.extract_roles()?;

    if roles.len() == 1 {
        let mut role = roles[0].split(",");

        println!("roles[0] {}", roles[0]);

        let role_arn = role.next().unwrap();
        let principal_arn = role.next().unwrap();

        let resp = aws.get_sts_token(&role_arn, &principal_arn, &saml_assertion.encoded_as_base64())?;

        // let resp: AssumeRoleWithSAMLResponseWrapper = client.get("https://sts.cn-northwest-1.amazonaws.com.cn")
        //     .query(&[
        //         ("Version", "2011-06-15"),
        //         ("Action", "AssumeRoleWithSAML"),
        //         ("RoleArn", &role_arn),
        //         ("PrincipalArn", &principal_arn),
        //         ("SAMLAssertion", &saml_assertion.encoded_as_base64())
        //     ])
        //     .header("Accept", "application/json")
        //     .send()?
        //     .json()?;

        println!("{:?}", resp);        
    }

    return Ok(());
}

fn get_saml_assertion(provider: &dyn IdentiyProvider) -> anyhow::Result<SAMLAssertion> {
    provider.get_saml_assertion()
}