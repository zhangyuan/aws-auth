pub fn create_http_client_with_redirects() -> anyhow::Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > 5 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        }))
        .build()?;
    Ok(client)
}

pub fn create_http_client() -> reqwest::Client {
    reqwest::Client::new()
}
