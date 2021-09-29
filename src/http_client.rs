pub fn create_http_client_with_redirects() -> Result<reqwest::blocking::Client, anyhow::Error> {
    let client = reqwest::blocking::Client::builder()
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

pub fn create_http_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::new()
}