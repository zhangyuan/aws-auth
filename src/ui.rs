use crate::aws::AwsRole;
use crate::identity_provider::MfaFactor;
use std::io::{self, BufRead, Write};

pub trait UI {
    fn get_username_and_password(&self) -> (String, String);
    fn get_mfa_code(&self, prompt: &str) -> String;
    fn get_mfa_factor<'a>(&self, factors: &'a [MfaFactor]) -> &'a MfaFactor;
    fn get_aws_role<'a>(&self, roles: &'a [crate::aws::AwsRole]) -> &'a AwsRole;
}

pub struct StdUI {}

impl UI for StdUI {
    fn get_username_and_password(&self) -> (String, String) {
        let username = self.get("Username");
        let password = self.get_password("Password");

        (username, password)
    }

    fn get_mfa_code(&self, prompt: &str) -> String {
        self.get(prompt)
    }

    fn get_mfa_factor<'a>(&self, factors: &'a [MfaFactor]) -> &'a MfaFactor {
        let stdin = io::stdin();
        let mut text = String::new();

        let totp_factors = factors
            .iter()
            .filter(|f| f.factor_type == "token:software:totp")
            .collect::<Vec<_>>();
        loop {
            for (idx, e) in totp_factors.iter().enumerate() {
                println!("[{}] {} - {} ", idx, e.provider, e.factor_type);
            }
            text.clear();
            print!("Select the mfa method: ");
            io::stdout().flush().unwrap();

            stdin
                .lock()
                .read_line(&mut text)
                .unwrap_or_else(|_| panic!("Could not read MFA"));
            let result = text.trim().parse::<usize>();

            if let Ok(selected) = result {
                if selected < totp_factors.len() {
                    return totp_factors.get(selected).unwrap();
                }
            }
        }
    }

    fn get_aws_role<'a>(&self, roles: &'a [crate::aws::AwsRole]) -> &'a AwsRole {
        let stdin = io::stdin();
        let mut text = String::new();

        loop {
            println!("Available role(s):");
            for (idx, e) in roles.iter().enumerate() {
                println!("[{}] {}", idx, e.principal_arn);
            }
            text.clear();
            print!("Select the role: ");
            io::stdout().flush().unwrap();
            stdin
                .lock()
                .read_line(&mut text)
                .unwrap_or_else(|_| panic!("Could not read role"));
            let result = text.trim().parse::<usize>();

            if let Ok(selected) = result {
                if selected < roles.len() {
                    return roles.get(selected).unwrap();
                }
            }
        }
    }
}

impl StdUI {
    fn get(&self, prompt: &str) -> String {
        let stdin = io::stdin();
        let mut text = String::new();
        while text.trim().is_empty() {
            print!("{}: ", prompt);
            io::stdout().flush().unwrap();
            text.clear();
            stdin
                .lock()
                .read_line(&mut text)
                .unwrap_or_else(|_| panic!("Could not read {}", prompt));
        }
        return text.trim().to_string();
    }

    fn get_password(&self, prompt: &str) -> String {
        loop {
            print!("{}: ", prompt);
            io::stdout().flush().unwrap();
            let password = rpassword::read_password().unwrap();
            if password.trim().is_empty() {
                continue;
            }
            return password;
        }
    }
}
