use std::io::{self, BufRead, Write};

pub trait UI {
    fn get_username_and_password(&self) -> (String, String);
    fn get_mfa_code(&self, prompt: &str) -> String;
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
