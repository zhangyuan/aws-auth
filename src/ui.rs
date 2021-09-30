use std::io::{self, Write, BufRead};

pub trait UI {
    fn get_username_and_password(&self) -> (String, String);
    fn get(&self, prompt: &str) -> String;
}

pub struct StdUI {
}

impl UI for StdUI {
    fn get_username_and_password(&self) -> (String, String) {
        let username = self.get("Username");

        let mut password: String;
        loop {
            print!("{}: ", "Password");
            io::stdout().flush().unwrap();

            password = rpassword::read_password().unwrap();

            if password.trim().is_empty() {
                continue
            }
            break;
        }

        (username, password)
    }

    fn get(&self, prompt: &str) -> String {
        let stdin = io::stdin();
        let mut text = String::new();
        while text.trim().is_empty() {
            print!("{}: ", prompt);
            io::stdout().flush().unwrap();
            text.clear();
            stdin.lock().read_line(&mut text).expect("Could not read username");
        }
        return text.trim().to_string();
    }
}
