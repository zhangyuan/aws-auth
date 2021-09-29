use std::io::{self, Write, BufRead};

pub fn read_from_stdin(prompt: &str) -> String {
    let stdin = io::stdin();
    let mut text = String::new();
    while text.trim().is_empty() {
        print!("{}: ", prompt);
        io::stdout().flush().unwrap();
        text.clear();
        stdin.lock().read_line(&mut text).expect("Could not read username");
    }
    text.trim().to_string()
}

pub fn read_password_from_stdin(prompt: &str) -> String {
    loop {
        print!("{}: ", prompt);
        io::stdout().flush().unwrap();

        let pass = rpassword::read_password().unwrap();

        if pass.trim().is_empty() {
            continue
        }
        return pass.trim().to_string();
    }
}
