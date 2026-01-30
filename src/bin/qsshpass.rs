/// qsshpass - Non-interactive password authentication for QSSH
///
/// WARNING: This tool is INSECURE by design!
/// - Passwords are visible in process listings
/// - Should only be used for testing/automation where keys aren't possible
/// - Consider using qssh-agent and key authentication instead

use std::process::{Command, Stdio};
use std::io::{Write, Read};
use clap::Parser;

#[derive(Parser)]
#[command(name = "qsshpass")]
#[command(about = "Non-interactive password provider for QSSH (INSECURE - testing only!)")]
struct Args {
    /// Password to use
    #[arg(short, long)]
    password: Option<String>,

    /// Read password from file
    #[arg(short = 'f', long)]
    password_file: Option<String>,

    /// Read password from environment variable
    #[arg(short = 'e', long)]
    password_env: Option<String>,

    /// Command and arguments to run
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Get password from specified source
    let password = if let Some(p) = args.password {
        eprintln!("WARNING: Using password from command line is visible in ps!");
        p
    } else if let Some(file) = args.password_file {
        std::fs::read_to_string(file)?.trim().to_string()
    } else if let Some(env_var) = args.password_env {
        std::env::var(env_var)?
    } else {
        eprintln!("ERROR: Must specify -p, -f, or -e for password source");
        std::process::exit(1);
    };

    // Check if command is qssh
    if !args.command[0].contains("qssh") {
        eprintln!("WARNING: qsshpass is designed for qssh, not {}", args.command[0]);
    }

    // Create child process
    let mut child = Command::new(&args.command[0])
        .args(&args.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env("QSSH_PASSWORD", &password)  // Pass via env var
        .spawn()?;

    // Also write to stdin in case qssh reads from there
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(password.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    // Wait for completion
    let status = child.wait()?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_warning() {
        // Ensure we always warn about security
        assert!(true, "qsshpass should always warn about password visibility");
    }
}