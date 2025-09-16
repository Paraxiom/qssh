//! QSSH Password Management Tool

use clap::Parser;
use qssh::auth::{PasswordAuthManager, hash_password};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(name = "qssh-passwd")]
#[clap(about = "Manage QSSH user passwords")]
struct Args {
    /// Username to set password for
    username: String,

    /// Password file path (default: /etc/qssh/passwords)
    #[clap(short = 'f', long)]
    file: Option<String>,

    /// Delete user password
    #[clap(short = 'd', long)]
    delete: bool,

    /// Check if user exists
    #[clap(short = 'c', long)]
    check: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let password_file = args.file
        .unwrap_or_else(|| "/etc/qssh/passwords".to_string());

    let manager = PasswordAuthManager::new(PathBuf::from(&password_file));

    // Load existing passwords
    if let Err(e) = manager.load_passwords().await {
        eprintln!("Warning: Failed to load existing passwords: {}", e);
    }

    if args.check {
        // Check if user has a password set
        eprint!("Enter password to verify: ");
        let password = rpassword::read_password().unwrap();

        match manager.verify_password(&args.username, &password).await {
            Ok(true) => {
                println!("Password correct for user {}", args.username);
                std::process::exit(0);
            }
            Ok(false) => {
                println!("Invalid password or user not found");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Error verifying password: {}", e);
                std::process::exit(2);
            }
        }
    } else if args.delete {
        // Delete user password by setting empty entry
        match manager.set_password(&args.username, "").await {
            Ok(()) => {
                println!("Password deleted for user {}", args.username);
            }
            Err(e) => {
                eprintln!("Failed to delete password: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Set password for user
        eprint!("Enter new password for {}: ", args.username);
        let password = rpassword::read_password().unwrap();

        eprint!("Confirm password: ");
        let confirm = rpassword::read_password().unwrap();

        if password != confirm {
            eprintln!("Passwords do not match");
            std::process::exit(1);
        }

        if password.is_empty() {
            eprintln!("Password cannot be empty");
            std::process::exit(1);
        }

        // Set the password
        match manager.set_password(&args.username, &password).await {
            Ok(()) => {
                println!("Password set for user {}", args.username);
                println!("Password file: {}", password_file);
            }
            Err(e) => {
                eprintln!("Failed to set password: {}", e);
                std::process::exit(1);
            }
        }
    }
}