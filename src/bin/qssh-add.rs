//! QSSH-Add - Add keys to QSSH agent

use clap::Parser;
use qssh::agent::{AgentClient, AgentMessage};
use qssh::PqAlgorithm;
use std::path::PathBuf;
use tokio::fs;

#[derive(Parser, Debug)]
#[clap(name = "qssh-add")]
#[clap(about = "Add post-quantum SSH keys to QSSH agent")]
struct Args {
    /// Key file to add (default: ~/.qssh/id_qssh)
    key_file: Option<PathBuf>,

    /// List keys in agent
    #[clap(short = 'l', long)]
    list: bool,

    /// Delete all keys from agent
    #[clap(short = 'D', long)]
    delete_all: bool,

    /// Delete specific key
    #[clap(short = 'd', long)]
    delete: Option<PathBuf>,

    /// Key lifetime in seconds (0 = forever)
    #[clap(short = 't', long)]
    lifetime: Option<u32>,

    /// Lock agent with passphrase
    #[clap(short = 'x', long)]
    lock: bool,

    /// Unlock agent
    #[clap(short = 'X', long)]
    unlock: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Create agent client
    let client = AgentClient::new();

    // Handle operations
    if args.list {
        list_keys(&client).await;
    } else if args.delete_all {
        delete_all_keys(&client).await;
    } else if let Some(key_path) = args.delete {
        delete_key(&client, key_path).await;
    } else if args.lock {
        lock_agent(&client).await;
    } else if args.unlock {
        unlock_agent(&client).await;
    } else {
        // Add key
        let key_path = args.key_file.unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".qssh/id_qssh")
        });

        add_key(&client, key_path, args.lifetime).await;
    }
}

async fn list_keys(client: &AgentClient) {
    match client.list_keys().await {
        Ok(keys) => {
            if keys.is_empty() {
                println!("The agent has no identities.");
            } else {
                println!("The agent has {} key(s):", keys.len());
                for key in keys {
                    println!("{} {} {} ({})",
                        key.public_key.len() * 8,
                        key.fingerprint,
                        key.comment,
                        format!("{:?}", key.algorithm));
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to list keys: {}", e);
            std::process::exit(1);
        }
    }
}

async fn delete_all_keys(client: &AgentClient) {
    match client.request(AgentMessage::RemoveAllKeys).await {
        Ok(AgentMessage::AllKeysRemoved) => {
            println!("All identities removed.");
        }
        Ok(AgentMessage::Error(e)) => {
            eprintln!("Failed to remove keys: {}", e);
            std::process::exit(1);
        }
        _ => {
            eprintln!("Unexpected response from agent");
            std::process::exit(1);
        }
    }
}

async fn delete_key(client: &AgentClient, key_path: PathBuf) {
    // Load public key
    let pubkey_path = key_path.with_extension("pub");
    let pubkey_data = match fs::read_to_string(&pubkey_path).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read public key {}: {}", pubkey_path.display(), e);
            std::process::exit(1);
        }
    };

    // Parse public key from standard SSH format
    let parts: Vec<&str> = pubkey_data.split_whitespace().collect();
    if parts.len() < 2 {
        eprintln!("Invalid public key format");
        std::process::exit(1);
    }

    use base64::Engine;
    let public_key = match base64::engine::general_purpose::STANDARD.decode(parts[1]) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to decode public key: {}", e);
            std::process::exit(1);
        }
    };

    match client.request(AgentMessage::RemoveKey { public_key }).await {
        Ok(AgentMessage::KeyRemoved) => {
            println!("Identity removed: {}", key_path.display());
        }
        Ok(AgentMessage::Error(e)) => {
            eprintln!("Failed to remove key: {}", e);
            std::process::exit(1);
        }
        _ => {
            eprintln!("Unexpected response from agent");
            std::process::exit(1);
        }
    }
}

async fn add_key(client: &AgentClient, key_path: PathBuf, lifetime: Option<u32>) {
    // Read private key
    let key_data = match fs::read_to_string(&key_path).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read key {}: {}", key_path.display(), e);
            std::process::exit(1);
        }
    };

    // Parse key type from header
    let algorithm = if key_data.contains("FALCON") {
        PqAlgorithm::Falcon512
    } else if key_data.contains("SPHINCS") {
        PqAlgorithm::SphincsPlus
    } else {
        eprintln!("Unknown key type");
        std::process::exit(1);
    };

    // Extract base64 key data from PEM format
    let mut key_lines = Vec::new();
    let mut in_key = false;
    for line in key_data.lines() {
        if line.contains("BEGIN") {
            in_key = true;
        } else if line.contains("END") {
            break;
        } else if in_key && !line.starts_with('-') {
            key_lines.push(line);
        }
    }

    use base64::Engine;
    let private_key = match base64::engine::general_purpose::STANDARD.decode(key_lines.join("")) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to decode private key: {}", e);
            std::process::exit(1);
        }
    };

    // Read public key
    let pubkey_path = key_path.with_extension("pub");
    let pubkey_data = match fs::read_to_string(&pubkey_path).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read public key: {}", e);
            std::process::exit(1);
        }
    };

    // Parse public key
    let parts: Vec<&str> = pubkey_data.split_whitespace().collect();
    if parts.len() < 2 {
        eprintln!("Invalid public key format");
        std::process::exit(1);
    }

    let public_key = match base64::engine::general_purpose::STANDARD.decode(parts[1]) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to decode public key: {}", e);
            std::process::exit(1);
        }
    };

    let comment = parts.get(2).unwrap_or(&"").to_string();

    // Prompt for passphrase if key is encrypted
    // For now, assume unencrypted keys

    // Add to agent
    match client.add_key(algorithm, private_key, public_key, comment, lifetime).await {
        Ok(()) => {
            println!("Identity added: {}", key_path.display());
            if let Some(t) = lifetime {
                if t > 0 {
                    println!("Lifetime set to {} seconds", t);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to add key: {}", e);
            std::process::exit(1);
        }
    }
}

async fn lock_agent(client: &AgentClient) {
    eprint!("Enter lock passphrase: ");
    let passphrase = rpassword::read_password().unwrap();

    match client.request(AgentMessage::Lock { passphrase }).await {
        Ok(AgentMessage::Locked) => {
            println!("Agent locked.");
        }
        Ok(AgentMessage::Error(e)) => {
            eprintln!("Failed to lock agent: {}", e);
            std::process::exit(1);
        }
        _ => {
            eprintln!("Unexpected response from agent");
            std::process::exit(1);
        }
    }
}

async fn unlock_agent(client: &AgentClient) {
    eprint!("Enter lock passphrase: ");
    let passphrase = rpassword::read_password().unwrap();

    match client.request(AgentMessage::Unlock { passphrase }).await {
        Ok(AgentMessage::Unlocked) => {
            println!("Agent unlocked.");
        }
        Ok(AgentMessage::Error(e)) => {
            eprintln!("Failed to unlock agent: {}", e);
            std::process::exit(1);
        }
        _ => {
            eprintln!("Unexpected response from agent");
            std::process::exit(1);
        }
    }
}