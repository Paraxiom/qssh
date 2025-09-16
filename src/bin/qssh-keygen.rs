//! QSSH Key Generation Tool
//! 
//! Generates quantum-safe keypairs for QSSH authentication

use clap::{Parser, ValueEnum};
use qssh::crypto::{PqKeyExchange, PqSignature};
use qssh::PqAlgorithm;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use base64::Engine;

#[derive(Parser)]
#[command(name = "qssh-keygen")]
#[command(about = "Generate quantum-safe SSH keys", long_about = None)]
struct Args {
    /// Type of key to generate
    #[arg(short = 't', long, default_value = "falcon512")]
    key_type: KeyType,

    /// Output file path (private key)
    #[arg(short = 'f', long, default_value = "~/.qssh/id_qssh")]
    output: String,

    /// Comment for the key
    #[arg(short = 'C', long)]
    comment: Option<String>,

    /// Bits of entropy (ignored, for compatibility)
    #[arg(short = 'b', long)]
    bits: Option<u32>,

    /// Generate host key instead of user key
    #[arg(long)]
    host_key: bool,

    /// Overwrite existing key without prompting
    #[arg(short = 'y', long)]
    yes: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum KeyType {
    #[value(name = "falcon512")]
    Falcon512,
    #[value(name = "sphincs+")]
    SphincsPlus,
    #[value(name = "rsa")]
    Rsa,  // For compatibility warning
    #[value(name = "ed25519")]
    Ed25519,  // For compatibility warning
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Warn about non-quantum algorithms
    match args.key_type {
        KeyType::Rsa | KeyType::Ed25519 => {
            eprintln!("Warning: {} is not quantum-safe. Use falcon512 or sphincs+ instead.", 
                match args.key_type {
                    KeyType::Rsa => "RSA",
                    KeyType::Ed25519 => "Ed25519",
                    _ => unreachable!()
                });
            std::process::exit(1);
        }
        _ => {}
    }

    // Expand tilde in output path
    let output_path = expand_tilde(&args.output);
    let public_path = format!("{}.pub", output_path);

    // Check if files exist
    if !args.yes && (std::path::Path::new(&output_path).exists() || 
                     std::path::Path::new(&public_path).exists()) {
        eprint!("{} already exists. Overwrite? (y/n) ", output_path);
        use std::io::{self, BufRead};
        let stdin = io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        if !line.trim().eq_ignore_ascii_case("y") {
            println!("Key generation cancelled.");
            return Ok(());
        }
    }

    // Create directory if needed
    if let Some(parent) = std::path::Path::new(&output_path).parent() {
        fs::create_dir_all(parent)?;
    }

    // Generate the keypair
    println!("Generating {} key pair...", match args.key_type {
        KeyType::Falcon512 => "Falcon-512 post-quantum",
        KeyType::SphincsPlus => "SPHINCS+ post-quantum",
        _ => unreachable!()
    });

    let (private_key, public_key, algorithm) = match args.key_type {
        KeyType::Falcon512 => {
            let kex = PqKeyExchange::new()?;
            let private_bytes = kex.secret_bytes();
            let public_bytes = kex.public_bytes();
            (private_bytes, public_bytes, PqAlgorithm::Falcon512)
        },
        KeyType::SphincsPlus => {
            let sig = PqSignature::new()?;
            let private_bytes = sig.secret_bytes();
            let public_bytes = sig.public_bytes();
            (private_bytes, public_bytes, PqAlgorithm::SphincsPlus)
        },
        _ => unreachable!()
    };

    // Format the private key (similar to OpenSSH format but quantum-safe)
    let private_pem = format!(
        "-----BEGIN QSSH PRIVATE KEY-----\n\
         Algorithm: {}\n\
         {}\n\
         -----END QSSH PRIVATE KEY-----\n",
        algorithm,
        base64::engine::general_purpose::STANDARD.encode(&private_key)
    );

    // Format the public key (similar to OpenSSH authorized_keys format)
    let comment = args.comment.unwrap_or_else(|| {
        format!("{}@{}", 
            std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
            hostname::get().ok()
                .and_then(|h| h.to_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "localhost".to_string())
        )
    });

    let public_line = format!(
        "qssh-{} {} {}\n",
        match algorithm {
            PqAlgorithm::Falcon512 => "falcon512",
            PqAlgorithm::SphincsPlus => "sphincs+",
            _ => panic!("Unsupported algorithm"),
        },
        base64::engine::general_purpose::STANDARD.encode(&public_key),
        comment
    );

    // Write private key with restricted permissions
    fs::write(&output_path, private_pem)?;
    let mut perms = fs::metadata(&output_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&output_path, perms)?;

    // Write public key
    fs::write(&public_path, public_line)?;

    // Display fingerprint
    let fingerprint = compute_fingerprint(&public_key);
    
    println!("Your identification has been saved in {}", output_path);
    println!("Your public key has been saved in {}", public_path);
    println!("The key fingerprint is:");
    println!("{} {} {} ({})", 
        fingerprint,
        public_key.len() * 8,
        comment,
        algorithm
    );

    if args.host_key {
        println!("\nFor host key, add to /etc/qssh/host_key");
    } else {
        println!("\nTo use this key, add the contents of {} to the remote ~/.qssh/authorized_keys", public_path);
    }

    Ok(())
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") || path == "~" {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        path.replacen("~", &home, 1)
    } else {
        path.to_string()
    }
}

fn compute_fingerprint(public_key: &[u8]) -> String {
    use sha3::{Sha3_256, Digest};
    let mut hasher = Sha3_256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    
    // Format as colon-separated hex like SSH
    hash.iter()
        .take(16)  // First 16 bytes
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}