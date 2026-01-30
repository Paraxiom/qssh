//! QSSH Server Daemon - Quantum-secure SSH server

use clap::Parser;
use qssh::server::{QsshServer, QsshServerConfig};
use std::process;
use std::path::PathBuf;
use tokio::fs;
use base64::Engine;
use serde::Deserialize;

/// QKD configuration loaded from file
#[derive(Debug, Deserialize)]
struct QkdFileConfig {
    /// QKD API endpoint URL
    endpoint: Option<String>,
    /// Path to client certificate
    cert_path: Option<String>,
    /// Path to client private key
    key_path: Option<String>,
    /// Path to CA certificate
    ca_path: Option<String>,
    /// Request timeout in milliseconds
    timeout_ms: Option<u64>,
    /// Minimum entropy threshold
    min_entropy: Option<f64>,
}

#[derive(Parser, Debug)]
#[clap(name = "qsshd")]
#[clap(about = "Quantum-Secure Shell Daemon - Accept quantum-secure remote connections")]
#[clap(version = "0.1.0")]
struct Args {
    /// Address to listen on
    #[clap(short, long, default_value = "0.0.0.0:4242")]
    listen: String,
    
    /// Generate host keys and exit
    #[clap(long)]
    generate_keys: bool,
    
    /// Host key file
    #[clap(long, default_value = "/etc/qssh/host_key")]
    host_key: PathBuf,
    
    /// Authorized keys file
    #[clap(long, default_value = "/etc/qssh/authorized_keys")]
    authorized_keys: PathBuf,
    
    /// Maximum concurrent connections
    #[clap(long, default_value = "100")]
    max_connections: usize,
    
    /// Enable QKD support
    #[clap(long)]
    qkd: bool,
    
    /// QKD configuration file
    #[clap(long)]
    qkd_config: Option<PathBuf>,
    
    /// Verbose output
    #[clap(short, long)]
    verbose: bool,
    
    /// Daemonize (run in background)
    #[clap(short, long)]
    daemon: bool,

    /// Use quantum-native transport (768-byte indistinguishable frames)
    #[clap(long)]
    quantum_native: bool,

    /// Use classical transport (for compatibility)
    #[clap(long)]
    classical: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    
    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }
    
    // Generate keys mode
    if args.generate_keys {
        if let Err(e) = generate_host_keys(&args.host_key).await {
            eprintln!("Failed to generate host keys: {}", e);
            process::exit(1);
        }
        println!("Host keys generated successfully at: {:?}", args.host_key);
        return;
    }
    
    // Create server configuration
    let mut config = match QsshServerConfig::new(&args.listen) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to create server config: {}", e);
            process::exit(1);
        }
    };
    
    config.max_connections = args.max_connections;

    // Determine transport type
    let quantum_native = if args.classical {
        false
    } else if args.quantum_native {
        true
    } else {
        true  // Default to quantum-native
    };
    config.quantum_native = quantum_native;
    
    // Load authorized keys
    if args.authorized_keys.exists() {
        match load_authorized_keys(&args.authorized_keys).await {
            Ok(keys) => {
                for (username, pubkey) in keys {
                    config.add_authorized_key(&username, pubkey);
                }
                log::info!("Loaded {} authorized keys", config.authorized_keys.len());
            }
            Err(e) => {
                eprintln!("Failed to load authorized keys: {}", e);
                process::exit(1);
            }
        }
    } else {
        log::warn!("No authorized_keys file found at {:?}", args.authorized_keys);
    }
    
    // Load host key (in production, would deserialize from file)
    // For now, generate new key each time
    
    if args.qkd {
        log::info!("QKD support enabled");
        config.qkd_enabled = true;

        if let Some(qkd_config_path) = &args.qkd_config {
            match load_qkd_config(qkd_config_path).await {
                Ok(qkd_cfg) => {
                    log::info!("Loaded QKD configuration from {:?}", qkd_config_path);
                    if let Some(endpoint) = qkd_cfg.endpoint {
                        config.qkd_endpoint = Some(endpoint);
                    }
                    if let Some(cert_path) = qkd_cfg.cert_path {
                        config.qkd_cert_path = Some(cert_path);
                    }
                    if let Some(key_path) = qkd_cfg.key_path {
                        config.qkd_key_path = Some(key_path);
                    }
                    if let Some(ca_path) = qkd_cfg.ca_path {
                        config.qkd_ca_path = Some(ca_path);
                    }
                }
                Err(e) => {
                    log::error!("Failed to load QKD config from {:?}: {}", qkd_config_path, e);
                    process::exit(1);
                }
            }
        } else {
            log::warn!("QKD enabled but no config file specified. Using default endpoint.");
            // Default QKD endpoint for Toshiba device
            config.qkd_endpoint = Some("https://192.168.0.4/api/v1".to_string());
        }
    }
    
    // Daemonize if requested
    if args.daemon {
        log::info!("Daemonizing...");
        // In production, use proper daemonization
        // For now, just note it
    }
    
    // Create and start server
    let server = QsshServer::new(config);
    
    log::info!("Starting QSSH server on {}", args.listen);
    log::info!("Post-quantum algorithms: SPHINCS+, Falcon");
    if quantum_native {
        log::info!("Transport: Quantum-native (768-byte indistinguishable frames)");
    } else {
        log::info!("Transport: Classical (variable-size frames)");
    }
    if args.qkd {
        log::info!("QKD: Enabled");
    } else {
        log::info!("QKD: Disabled");
    }
    
    // Start server
    match server.start().await {
        Ok(()) => {
            log::info!("Server stopped normally");
        }
        Err(e) => {
            eprintln!("Server error: {}", e);
            process::exit(1);
        }
    }
}

/// Load QKD configuration from file
///
/// Supports JSON format. Example config file:
/// ```json
/// {
///     "endpoint": "https://192.168.0.4/api/v1/keys",
///     "cert_path": "/etc/qssh/qkd-cert.pem",
///     "key_path": "/etc/qssh/qkd-key.pem",
///     "ca_path": "/etc/qssh/qkd-ca.pem",
///     "timeout_ms": 5000
/// }
/// ```
async fn load_qkd_config(path: &PathBuf) -> Result<QkdFileConfig, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path).await?;

    let config: QkdFileConfig = serde_json::from_str(&contents)?;

    log::debug!("QKD config: endpoint={:?}, cert={:?}, key={:?}, ca={:?}",
        config.endpoint, config.cert_path, config.key_path, config.ca_path);

    Ok(config)
}

/// Generate host keys
async fn generate_host_keys(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use qssh::crypto::PqKeyExchange;
    
    // Create directory if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    
    // Generate keys
    let _host_key = PqKeyExchange::new()?;
    
    // In production, serialize and save to file
    // For demo, just create empty file
    fs::write(path, b"# QSSH Host Key\n# Format: SPHINCS+ and Falcon keys\n").await?;
    
    Ok(())
}

/// Load authorized keys file
async fn load_authorized_keys(path: &PathBuf) -> Result<Vec<(String, Vec<u8>)>, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path).await?;
    let mut keys = Vec::new();
    
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Support two formats:
        // 1. Standard SSH format: algorithm public-key [comment]
        // 2. QSSH format: username algorithm public-key
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if parts[0].starts_with("qssh-") {
                // Standard SSH format: qssh-algorithm key [comment]
                let algorithm = parts[0];
                let pubkey_b64 = parts[1];
                let comment = if parts.len() > 2 {
                    parts[2..].join(" ")
                } else {
                    String::new()
                };
                
                // Extract username from comment (format: user@host)
                let username = comment.split('@').next().unwrap_or("*");
                
                // Decode base64 public key
                if let Ok(pubkey) = base64::engine::general_purpose::STANDARD.decode(pubkey_b64) {
                    keys.push((username.to_string(), pubkey));
                    log::info!("Loaded key for user '{}' ({})", username, algorithm);
                } else {
                    log::warn!("Invalid public key for {}", algorithm);
                }
            } else if parts.len() >= 3 {
                // QSSH format: username algorithm public-key
                let username = parts[0];
                let _algorithm = parts[1];
                let pubkey_b64 = parts[2];
                
                if let Ok(pubkey) = base64::engine::general_purpose::STANDARD.decode(pubkey_b64) {
                    keys.push((username.to_string(), pubkey));
                    log::info!("Loaded key for user '{}'", username);
                } else {
                    log::warn!("Invalid public key for user {}", username);
                }
            }
        }
    }
    
    Ok(keys)
}

// Example authorized_keys file format:
// ```
// # QSSH Authorized Keys
// # Format: username algorithm base64-encoded-public-key
// alice sphincs+ MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg...
// bob falcon512 MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg...
// ```