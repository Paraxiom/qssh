//! QSSH Node Connect — One-liner PQ tunnel to a QuantumHarmony node
//!
//! Opens a PQ-encrypted tunnel binding all standard node ports,
//! unlocks the signing service vault, and signals the agent to enter self-heal mode.
//!
//! Usage:
//!   qssh-node connect alice         # Connect to alice with all standard ports
//!   qssh-node connect alice --port 2222  # Custom qssh port
//!   qssh-node status alice          # Check connection status
//!   qssh-node disconnect alice      # Disconnect from node

use clap::{Parser, Subcommand};
use qssh::{QsshConfig, PqAlgorithm, QsshClient, KexAlgorithm, security_tiers::SecurityTier};
use qssh::config::ConfigParser;
use qssh::port_forward::PortForwardManager;
use qssh::vault::SigningClient;
use std::path::PathBuf;
use std::sync::Arc;

/// Standard port forwards for a QuantumHarmony node
const DEFAULT_FORWARDS: &[(&str, u16)] = &[
    ("Node RPC",         9944),
    ("Dashboard",        8080),
    ("Faucet",           8085),
    ("Operator API",     9955),
    ("Coherence Shield", 3080),
];

#[derive(Parser, Debug)]
#[clap(name = "qssh-node")]
#[clap(about = "Connect to a QuantumHarmony node with a single command")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Args {
    #[clap(subcommand)]
    command: NodeCommand,
}

#[derive(Subcommand, Debug)]
enum NodeCommand {
    /// Connect to a node (opens PQ tunnel + unlocks vault)
    Connect {
        /// Node name (looked up in ~/.qssh/config) or user@host
        node: String,

        /// QSSH server port
        #[clap(short = 'p', long, default_value = "22222")]
        port: u16,

        /// Additional local port forwards (e.g., 8200:localhost:8200)
        #[clap(short = 'L', long)]
        local: Vec<String>,

        /// Signing service socket path (to unlock vault)
        #[clap(long, default_value = "~/.qssh/sign.sock")]
        sign_socket: String,

        /// Skip vault unlock
        #[clap(long)]
        no_unlock: bool,

        /// Verbose output
        #[clap(short, long)]
        verbose: bool,

        /// Use quantum-native transport (768-byte frames)
        #[clap(long)]
        quantum_native: bool,

        /// Use classical transport
        #[clap(long)]
        classical: bool,
    },

    /// Check connection status for a node
    Status {
        /// Node name
        node: String,
    },

    /// List known nodes from ~/.qssh/config
    List,
}

fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(format!("{}{}", home, &path[1..]));
        }
    }
    PathBuf::from(path)
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match args.command {
        NodeCommand::Connect {
            node, port, local, sign_socket,
            no_unlock, verbose, quantum_native, classical,
        } => {
            // Initialize logging
            if verbose {
                env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                    .target(env_logger::Target::Stderr)
                    .init();
            } else {
                env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                    .target(env_logger::Target::Stderr)
                    .init();
            }

            // Load qssh config to resolve node name
            let config_parser = ConfigParser::load_default().unwrap_or_else(|e| {
                if verbose {
                    eprintln!("Warning: Failed to load config: {}", e);
                }
                ConfigParser::parse("").unwrap()
            });

            // Parse destination (node name or user@host)
            let (username, hostname) = if node.contains('@') {
                let parts: Vec<&str> = node.split('@').collect();
                if parts.len() != 2 {
                    eprintln!("Error: Invalid format. Use node-name or user@host");
                    std::process::exit(1);
                }
                (Some(parts[0].to_string()), parts[1].to_string())
            } else {
                (None, node.clone())
            };

            let host_config = config_parser.get_host_config(&hostname);

            let username = username.or(host_config.user).unwrap_or_else(|| {
                whoami::username()
            });

            let actual_host = if let Some(h) = host_config.hostname {
                h
            } else {
                hostname.clone()
            };

            let actual_port = if port != 22222 {
                port
            } else {
                host_config.port.unwrap_or(22222)
            };

            let server = format!("{}:{}", actual_host, actual_port);

            // Determine transport
            let use_quantum = if classical { false } else if quantum_native { true } else { true };

            eprintln!("QSSH Node Connect v{}", env!("CARGO_PKG_VERSION"));
            eprintln!("Connecting to {} as {}...", server, username);

            // Build port forward list: default + extras
            let mut forwards = Vec::new();
            for (name, p) in DEFAULT_FORWARDS {
                let spec = format!("{}:localhost:{}", p, p);
                match PortForwardManager::parse_forward_spec(&spec, "local") {
                    Ok(fwd) => {
                        eprintln!("  -L {} ({})", spec, name);
                        forwards.push(fwd);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to parse default forward {}: {}", spec, e);
                    }
                }
            }

            // Add extra forwards
            for spec in &local {
                match PortForwardManager::parse_forward_spec(spec, "local") {
                    Ok(fwd) => {
                        eprintln!("  -L {} (custom)", spec);
                        forwards.push(fwd);
                    }
                    Err(e) => {
                        eprintln!("Error: Invalid forward spec '{}': {}", spec, e);
                        std::process::exit(1);
                    }
                }
            }

            // Create qssh config
            let config = QsshConfig {
                server: server.clone(),
                username: username.clone(),
                password: None,
                port_forwards: Vec::new(),
                use_qkd: false,
                qkd_endpoint: None,
                qkd_cert_path: None,
                qkd_key_path: None,
                qkd_ca_path: None,
                pq_algorithm: PqAlgorithm::Falcon512,
                kex_algorithm: KexAlgorithm::default(),
                key_rotation_interval: 3600,
                security_tier: SecurityTier::default(),
                quantum_native: use_quantum,
            };

            // Connect
            let mut client = QsshClient::new(config);
            match client.connect().await {
                Ok(()) => {
                    eprintln!("Connected to {} (PQ-encrypted)", server);
                }
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                    std::process::exit(1);
                }
            }

            // Set up port forwards
            if let Some(transport) = client.transport() {
                let transport = Arc::new(transport.clone());
                let mut pfm = PortForwardManager::new(transport);
                for fwd in forwards {
                    pfm.add_forward(fwd);
                }
                match pfm.start_all().await {
                    Ok(()) => {
                        eprintln!("All port forwards established");
                        client.set_remote_forward_state(
                            pfm.remote_registry(),
                            pfm.channel_router(),
                        );
                    }
                    Err(e) => {
                        eprintln!("Warning: Port forward setup failed: {}", e);
                    }
                }
            }

            // Unlock signing service vault
            if !no_unlock {
                let sign_path = expand_tilde(&sign_socket);
                if sign_path.exists() {
                    eprintln!("Unlocking signing service vault...");

                    // Prompt for passphrase
                    eprint!("Vault passphrase: ");
                    match rpassword::read_password() {
                        Ok(passphrase) => {
                            let signing_client = SigningClient::new(sign_path);
                            match signing_client.unlock(&passphrase).await {
                                Ok(()) => {
                                    eprintln!("Vault unlocked — agent entering self-heal mode");
                                }
                                Err(e) => {
                                    eprintln!("Warning: Vault unlock failed: {}", e);
                                    eprintln!("Agent will remain in watch-only mode");
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: Could not read passphrase: {}", e);
                        }
                    }
                } else {
                    eprintln!("Signing service not running (no socket at {:?})", sign_path);
                    eprintln!("Start it with: qssh-sign");
                }
            }

            eprintln!();
            eprintln!("Node {} connected. Access via:", hostname);
            for (name, p) in DEFAULT_FORWARDS {
                eprintln!("  {} → http://localhost:{}", name, p);
            }
            eprintln!();
            eprintln!("Press Ctrl+C to disconnect");

            // Keep connection alive (forward loop)
            match client.run_forward_loop().await {
                Ok(()) => {}
                Err(e) => {
                    log::debug!("Forward loop ended: {}", e);
                }
            }

            // Disconnect
            if let Err(e) = client.disconnect().await {
                log::debug!("Disconnect error: {}", e);
            }

            // Lock vault on disconnect
            if !no_unlock {
                let sign_path = expand_tilde(&sign_socket);
                if sign_path.exists() {
                    let signing_client = SigningClient::new(sign_path);
                    if let Ok(()) = signing_client.lock().await {
                        eprintln!("Vault locked — agent returning to watch-only mode");
                    }
                }
            }

            eprintln!("Disconnected from {}", hostname);
        }

        NodeCommand::Status { node } => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
                .init();

            eprintln!("Checking status of node: {}", node);

            // Check signing service
            let sign_path = expand_tilde("~/.qssh/sign.sock");
            if sign_path.exists() {
                let client = SigningClient::new(sign_path);
                match client.health().await {
                    Ok(unlocked) => {
                        if unlocked {
                            eprintln!("  Signing service: UNLOCKED (self-heal mode)");
                        } else {
                            eprintln!("  Signing service: LOCKED (watch-only mode)");
                        }
                    }
                    Err(e) => {
                        eprintln!("  Signing service: ERROR ({})", e);
                    }
                }
            } else {
                eprintln!("  Signing service: NOT RUNNING");
            }

            // Check if standard ports are reachable
            for (name, port) in DEFAULT_FORWARDS {
                let addr = format!("127.0.0.1:{}", port);
                match std::net::TcpStream::connect_timeout(
                    &addr.parse().unwrap(),
                    std::time::Duration::from_secs(1),
                ) {
                    Ok(_) => eprintln!("  {} (:{}) → REACHABLE", name, port),
                    Err(_) => eprintln!("  {} (:{}) → NOT REACHABLE", name, port),
                }
            }
        }

        NodeCommand::List => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
                .init();

            let config_parser = ConfigParser::load_default().unwrap_or_else(|_| {
                ConfigParser::parse("").unwrap()
            });

            eprintln!("Known nodes (from ~/.qssh/config):");
            let hosts = config_parser.list_hosts();
            if hosts.is_empty() {
                eprintln!("  (none — add hosts to ~/.qssh/config)");
            } else {
                for host in hosts {
                    let cfg = config_parser.get_host_config(&host);
                    let hostname = cfg.hostname.unwrap_or_else(|| host.clone());
                    let port = cfg.port.unwrap_or(22222);
                    let user = cfg.user.unwrap_or_else(|| "?".into());
                    eprintln!("  {} → {}@{}:{}", host, user, hostname, port);
                }
            }
        }
    }
}
