//! QSSH Client - Quantum-secure SSH replacement

use clap::Parser;
use qssh::{QsshConfig, PortForward, PqAlgorithm, QsshClient, security_tiers::SecurityTier};
use qssh::config::ConfigParser;
use qssh::port_forward::{PortForwardManager, ForwardType};
use log::info;
use std::process;

#[derive(Parser, Debug)]
#[clap(name = "qssh")]
#[clap(about = "Quantum-Secure Shell - Connect to remote systems with post-quantum security")]
#[clap(version = "0.1.0")]
struct Args {
    /// User@host to connect to
    destination: String,
    
    /// Port to connect to
    #[clap(short = 'p', long, default_value = "22222")]
    port: u16,
    
    /// Enable QKD (Quantum Key Distribution)
    #[clap(long)]
    qkd: bool,
    
    /// QKD endpoint URL
    #[clap(long)]
    qkd_endpoint: Option<String>,
    
    /// QKD client certificate path
    #[clap(long)]
    qkd_cert: Option<String>,
    
    /// QKD client key path
    #[clap(long)]
    qkd_key: Option<String>,
    
    /// QKD CA certificate path
    #[clap(long)]
    qkd_ca: Option<String>,
    
    /// Local port forwarding (e.g., 8080:localhost:80)
    #[clap(short = 'L', long)]
    local: Vec<String>,
    
    /// Remote port forwarding (e.g., 9000:localhost:9000)
    #[clap(short = 'R', long)]
    remote: Vec<String>,
    
    /// Post-quantum algorithm to use (sphincs, falcon512, falcon1024)
    #[clap(long, default_value = "sphincs")]
    pq_algo: String,
    
    /// Execute command instead of shell
    #[clap(short = 'c', long)]
    command: Option<String>,

    /// Use password authentication
    #[clap(short = 'P', long)]
    use_password: bool,

    /// Enable X11 forwarding
    #[clap(short = 'X', long)]
    x11: bool,

    /// Enable trusted X11 forwarding
    #[clap(short = 'Y', long)]
    trusted_x11: bool,

    /// Verbose output
    #[clap(short, long)]
    verbose: bool,

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
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .target(env_logger::Target::Stderr)
            .init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
            .target(env_logger::Target::Stderr)
            .init();
    }
    
    // Load config file
    let config_parser = ConfigParser::load_default().unwrap_or_else(|e| {
        if args.verbose {
            eprintln!("Warning: Failed to load config file: {}", e);
        }
        ConfigParser::parse("").unwrap()
    });

    // Parse destination
    let (username, hostname) = if args.destination.contains('@') {
        let parts: Vec<&str> = args.destination.split('@').collect();
        if parts.len() != 2 {
            eprintln!("Error: Invalid destination format. Use user@host or host");
            process::exit(1);
        }
        (Some(parts[0].to_string()), parts[1].to_string())
    } else {
        (None, args.destination.clone())
    };

    // Get config for host
    let host_config = config_parser.get_host_config(&hostname);

    // Override with command line args
    let username = username.or(host_config.user).unwrap_or_else(|| {
        eprintln!("Error: Username not specified. Use user@host or configure in ~/.qssh/config");
        process::exit(1);
    });

    let port = if args.port != 22222 {
        args.port
    } else {
        host_config.port.unwrap_or(22222)
    };

    let host = if let Some(h) = host_config.hostname {
        format!("{}:{}", h, port)
    } else {
        format!("{}:{}", hostname, port)
    };
    
    // Parse port forwards
    let mut port_forwards = Vec::new();
    
    for forward in args.local {
        if let Some(pf) = parse_port_forward(&forward) {
            port_forwards.push(pf);
        } else {
            eprintln!("Error: Invalid port forward format: {}", forward);
            process::exit(1);
        }
    }
    
    // Determine PQ algorithm (Kyber removed due to vulnerabilities)
    let pq_algorithm = match args.pq_algo.as_str() {
        "sphincs" => PqAlgorithm::SphincsPlus,
        "falcon" | "falcon512" => PqAlgorithm::Falcon512,
        "falcon1024" => PqAlgorithm::Falcon1024,
        // Warn about deprecated/vulnerable algorithms
        "kyber" | "kyber512" | "kyber768" | "kyber1024" => {
            eprintln!("Warning: Kyber algorithms are vulnerable to KyberSlash attacks.");
            eprintln!("Using Falcon-512 instead for quantum security.");
            PqAlgorithm::Falcon512
        },
        _ => {
            eprintln!("Error: Unknown PQ algorithm: {}", args.pq_algo);
            eprintln!("Available algorithms: sphincs, falcon512, falcon1024");
            process::exit(1);
        }
    };
    
    // Handle password authentication
    let password = if args.use_password {
        // Prompt for password
        eprint!("Password: ");
        rpassword::read_password().ok()
    } else {
        None
    };

    // Determine transport type
    let quantum_native = if args.classical {
        false
    } else if args.quantum_native {
        true
    } else {
        true  // Default to quantum-native
    };

    // Create configuration
    let config = QsshConfig {
        server: host.clone(),
        username: username.clone(),
        password,
        port_forwards,
        use_qkd: args.qkd,
        qkd_endpoint: args.qkd_endpoint.clone(),
        qkd_cert_path: args.qkd_cert.clone(),
        qkd_key_path: args.qkd_key.clone(),
        qkd_ca_path: args.qkd_ca.clone(),
        pq_algorithm,
        key_rotation_interval: 3600, // 1 hour
        security_tier: SecurityTier::default(),
        quantum_native,
    };
    
    info!("Connecting to {} as {}...", host, username);
    info!("Using post-quantum algorithm: {:?}", pq_algorithm);
    if quantum_native {
        info!("Transport: Quantum-native (768-byte indistinguishable frames)");
    } else {
        info!("Transport: Classical (variable-size frames)");
    }
    
    if args.qkd {
        info!("QKD enabled");
        if let Some(endpoint) = args.qkd_endpoint {
            info!("QKD endpoint: {}", endpoint);
        }
    }
    
    // Create client and connect
    let mut client = QsshClient::new(config);
    
    match client.connect().await {
        Ok(()) => {
            info!("Connected successfully!");

            // Enable X11 forwarding if requested
            if args.x11 || args.trusted_x11 {
                match client.enable_x11(args.trusted_x11).await {
                    Ok(()) => {
                        info!("X11 forwarding enabled");
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to enable X11 forwarding: {}", e);
                    }
                }
            }

            // Execute command or start shell
            if let Some(command) = args.command {
                match client.exec(&command).await {
                    Ok(output) => {
                        println!("{}", output);
                    }
                    Err(e) => {
                        eprintln!("Command execution failed: {}", e);
                        process::exit(1);
                    }
                }
            } else {
                // Interactive shell
                match client.shell().await {
                    Ok(_) => {
                        info!("Shell session terminated normally");
                    }
                    Err(e) => {
                        eprintln!("Shell error: {}", e);
                        eprintln!("Error details: {:?}", e);
                    }
                }
            }
            
            // Disconnect
            if let Err(e) = client.disconnect().await {
                eprintln!("Error disconnecting: {}", e);
            }
        }
        Err(e) => {
            eprintln!("Connection failed: {}", e);
            process::exit(1);
        }
    }
}

fn parse_port_forward(spec: &str) -> Option<PortForward> {
    // Parse using PortForwardManager and convert to PortForward
    match PortForwardManager::parse_forward_spec(spec, "local") {
        Ok(ForwardType::Local { bind_addr, remote_host, remote_port }) => {
            Some(PortForward {
                local_port: bind_addr.port(),
                remote_host,
                remote_port,
            })
        }
        _ => None,
    }
}