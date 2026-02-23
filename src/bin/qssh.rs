//! QSSH Client - Quantum-secure SSH replacement

use clap::Parser;
use qssh::{QsshConfig, PqAlgorithm, QsshClient, ReconnectConfig, security_tiers::SecurityTier};
use qssh::config::ConfigParser;
use qssh::port_forward::PortForwardManager;
use qssh::multiplex::{ControlMaster, ControlClient};
use qssh::proxy::{ProxyConnection, ProxyConfig, ProxyType};
use log::info;
use std::process;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[clap(name = "qssh")]
#[clap(about = "Quantum-Secure Shell - Connect to remote systems with post-quantum security")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
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

    /// Dynamic port forwarding / SOCKS5 proxy (e.g., 1080)
    #[clap(short = 'D', long)]
    dynamic: Vec<String>,
    
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

    /// Enable agent forwarding (forwards QSSH_AUTH_SOCK to remote)
    #[clap(short = 'A', long = "agent-forward")]
    agent_forward: bool,

    /// Verbose output
    #[clap(short, long)]
    verbose: bool,

    /// Use quantum-native transport (768-byte indistinguishable frames)
    #[clap(long)]
    quantum_native: bool,

    /// Use classical transport (for compatibility)
    #[clap(long)]
    classical: bool,

    /// Auto-reconnect on disconnect (exponential backoff)
    #[clap(long)]
    persistent: bool,

    /// Maximum reconnection attempts (0 = infinite, default 10)
    #[clap(long, default_value = "10")]
    max_retries: u32,

    /// Control socket path for connection multiplexing (like ssh -S)
    /// If a master is already running, new sessions reuse its connection.
    /// Otherwise, this process becomes the master.
    #[clap(short = 'S', long = "ctl-path")]
    ctl_path: Option<String>,

    /// ProxyJump through intermediate host (e.g., user@jumphost or user@jump1,jump2)
    #[clap(short = 'J', long = "proxy-jump")]
    jump: Option<String>,
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
    
    // Parse local forward specs (-L)
    let mut local_forwards = Vec::new();
    for spec in &args.local {
        match PortForwardManager::parse_forward_spec(spec, "local") {
            Ok(fwd) => local_forwards.push(fwd),
            Err(e) => {
                eprintln!("Error: Invalid local forward spec '{}': {}", spec, e);
                process::exit(1);
            }
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
        port_forwards: Vec::new(), // -L forwards handled via PortForwardManager below
        use_qkd: args.qkd,
        qkd_endpoint: args.qkd_endpoint.clone(),
        qkd_cert_path: args.qkd_cert.clone(),
        qkd_key_path: args.qkd_key.clone(),
        qkd_ca_path: args.qkd_ca.clone(),
        pq_algorithm,
        kex_algorithm: qssh::KexAlgorithm::default(),
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
    
    // Parse remote forward specs
    let mut remote_forwards = Vec::new();
    for spec in &args.remote {
        match PortForwardManager::parse_forward_spec(spec, "remote") {
            Ok(fwd) => remote_forwards.push(fwd),
            Err(e) => {
                eprintln!("Error: Invalid remote forward spec '{}': {}", spec, e);
                process::exit(1);
            }
        }
    }

    // Parse dynamic forward specs (-D SOCKS5)
    let mut dynamic_forwards = Vec::new();
    for spec in &args.dynamic {
        match PortForwardManager::parse_forward_spec(spec, "dynamic") {
            Ok(fwd) => dynamic_forwards.push(fwd),
            Err(e) => {
                eprintln!("Error: Invalid dynamic forward spec '{}': {}", spec, e);
                process::exit(1);
            }
        }
    }

    let has_remote_forwards = !remote_forwards.is_empty();
    let has_forwards = !local_forwards.is_empty() || !remote_forwards.is_empty() || !dynamic_forwards.is_empty();

    // ──── Multiplexing: -S <socket_path> ────
    // If a control master is already running, connect as a client (reuse existing PQ tunnel).
    // Otherwise fall through to normal connect and optionally become the master.
    if let Some(ref ctl_path_str) = args.ctl_path {
        let ctl_path = expand_tilde(ctl_path_str);
        if ControlMaster::check_master(&ctl_path).await {
            info!("Reusing existing connection via control master at {:?}", ctl_path);

            let mut mux_client = ControlClient::new(ctl_path);
            match mux_client.connect().await {
                Ok(()) => {
                    match mux_client.new_session(args.command.clone()).await {
                        Ok(session_id) => {
                            info!("Multiplexed session {} created", session_id);
                            // For exec mode: read output from session
                            // For shell mode: the session runs in the master, we just wait
                            eprintln!("Session {} active on existing connection. Press Ctrl+C to close.", session_id);
                            tokio::signal::ctrl_c().await.ok();
                            let _ = mux_client.close_session(session_id).await;
                        }
                        Err(e) => {
                            eprintln!("Failed to create multiplexed session: {}", e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to connect to control master: {}", e);
                    process::exit(1);
                }
            }
            return;
        }
    }

    // Build reconnect config
    let reconnect_config = if args.persistent {
        Some(ReconnectConfig {
            max_attempts: args.max_retries,
            ..ReconnectConfig::default()
        })
    } else {
        None
    };

    // Outer reconnect loop — re-entered when --persistent and the session drops
    let mut session_count = 0u32;
    loop {
        session_count += 1;

        // Create client and connect
        let mut client = QsshClient::new(config.clone());

        let connect_result = if let Some(ref jump_spec) = args.jump {
            // ProxyJump: connect through intermediate host
            info!("Using ProxyJump through: {}", jump_spec);
            let proxy_config = ProxyConfig {
                proxy_type: ProxyType::Jump,
                target: jump_spec.clone(),
                options: Vec::new(),
            };
            let proxy = ProxyConnection::new(proxy_config, config.clone());

            // Extract host and port from the server address
            let parts: Vec<&str> = config.server.split(':').collect();
            let proxy_host = parts[0];
            let proxy_port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(22222);

            match proxy.connect(proxy_host, proxy_port).await {
                Ok(stream) => client.connect_via_stream(stream).await,
                Err(e) => Err(e),
            }
        } else if let Some(ref rc) = reconnect_config {
            client.connect_with_retry(rc).await
        } else {
            client.connect().await
        };

        match connect_result {
            Ok(()) => {
                if session_count > 1 {
                    eprintln!("Reconnected (session #{})", session_count);
                }
                info!("Connected successfully!");

                // Start control master if -S was requested and no master existed
                if let Some(ref ctl_path_str) = args.ctl_path {
                    if let Some(transport) = client.transport() {
                        let ctl_path = expand_tilde(ctl_path_str);
                        let master = ControlMaster::new(ctl_path.clone(), Arc::new(transport.clone()));
                        info!("Starting control master at {:?}", ctl_path);
                        tokio::spawn(async move {
                            if let Err(e) = master.start().await {
                                log::error!("Control master error: {}", e);
                            }
                        });
                    }
                }

                // Set up port forwards (-L and -R) via PortForwardManager
                if has_forwards {
                    if let Some(transport) = client.transport() {
                        let transport = Arc::new(transport.clone());
                        let mut pfm = PortForwardManager::new(transport);
                        for fwd in &local_forwards {
                            pfm.add_forward(fwd.clone());
                        }
                        for fwd in &remote_forwards {
                            pfm.add_forward(fwd.clone());
                        }
                        for fwd in &dynamic_forwards {
                            pfm.add_forward(fwd.clone());
                        }
                        match pfm.start_all().await {
                            Ok(()) => {
                                info!("Port forwards established");
                                client.set_remote_forward_state(
                                    pfm.remote_registry(),
                                    pfm.channel_router(),
                                );
                            }
                            Err(e) => {
                                eprintln!("Error setting up port forwards: {}", e);
                                if reconnect_config.is_none() { process::exit(1); }
                            }
                        }
                    }
                }

                // Enable X11 forwarding if requested
                if args.x11 || args.trusted_x11 {
                    match client.enable_x11(args.trusted_x11).await {
                        Ok(()) => info!("X11 forwarding enabled"),
                        Err(e) => eprintln!("Warning: Failed to enable X11 forwarding: {}", e),
                    }
                }

                // Enable agent forwarding if requested
                if args.agent_forward {
                    match client.enable_agent_forwarding().await {
                        Ok(()) => info!("Agent forwarding enabled"),
                        Err(e) => eprintln!("Warning: Failed to enable agent forwarding: {}", e),
                    }
                }

                // Execute command or start shell
                if let Some(ref command) = args.command {
                    match client.exec_with_status(command).await {
                        Ok((output, exit_code)) => {
                            print!("{}", output);
                            if exit_code != 0 && reconnect_config.is_none() && !has_remote_forwards && !has_forwards {
                                process::exit(exit_code as i32);
                            }
                        }
                        Err(e) => {
                            eprintln!("Command execution failed: {}", e);
                            if reconnect_config.is_none() { process::exit(1); }
                        }
                    }

                    // If forwards are active, keep connection alive
                    if has_remote_forwards || has_forwards {
                        info!("Exec completed, keeping connection alive for port forwards");
                        info!("Press Ctrl+C to disconnect");
                        if let Err(e) = client.run_forward_loop().await {
                            log::debug!("Forward loop ended: {}", e);
                        }
                    }
                } else {
                    // Interactive shell
                    match client.shell().await {
                        Ok(_) => info!("Shell session terminated normally"),
                        Err(e) => {
                            eprintln!("Shell error: {}", e);
                            eprintln!("Error details: {:?}", e);
                        }
                    }
                }

                // Disconnect
                let _ = client.disconnect().await;

                // Clean up control master socket on disconnect
                if let Some(ref ctl_path_str) = args.ctl_path {
                    let ctl_path = expand_tilde(ctl_path_str);
                    let _ = std::fs::remove_file(&ctl_path);
                }
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
                if reconnect_config.is_none() { process::exit(1); }
                // --persistent: the connect_with_retry already exhausted retries
                process::exit(1);
            }
        }

        // If not persistent, exit after one session
        if reconnect_config.is_none() {
            break;
        }

        // Persistent mode: brief pause then reconnect
        eprintln!("Session ended. Reconnecting in 1s...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(format!("{}{}", home, &path[1..]));
        }
    }
    PathBuf::from(path)
}

