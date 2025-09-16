//! QSSH Agent - Post-quantum SSH agent daemon

use clap::Parser;
use qssh::agent::QsshAgent;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(name = "qssh-agent")]
#[clap(about = "QSSH Agent - Manages post-quantum SSH keys")]
struct Args {
    /// Socket path
    #[clap(short = 's', long)]
    socket: Option<String>,

    /// Kill existing agent
    #[clap(short = 'k', long)]
    kill: bool,

    /// Run in foreground
    #[clap(short = 'D', long)]
    debug: bool,

    /// Output shell commands to set up environment
    #[clap(short = 'c', long)]
    csh_style: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize logging
    if args.debug {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .init();
    }

    // Determine socket path
    let socket_path = args.socket.unwrap_or_else(|| {
        format!("/tmp/qssh-agent-{}/agent.sock", std::process::id())
    });

    let socket_path = PathBuf::from(&socket_path);

    if args.kill {
        // Kill existing agent
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).ok();
            println!("Agent killed");
        } else {
            eprintln!("No agent running");
        }
        return;
    }

    // Create agent
    let agent = QsshAgent::new(socket_path.clone());

    // Output environment setup commands
    if !args.debug {
        if args.csh_style {
            // C-shell style
            println!("setenv QSSH_AUTH_SOCK {};", socket_path.display());
            println!("echo Agent pid {};", std::process::id());
        } else {
            // Bourne shell style
            println!("QSSH_AUTH_SOCK={}; export QSSH_AUTH_SOCK;", socket_path.display());
            println!("echo Agent pid {};", std::process::id());
        }
    }

    // Fork to background unless debugging
    if !args.debug {
        use std::process::{Command, Stdio};

        // Re-execute self with debug flag to run in background
        let exe = std::env::current_exe().expect("Failed to get current exe");
        let mut cmd = Command::new(exe);
        cmd.arg("-D")
            .arg("-s")
            .arg(socket_path.to_str().unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        match cmd.spawn() {
            Ok(child) => {
                // Parent exits, child continues
                if !args.csh_style {
                    println!("echo Agent pid {};", child.id());
                }
                return;
            }
            Err(e) => {
                eprintln!("Failed to fork: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Run agent
    log::info!("Starting QSSH Agent on {:?}", socket_path);

    // Start periodic cleanup of expired keys
    let agent_clone = agent.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            agent_clone.cleanup_expired_keys().await;
        }
    });

    // Run the agent
    if let Err(e) = agent.start().await {
        eprintln!("Agent error: {}", e);
        std::process::exit(1);
    }
}