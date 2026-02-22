//! QSSH Signing Service — Isolated key-holding daemon
//!
//! Runs as a separate process with minimal attack surface.
//! Holds decrypted keys in mlock'd memory, exposes a Unix socket API
//! for sign(key_id, message) → signature.
//!
//! Usage:
//!   qssh-sign                    # Start with defaults
//!   qssh-sign --socket /path     # Custom socket path
//!   qssh-sign --rate-limit 30    # Max 30 signs/minute per key
//!   qssh-sign --foreground       # Run in foreground (no daemonize)

use clap::Parser;
use qssh::vault::SigningService;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(name = "qssh-sign")]
#[clap(about = "QSSH Signing Service — Isolated key enclave with Unix socket API")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Args {
    /// Unix socket path for the signing API
    #[clap(short = 's', long, default_value = "~/.qssh/sign.sock")]
    socket: String,

    /// Audit log path (JSONL, hash-chained)
    #[clap(short = 'a', long, default_value = "~/.qssh/audit.jsonl")]
    audit: String,

    /// Maximum signing operations per minute per key
    #[clap(short = 'r', long, default_value = "60")]
    rate_limit: u32,

    /// Run in foreground (don't daemonize)
    #[clap(short = 'f', long)]
    foreground: bool,

    /// Verbose output
    #[clap(short = 'v', long)]
    verbose: bool,

    /// Kill existing signing service
    #[clap(short = 'k', long)]
    kill: bool,
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

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .target(env_logger::Target::Stderr)
            .init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .target(env_logger::Target::Stderr)
            .init();
    }

    let socket_path = expand_tilde(&args.socket);
    let audit_path = expand_tilde(&args.audit);

    if args.kill {
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).ok();
            eprintln!("Signing service stopped (socket removed)");
        } else {
            eprintln!("No signing service running at {:?}", socket_path);
        }
        return;
    }

    // Ensure ~/.qssh/ directory exists
    if let Some(parent) = socket_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("Failed to create directory {:?}: {}", parent, e);
            std::process::exit(1);
        }
    }

    eprintln!("QSSH Signing Service v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("Socket: {:?}", socket_path);
    eprintln!("Audit:  {:?}", audit_path);
    eprintln!("Rate:   {} signs/min/key", args.rate_limit);

    if !args.foreground {
        // Daemonize: re-exec with --foreground
        use std::process::{Command, Stdio};
        let exe = std::env::current_exe().expect("Failed to get current exe");
        let mut cmd = Command::new(exe);
        cmd.arg("--foreground")
           .arg("--socket").arg(socket_path.to_str().unwrap())
           .arg("--audit").arg(audit_path.to_str().unwrap())
           .arg("--rate-limit").arg(args.rate_limit.to_string());
        if args.verbose {
            cmd.arg("--verbose");
        }
        cmd.stdin(Stdio::null())
           .stdout(Stdio::null())
           .stderr(Stdio::null());

        match cmd.spawn() {
            Ok(child) => {
                eprintln!("Signing service started (pid {})", child.id());
                return;
            }
            Err(e) => {
                eprintln!("Failed to daemonize: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Run the signing service
    let service = SigningService::new(socket_path, audit_path, args.rate_limit);

    if let Err(e) = service.run().await {
        log::error!("Signing service error: {}", e);
        std::process::exit(1);
    }
}
