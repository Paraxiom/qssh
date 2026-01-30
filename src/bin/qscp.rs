//! QSCP - Quantum-secure file copy

use clap::Parser;
use qssh::{QsshConfig, PqAlgorithm, QsshClient, security_tiers::SecurityTier};
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Parser, Debug)]
#[clap(name = "qscp")]
#[clap(about = "Quantum-Secure Copy - Transfer files with post-quantum security")]
#[clap(version = "0.1.0")]
struct Args {
    /// Source file(s)
    source: Vec<String>,
    
    /// Destination
    destination: String,
    
    /// Port to connect to
    #[clap(short = 'P', long, default_value = "22222")]
    port: u16,
    
    /// Enable QKD
    #[clap(long)]
    qkd: bool,
    
    /// Recursive copy
    #[clap(short, long)]
    recursive: bool,
    
    /// Preserve attributes
    #[clap(short, long)]
    preserve: bool,
    
    /// Verbose output
    #[clap(short, long)]
    verbose: bool,
    
    /// Show progress
    #[clap(long)]
    progress: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    
    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }
    
    // Parse source and destination
    let result = if args.destination.contains(':') {
        // Upload to remote
        upload_files(&args).await
    } else if args.source.iter().any(|s| s.contains(':')) {
        // Download from remote
        download_files(&args).await
    } else {
        eprintln!("Error: Either source or destination must be remote (user@host:path)");
        std::process::exit(1);
    };
    
    if let Err(e) = result {
        eprintln!("Transfer failed: {}", e);
        std::process::exit(1);
    }
}

async fn upload_files(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Parse destination
    let (remote, remote_path) = parse_remote(&args.destination)?;
    let (username, host) = parse_user_host(&remote)?;
    
    // Create client
    let config = QsshConfig {
        server: format!("{}:{}", host, args.port),
        username,
        password: None,
        port_forwards: vec![],
        use_qkd: args.qkd,
        qkd_endpoint: None,
        qkd_cert_path: None,
        qkd_key_path: None,
        qkd_ca_path: None,
        pq_algorithm: PqAlgorithm::Falcon512,
        key_rotation_interval: 3600,
        security_tier: SecurityTier::default(),
        quantum_native: true,
    };

    let mut client = QsshClient::new(config);
    client.connect().await?;

    // Upload each file
    for source in &args.source {
        let path = Path::new(source);
        if path.is_file() {
            upload_file(&client, path, &remote_path, args.progress).await?;
        } else if path.is_dir() && args.recursive {
            upload_directory(&client, path, &remote_path, args.progress).await?;
        } else {
            eprintln!("Skipping {}: not a regular file", source);
        }
    }
    
    client.disconnect().await?;
    Ok(())
}

async fn download_files(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Find remote source
    let remote_source = args.source.iter()
        .find(|s| s.contains(':'))
        .ok_or("No remote source found")?;
    
    let (remote, remote_path) = parse_remote(remote_source)?;
    let (username, host) = parse_user_host(&remote)?;
    
    // Create client
    let config = QsshConfig {
        server: format!("{}:{}", host, args.port),
        username,
        password: None,
        port_forwards: vec![],
        use_qkd: args.qkd,
        qkd_endpoint: None,
        qkd_cert_path: None,
        qkd_key_path: None,
        qkd_ca_path: None,
        pq_algorithm: PqAlgorithm::Falcon512,
        key_rotation_interval: 3600,
        security_tier: SecurityTier::default(),
        quantum_native: true,
    };

    let mut client = QsshClient::new(config);
    client.connect().await?;

    // Download file
    download_file(&client, &remote_path, &args.destination, args.progress).await?;
    
    client.disconnect().await?;
    Ok(())
}

async fn upload_file(
    client: &QsshClient,
    local_path: &Path,
    remote_path: &str,
    show_progress: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(local_path).await?;
    let file_size = metadata.len();
    
    if show_progress {
        println!("Uploading {} ({} bytes)", local_path.display(), file_size);
    }
    
    // Read file
    let contents = fs::read(local_path).await?;
    
    // Send via exec (in production, use SFTP protocol)
    use base64::Engine;
    let remote_cmd = format!(
        "cat > {} << 'EOF'\n{}\nEOF",
        remote_path,
        base64::engine::general_purpose::STANDARD.encode(&contents)
    );
    
    client.exec(&remote_cmd).await?;
    
    if show_progress {
        println!("Upload complete: {}", local_path.display());
    }
    
    Ok(())
}

async fn download_file(
    client: &QsshClient,
    remote_path: &str,
    local_path: &str,
    show_progress: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if show_progress {
        println!("Downloading {} to {}", remote_path, local_path);
    }
    
    // Download via exec (in production, use SFTP protocol)
    let output = client.exec(&format!("base64 {}", remote_path)).await?;
    use base64::Engine;
    let contents = base64::engine::general_purpose::STANDARD.decode(output.trim())?;
    
    // Write file
    fs::write(local_path, contents).await?;
    
    if show_progress {
        println!("Download complete: {}", local_path);
    }
    
    Ok(())
}

async fn upload_directory(
    client: &QsshClient,
    local_path: &Path,
    remote_path: &str,
    show_progress: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create remote directory
    client.exec(&format!("mkdir -p {}", remote_path)).await?;
    
    // Walk directory
    let mut entries = fs::read_dir(local_path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let name = entry.file_name();
        let remote_file = format!("{}/{}", remote_path, name.to_string_lossy());
        
        if path.is_file() {
            upload_file(client, &path, &remote_file, show_progress).await?;
        } else if path.is_dir() {
            Box::pin(upload_directory(client, &path, &remote_file, show_progress)).await?;
        }
    }
    
    Ok(())
}

fn parse_remote(spec: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = spec.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err("Invalid remote specification".into());
    }
    
    Ok((parts[1].to_string(), parts[0].to_string()))
}

fn parse_user_host(remote: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = remote.split('@').collect();
    if parts.len() != 2 {
        return Err("Invalid user@host format".into());
    }
    
    Ok((parts[0].to_string(), parts[1].to_string()))
}