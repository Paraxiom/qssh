//! QSCP - Quantum-secure file copy (using SFTP protocol)

use clap::Parser;
use qssh::{QsshConfig, PqAlgorithm, QsshClient, security_tiers::SecurityTier};
use qssh::sftp_client::SftpClient;
use std::path::Path;
use tokio::fs;

#[derive(Parser, Debug)]
#[clap(name = "qscp")]
#[clap(about = "Quantum-Secure Copy - Transfer files with post-quantum security")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
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
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .target(env_logger::Target::Stderr)
            .init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
            .target(env_logger::Target::Stderr)
            .init();
    }

    // Parse source and destination
    let result = if args.destination.contains(':') {
        upload_files(&args).await
    } else if args.source.iter().any(|s| s.contains(':')) {
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

fn make_config(host: &str, port: u16, username: String, qkd: bool) -> QsshConfig {
    QsshConfig {
        server: format!("{}:{}", host, port),
        username,
        password: None,
        port_forwards: vec![],
        use_qkd: qkd,
        qkd_endpoint: None,
        qkd_cert_path: None,
        qkd_key_path: None,
        qkd_ca_path: None,
        pq_algorithm: PqAlgorithm::Falcon512,
        kex_algorithm: qssh::KexAlgorithm::default(),
        key_rotation_interval: 3600,
        security_tier: SecurityTier::default(),
        quantum_native: true,
    }
}

async fn upload_files(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let (remote, remote_path) = parse_remote(&args.destination)?;
    let (username, host) = parse_user_host(&remote)?;

    let config = make_config(&host, args.port, username, args.qkd);
    let mut client = QsshClient::new(config);
    client.connect().await?;

    // Open SFTP session
    let transport = client.transport()
        .ok_or("Not connected")?
        .clone();
    let mut sftp = SftpClient::connect(transport).await?;

    for source in &args.source {
        let path = Path::new(source);
        if path.is_file() {
            upload_file(&mut sftp, path, &remote_path, args.progress).await?;
        } else if path.is_dir() && args.recursive {
            upload_directory(&mut sftp, &client, path, &remote_path, args.progress).await?;
        } else if path.is_dir() {
            eprintln!("Skipping {}: is a directory (use -r for recursive)", source);
        } else {
            eprintln!("Skipping {}: not a regular file", source);
        }
    }

    sftp.close().await?;
    client.disconnect().await?;
    Ok(())
}

async fn download_files(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let remote_source = args.source.iter()
        .find(|s| s.contains(':'))
        .ok_or("No remote source found")?;

    let (remote, remote_path) = parse_remote(remote_source)?;
    let (username, host) = parse_user_host(&remote)?;

    let config = make_config(&host, args.port, username, args.qkd);
    let mut client = QsshClient::new(config);
    client.connect().await?;

    let transport = client.transport()
        .ok_or("Not connected")?
        .clone();
    let mut sftp = SftpClient::connect(transport).await?;

    download_file(&mut sftp, &remote_path, &args.destination, args.progress).await?;

    sftp.close().await?;
    client.disconnect().await?;
    Ok(())
}

async fn upload_file(
    sftp: &mut SftpClient,
    local_path: &Path,
    remote_path: &str,
    show_progress: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(local_path).await?;
    let file_size = metadata.len();

    if show_progress {
        eprintln!("Uploading {} ({} bytes)", local_path.display(), file_size);
    }

    let contents = fs::read(local_path).await?;

    // If remote_path ends with /, append the filename
    let dest = if remote_path.ends_with('/') {
        let name = local_path.file_name()
            .ok_or("No filename")?
            .to_string_lossy();
        format!("{}{}", remote_path, name)
    } else {
        remote_path.to_string()
    };

    sftp.upload(&contents, &dest).await?;

    if show_progress {
        eprintln!("Upload complete: {} -> {} ({} bytes)", local_path.display(), dest, file_size);
    }

    Ok(())
}

async fn download_file(
    sftp: &mut SftpClient,
    remote_path: &str,
    local_path: &str,
    show_progress: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if show_progress {
        eprintln!("Downloading {} to {}", remote_path, local_path);
    }

    let contents = sftp.download(remote_path).await?;
    fs::write(local_path, &contents).await?;

    if show_progress {
        eprintln!("Download complete: {} ({} bytes)", local_path, contents.len());
    }

    Ok(())
}

async fn upload_directory(
    sftp: &mut SftpClient,
    client: &QsshClient,
    local_path: &Path,
    remote_path: &str,
    show_progress: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create remote directory via exec (SFTP mkdir not yet wired)
    client.exec(&format!("mkdir -p {}", remote_path)).await?;

    let mut entries = fs::read_dir(local_path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let name = entry.file_name();
        let remote_file = format!("{}/{}", remote_path, name.to_string_lossy());

        if path.is_file() {
            upload_file(sftp, &path, &remote_file, show_progress).await?;
        } else if path.is_dir() {
            Box::pin(upload_directory(sftp, client, &path, &remote_file, show_progress)).await?;
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
