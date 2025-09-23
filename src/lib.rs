//! QSSH - Quantum Secure Shell
//! 
//! A quantum-secure replacement for SSH using post-quantum cryptography
//! and optional QKD (Quantum Key Distribution) integration.

pub mod crypto;
pub mod transport;
#[cfg(feature = "qkd")]
pub mod qkd;
pub mod handshake;
pub mod client;
pub mod server;
pub mod config;
pub mod agent;
pub mod x11;
pub mod pty;
pub mod auth;
pub mod vault;
pub mod p2p;
pub mod shell_handler;
pub mod shell_handler_pty;
pub mod pty_async;
pub mod shell_handler_async;
pub mod pty_thread;
pub mod shell_handler_thread;
pub mod port_forward;

// Re-export port forwarding types
pub use port_forward::{PortForwardManager, ForwardType};
pub mod subsystems;
pub mod multiplex;
pub mod proxy;
pub mod known_hosts;
pub mod compression;
pub mod session;
pub mod certificate;
pub mod gssapi;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QsshError {
    #[error("Connection error: {0}")]
    Connection(String),
    
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    #[error("QKD error: {0}")]
    Qkd(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, QsshError>;

/// QSSH configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QsshConfig {
    /// Server endpoint (host:port)
    pub server: String,

    /// Username for authentication
    pub username: String,

    /// Password for authentication (optional)
    #[serde(skip_serializing)]
    pub password: Option<String>,

    /// Port forwarding rules
    pub port_forwards: Vec<PortForward>,

    /// Enable QKD for quantum key distribution
    pub use_qkd: bool,
    
    /// QKD endpoint URL (e.g., "https://192.168.0.4/api/v1/keys")
    pub qkd_endpoint: Option<String>,
    
    /// Path to QKD client certificate
    pub qkd_cert_path: Option<String>,
    
    /// Path to QKD client private key
    pub qkd_key_path: Option<String>,
    
    /// Path to QKD CA certificate
    pub qkd_ca_path: Option<String>,

    /// Post-quantum algorithm to use
    pub pq_algorithm: PqAlgorithm,

    /// Key rotation interval (seconds)
    pub key_rotation_interval: u64,

    /// Use quantum-native transport (indistinguishable frames)
    pub quantum_native: bool,
}

impl Default for QsshConfig {
    fn default() -> Self {
        Self {
            server: "localhost:22222".to_string(),
            username: "user".to_string(),
            password: None,
            port_forwards: Vec::new(),
            use_qkd: false,
            qkd_endpoint: None,
            qkd_cert_path: None,
            qkd_key_path: None,
            qkd_ca_path: None,
            pq_algorithm: PqAlgorithm::Falcon512,
            key_rotation_interval: 3600,
            quantum_native: true,  // Default to quantum-native transport
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForward {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PqAlgorithm {
    SphincsPlus,
    Kyber512,
    Kyber768,
    Kyber1024,
    Falcon512,
}

impl std::fmt::Display for PqAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqAlgorithm::SphincsPlus => write!(f, "SPHINCS+"),
            PqAlgorithm::Kyber512 => write!(f, "Kyber-512"),
            PqAlgorithm::Kyber768 => write!(f, "Kyber-768"),
            PqAlgorithm::Kyber1024 => write!(f, "Kyber-1024"),
            PqAlgorithm::Falcon512 => write!(f, "Falcon-512"),
        }
    }
}

/// Quantum capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumCapabilities {
    pub supports_qkd: bool,
    pub supports_sphincs: bool,
    pub supports_kyber: bool,
    pub supports_falcon: bool,
    pub qkd_endpoints: Vec<String>,
}

/// Re-exports for convenience
pub use client::QsshClient;
pub use server::QsshServer;