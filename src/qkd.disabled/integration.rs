//! Integration with existing qkd_client library

use crate::{QsshError, Result};
// Temporarily disabled - qkd_client module structure issue
// use qkd_client::qkd::client::QkdClient;
// use qkd_client::qkd::etsi_api::{ETSIClient, Side, QKDKey};

/// QSSH QKD Integration
/// 
/// This wraps the existing qkd_client to provide QKD functionality
/// for QSSH's quantum-secure key exchange
pub struct QsshQkdIntegration {
    client: QkdClient,
    etsi_client: Option<ETSIClient>,
}

impl QsshQkdIntegration {
    /// Create new QKD integration
    pub fn new(endpoint: &str, is_alice: bool) -> Result<Self> {
        // Use the existing QkdClient
        let client = QkdClient::new(endpoint, None)
            .map_err(|e| QsshError::Qkd(format!("Failed to create QKD client: {}", e)))?;
        
        // Optionally create ETSI client for advanced features
        let etsi_client = if std::env::var("QSSH_USE_ETSI_API").is_ok() {
            let side = if is_alice { Side::Alice } else { Side::Bob };
            // Use certificate from environment or default location
            let cert_path = std::env::var("QSSH_QKD_CERT")
                .unwrap_or_else(|_| "/etc/qssh/qkd-cert.pem".to_string());
            let root_cert_path = std::env::var("QSSH_QKD_ROOT_CERT").ok();
            
            match qkd_client::qkd::etsi_api::ETSIClient::new(
                qkd_client::qkd::etsi_api::DeviceType::Simulated,
                side,
                std::path::Path::new(&cert_path),
                root_cert_path.as_deref().map(std::path::Path::new),
                None,
            ) {
                Ok(client) => Some(client),
                Err(e) => {
                    log::warn!("Failed to create ETSI client: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        Ok(Self {
            client,
            etsi_client,
        })
    }
    
    /// Get quantum key for session
    pub async fn get_session_key(&self, session_id: &str) -> Result<Vec<u8>> {
        // Try ETSI API first if available
        if let Some(etsi) = &self.etsi_client {
            match etsi.get_key_alice(32, "qssh-peer", Some(session_id)).await {
                Ok(key) => return Ok(key.key_bytes),
                Err(e) => {
                    log::warn!("ETSI API failed: {}, falling back to standard client", e);
                }
            }
        }
        
        // Fall back to standard client
        let key_buffer = self.client.get_key(session_id)
            .map_err(|e| QsshError::Qkd(format!("Failed to get QKD key: {}", e)))?;
        
        Ok(key_buffer.data.clone())
    }
    
    /// Mix QKD key with post-quantum key exchange
    pub fn mix_keys(&self, qkd_key: &[u8], pq_shared_secret: &[u8]) -> Vec<u8> {
        use sha3::{Sha3_256, Digest};
        
        // XOR the keys for information-theoretic security
        let mut mixed = vec![0u8; 32];
        for i in 0..32 {
            mixed[i] = qkd_key[i % qkd_key.len()] ^ pq_shared_secret[i % pq_shared_secret.len()];
        }
        
        // Additional mixing with SHA3
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-KEY-MIX");
        hasher.update(&mixed);
        hasher.update(qkd_key);
        hasher.update(pq_shared_secret);
        
        hasher.finalize().to_vec()
    }
}