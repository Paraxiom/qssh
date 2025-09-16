//! QKD (Quantum Key Distribution) integration module
//!
//! This module provides integration with quantum key distribution systems
//! when the `qkd` feature is enabled.

use crate::{Result, QsshError};
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};

pub mod bb84;
pub mod etsi_client;
pub use bb84::{BB84Protocol, E91Protocol};
pub use etsi_client::{EtsiQkdClient, create_etsi_client};

/// QKD Provider Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QkdProvider {
    /// BB84 protocol simulation
    BB84,
    /// E91 (Ekert) protocol simulation
    E91,
    /// Hardware QKD device
    Hardware { device_path: String },
    /// Network QKD service
    Network { endpoint: String },
}

/// QKD client for retrieving quantum keys
pub struct QkdClient {
    provider: QkdProvider,
    connection: Arc<Mutex<QkdConnection>>,
    config: QkdConfig,
}

/// Actual QKD connection implementation
struct QkdConnection {
    provider: QkdProvider,
    bb84: Option<BB84Protocol>,
    e91: Option<E91Protocol>,
    key_cache: Vec<Vec<u8>>,
    keys_generated: usize,
    error_count: usize,
    config: QkdConfig,
}

impl QkdConnection {
    fn new(provider: QkdProvider, config: QkdConfig) -> Self {
        let (bb84, e91) = match &provider {
            QkdProvider::BB84 => (Some(BB84Protocol::new()), None),
            QkdProvider::E91 => (None, Some(E91Protocol::new())),
            _ => (None, None),
        };

        Self {
            provider,
            bb84,
            e91,
            key_cache: Vec::new(),
            keys_generated: 0,
            error_count: 0,
            config,
        }
    }

    async fn generate_key(&mut self, size_bits: usize) -> Result<Vec<u8>> {
        match &self.provider {
            QkdProvider::BB84 => {
                if let Some(protocol) = &self.bb84 {
                    let key = protocol.generate_key(size_bits).await?;
                    self.keys_generated += 1;
                    Ok(key)
                } else {
                    Err(QsshError::Qkd("BB84 protocol not initialized".into()))
                }
            }
            QkdProvider::E91 => {
                // E91 implementation
                if let Some(protocol) = &self.e91 {
                    // Generate using entangled pairs
                    let (alice_measurements, bob_measurements) =
                        protocol.generate_entangled_pairs(size_bits * 2);

                    // Verify Bell inequality for security
                    let measurements: Vec<(f64, f64)> = alice_measurements
                        .iter()
                        .zip(bob_measurements.iter())
                        .map(|(&a, &b)| (a, b))
                        .collect();

                    if !protocol.verify_bell_inequality(&measurements) {
                        self.error_count += 1;
                        return Err(QsshError::Qkd("Bell inequality verification failed".into()));
                    }

                    // Convert measurements to key bits
                    let mut key = Vec::new();
                    for chunk in measurements.chunks(8) {
                        let mut byte = 0u8;
                        for (i, &(a, _)) in chunk.iter().enumerate() {
                            if a > std::f64::consts::PI / 2.0 {
                                byte |= 1 << i;
                            }
                        }
                        key.push(byte);
                    }

                    self.keys_generated += 1;
                    Ok(key[..size_bits / 8].to_vec())
                } else {
                    Err(QsshError::Qkd("E91 protocol not initialized".into()))
                }
            }
            QkdProvider::Hardware { device_path } => {
                // Interface with actual QKD hardware
                log::info!("Requesting key from hardware device: {}", device_path);

                // In production, this would interface with actual QKD hardware
                // For now, return a secure random key as placeholder
                let mut key = vec![0u8; size_bits / 8];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut key);

                self.keys_generated += 1;
                Ok(key)
            }
            QkdProvider::Network { endpoint } => {
                // Connect to network QKD service with certificate authentication
                log::info!("Requesting key from network QKD service: {}", endpoint);

                // Create ETSI client if not already created
                let etsi_client = create_etsi_client(&self.config)?;
                
                // Request key from real QKD device
                let key = etsi_client.get_key(size_bits / 8).await?;
                
                self.keys_generated += 1;
                Ok(key)
            }
        }
    }
}

impl QkdClient {
    /// Create a new QKD client
    pub fn new(endpoint: String, config: Option<QkdConfig>) -> Result<Self> {
        log::info!("Initializing QKD client for endpoint: {}", endpoint);

        // Determine provider type from endpoint
        let provider = if endpoint.starts_with("qkd://") || endpoint.starts_with("https://") {
            QkdProvider::Network { endpoint: endpoint.clone() }
        } else if endpoint.starts_with("bb84://") {
            QkdProvider::BB84
        } else if endpoint.starts_with("e91://") {
            QkdProvider::E91
        } else if endpoint.starts_with("/dev/") {
            QkdProvider::Hardware { device_path: endpoint }
        } else if endpoint.is_empty() {
            // Default to BB84 simulation
            QkdProvider::BB84
        } else {
            // Assume it's a network endpoint
            QkdProvider::Network { endpoint: endpoint.clone() }
        };

        let cfg = config.unwrap_or_default();
        let connection = QkdConnection::new(provider.clone(), cfg.clone());

        Ok(Self {
            provider,
            connection: Arc::new(Mutex::new(connection)),
            config: cfg,
        })
    }

    /// Get a quantum key of specified size (in bits)
    pub async fn get_key(&self, size_bits: usize) -> Result<Vec<u8>> {
        log::debug!("Requesting {} bit key from QKD system", size_bits);

        if size_bits % 8 != 0 {
            return Err(QsshError::Qkd("Key size must be multiple of 8 bits".into()));
        }

        let mut conn = self.connection.lock().await;

        // Check cache first
        if !conn.key_cache.is_empty() {
            for i in 0..conn.key_cache.len() {
                if conn.key_cache[i].len() * 8 >= size_bits {
                    let key = conn.key_cache.remove(i);
                    return Ok(key[..size_bits / 8].to_vec());
                }
            }
        }

        // Generate new key
        conn.generate_key(size_bits).await
    }

    /// Check if QKD system is available
    pub async fn is_available(&self) -> bool {
        match &self.provider {
            QkdProvider::BB84 | QkdProvider::E91 => true,
            QkdProvider::Hardware { device_path } => {
                // Check if device exists
                std::path::Path::new(device_path).exists()
            }
            QkdProvider::Network { endpoint } => {
                // Try to ping the endpoint
                log::debug!("Checking QKD network availability: {}", endpoint);
                false // Would need actual network check
            }
        }
    }

    /// Get QKD statistics
    pub async fn get_stats(&self) -> QkdStats {
        let conn = self.connection.lock().await;
        QkdStats {
            provider_type: format!("{:?}", self.provider),
            keys_generated: conn.keys_generated,
            error_count: conn.error_count,
            cached_keys: conn.key_cache.len(),
        }
    }
}

/// QKD configuration
#[derive(Clone)]
pub struct QkdConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub ca_path: Option<String>,
    pub timeout_ms: u64,
    pub cache_size: usize,
    pub min_entropy: f64,
}

impl Default for QkdConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            ca_path: None,
            timeout_ms: 5000,
            cache_size: 10,
            min_entropy: 0.9,
        }
    }
}

/// QKD session for managing key lifecycle
pub struct QkdSession {
    client: Arc<QkdClient>,
    session_id: String,
    keys_used: usize,
    total_bits: usize,
}

impl QkdSession {
    /// Create a new QKD session
    pub fn new(client: Arc<QkdClient>) -> Self {
        use rand::{thread_rng, Rng};
        let session_id = format!("{:016x}", thread_rng().gen::<u64>());

        Self {
            client,
            session_id,
            keys_used: 0,
            total_bits: 0,
        }
    }

    /// Get next key from QKD system
    pub async fn get_next_key(&mut self, size_bits: usize) -> Result<Vec<u8>> {
        let key = self.client.get_key(size_bits).await?;
        self.keys_used += 1;
        self.total_bits += size_bits;

        log::info!(
            "QKD Session {} - Key #{} retrieved ({} bits)",
            self.session_id, self.keys_used, size_bits
        );

        Ok(key)
    }

    /// Get session statistics
    pub fn get_stats(&self) -> (String, usize, usize) {
        (self.session_id.clone(), self.keys_used, self.total_bits)
    }
}

/// QKD Statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QkdStats {
    pub provider_type: String,
    pub keys_generated: usize,
    pub error_count: usize,
    pub cached_keys: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_qkd_client_bb84() {
        let client = QkdClient::new("bb84://simulator".to_string(), None).unwrap();
        assert!(client.is_available().await);

        // Get a 256-bit key
        let key = client.get_key(256).await.unwrap();
        assert_eq!(key.len(), 32); // 256 bits = 32 bytes
    }

    #[tokio::test]
    async fn test_qkd_client_e91() {
        let client = QkdClient::new("e91://simulator".to_string(), None).unwrap();
        assert!(client.is_available().await);

        // Get a 128-bit key
        let key = client.get_key(128).await.unwrap();
        assert_eq!(key.len(), 16); // 128 bits = 16 bytes
    }

    #[tokio::test]
    async fn test_qkd_session() {
        let client = Arc::new(QkdClient::new("bb84://simulator".to_string(), None).unwrap());
        let mut session = QkdSession::new(client);

        // Get multiple keys
        let key1 = session.get_next_key(128).await.unwrap();
        let key2 = session.get_next_key(256).await.unwrap();

        assert_eq!(key1.len(), 16);
        assert_eq!(key2.len(), 32);

        let (_, keys_used, total_bits) = session.get_stats();
        assert_eq!(keys_used, 2);
        assert_eq!(total_bits, 384);
    }
}