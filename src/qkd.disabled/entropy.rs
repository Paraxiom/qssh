//! Quantum entropy sources for QSSH

use crate::{QsshError, Result};
use reqwest::Client;
use std::time::Duration;

/// Quantum entropy provider supporting multiple sources
pub struct QuantumEntropyProvider {
    kirq_endpoint: Option<String>,
    crypto4a_endpoint: Option<String>,
    qkd_available: bool,
    client: Client,
}

impl QuantumEntropyProvider {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| QsshError::Qkd(format!("Failed to create HTTP client: {}", e)))?;
        
        // Check environment for endpoints
        let kirq_endpoint = std::env::var("QSSH_KIRQ_ENDPOINT")
            .ok()
            .or_else(|| Some("http://localhost:8001".to_string()));
        
        let crypto4a_endpoint = std::env::var("QSSH_CRYPTO4A_ENDPOINT")
            .ok()
            .or_else(|| Some("http://localhost:8106".to_string()));
        
        let qkd_available = std::env::var("QSSH_QKD_AVAILABLE")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        
        Ok(Self {
            kirq_endpoint,
            crypto4a_endpoint,
            qkd_available,
            client,
        })
    }
    
    /// Get entropy from the best available source
    pub async fn get_entropy(&self, num_bytes: usize) -> Result<Vec<u8>> {
        // Priority order: QKD > KIRQ > Crypto4A > OS RNG
        
        // 1. Try KIRQ Hub first (aggregated quantum entropy)
        if let Some(endpoint) = &self.kirq_endpoint {
            match self.get_kirq_entropy(endpoint, num_bytes).await {
                Ok(entropy) => {
                    log::info!("Using KIRQ entropy");
                    return Ok(entropy);
                }
                Err(e) => log::warn!("KIRQ entropy failed: {}", e),
            }
        }
        
        // 2. Try Crypto4A HSM
        if let Some(endpoint) = &self.crypto4a_endpoint {
            match self.get_crypto4a_entropy(endpoint, num_bytes).await {
                Ok(entropy) => {
                    log::info!("Using Crypto4A entropy");
                    return Ok(entropy);
                }
                Err(e) => log::warn!("Crypto4A entropy failed: {}", e),
            }
        }
        
        // 3. Fall back to OS random (still quantum-resistant with ChaCha20)
        log::info!("Using OS entropy (no quantum sources available)");
        self.get_os_entropy(num_bytes)
    }
    
    /// Get entropy from KIRQ Hub
    async fn get_kirq_entropy(&self, endpoint: &str, num_bytes: usize) -> Result<Vec<u8>> {
        let url = format!("{}/api/entropy/consume", endpoint);
        
        let response = self.client
            .post(&url)
            .json(&serde_json::json!({
                "amount": num_bytes,
                "consumer": "qssh"
            }))
            .send()
            .await
            .map_err(|e| QsshError::Qkd(format!("KIRQ request failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(QsshError::Qkd(format!("KIRQ error: {}", response.status())));
        }
        
        #[derive(serde::Deserialize)]
        struct KirqResponse {
            entropy: String, // Base64 encoded
        }
        
        let resp: KirqResponse = response.json().await
            .map_err(|e| QsshError::Qkd(format!("Invalid KIRQ response: {}", e)))?;
        
        use base64::Engine;
        let entropy = base64::engine::general_purpose::STANDARD.decode(&resp.entropy)
            .map_err(|e| QsshError::Qkd(format!("Invalid base64: {}", e)))?;
        
        Ok(entropy)
    }
    
    /// Get entropy from Crypto4A HSM
    async fn get_crypto4a_entropy(&self, endpoint: &str, num_bytes: usize) -> Result<Vec<u8>> {
        let url = format!("{}?size={}", endpoint, num_bytes);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| QsshError::Qkd(format!("Crypto4A request failed: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(QsshError::Qkd(format!("Crypto4A error: {}", response.status())));
        }
        
        let entropy = response.bytes().await
            .map_err(|e| QsshError::Qkd(format!("Failed to read bytes: {}", e)))?;
        
        Ok(entropy.to_vec())
    }
    
    /// Get entropy from OS RNG
    fn get_os_entropy(&self, num_bytes: usize) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut entropy = vec![0u8; num_bytes];
        rand::thread_rng().fill_bytes(&mut entropy);
        Ok(entropy)
    }
    
    /// Mix multiple entropy sources for defense in depth
    pub async fn get_mixed_entropy(&self, num_bytes: usize) -> Result<Vec<u8>> {
        use sha3::{Sha3_256, Digest};
        
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-ENTROPY-MIX");
        
        // Try to get entropy from all sources and mix them
        let mut sources_used = 0;
        
        // KIRQ
        if let Ok(kirq) = self.get_entropy(num_bytes).await {
            hasher.update(&kirq);
            sources_used += 1;
        }
        
        // OS RNG (always available)
        let os_entropy = self.get_os_entropy(32)?;
        hasher.update(&os_entropy);
        sources_used += 1;
        
        log::info!("Mixed entropy from {} sources", sources_used);
        
        // Expand to requested size using HKDF
        let seed = hasher.finalize();
        self.expand_entropy(&seed, num_bytes)
    }
    
    /// Expand entropy using HKDF
    fn expand_entropy(&self, seed: &[u8], num_bytes: usize) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        let hkdf = Hkdf::<Sha256>::new(None, seed);
        let mut output = vec![0u8; num_bytes];
        
        hkdf.expand(b"QSSH-EXPAND", &mut output)
            .map_err(|e| QsshError::Crypto(format!("HKDF failed: {}", e)))?;
        
        Ok(output)
    }
}