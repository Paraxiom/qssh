//! Quantum Key Distribution integration

use crate::Result;

pub mod entropy;
pub mod integration;
pub mod stark_integration;

pub use entropy::QuantumEntropyProvider;
pub use integration::QsshQkdIntegration;
pub use stark_integration::{QsshStarkQkd, ProvenQkdKey};

pub struct QkdClient {
    integration: Option<QsshQkdIntegration>,
}

impl QkdClient {
    pub fn new(endpoint: String, auth_token: Option<&str>) -> Result<Self> {
        let integration = if !endpoint.is_empty() {
            match QsshQkdIntegration::new(&endpoint, true) {
                Ok(integration) => Some(integration),
                Err(e) => {
                    log::warn!("Failed to create QKD integration: {}, falling back to entropy", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self { integration })
    }
    
    pub async fn get_key(&self, length: usize) -> Result<Vec<u8>> {
        if let Some(integration) = &self.integration {
            // Try to get real QKD key
            let session_id = format!("qssh-{}", rand::random::<u64>());
            match integration.get_session_key(&session_id).await {
                Ok(mut key) => {
                    // Truncate or extend to requested length
                    key.resize(length, 0);
                    return Ok(key);
                }
                Err(e) => {
                    log::warn!("QKD key retrieval failed: {}, using quantum entropy fallback", e);
                }
            }
        }
        
        // Fallback to quantum entropy
        let provider = QuantumEntropyProvider::new()?;
        provider.get_entropy(length).await
    }
}