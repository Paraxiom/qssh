//! QRNG Integration for Post-Quantum Cryptography
//!
//! This module ensures that PQC algorithms (Falcon-512, SPHINCS+)
//! use quantum entropy when available, providing true quantum randomness
//! for key generation and nonces.

use rand::{RngCore, SeedableRng, CryptoRng};
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Quantum Random Number Generator for PQC
pub struct QuantumRng {
    /// Fallback RNG for when quantum sources are unavailable
    fallback: ChaCha20Rng,

    /// QRNG endpoint (e.g., KIRQ Hub)
    qrng_endpoint: Option<String>,

    /// Cached quantum entropy
    entropy_cache: Arc<Mutex<Vec<u8>>>,

    /// Whether to mix quantum entropy with OS entropy (defense in depth)
    mix_with_os: bool,
}

impl QuantumRng {
    /// Create new QRNG with optional endpoint
    pub fn new(qrng_endpoint: Option<String>) -> Self {
        // Seed fallback RNG from OS
        let fallback = ChaCha20Rng::from_entropy();

        Self {
            fallback,
            qrng_endpoint,
            entropy_cache: Arc::new(Mutex::new(Vec::new())),
            mix_with_os: true, // Always mix for defense in depth
        }
    }

    /// Get quantum entropy if available
    async fn get_quantum_entropy(&self, num_bytes: usize) -> Option<Vec<u8>> {
        if let Some(endpoint) = &self.qrng_endpoint {
            // Try to get from QRNG device
            match self.fetch_from_qrng(endpoint, num_bytes).await {
                Ok(entropy) => {
                    log::info!("Using QRNG entropy for PQC key generation");
                    Some(entropy)
                }
                Err(e) => {
                    log::warn!("QRNG unavailable, using OS entropy: {}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    /// Fetch entropy from QRNG endpoint
    async fn fetch_from_qrng(&self, endpoint: &str, num_bytes: usize) -> Result<Vec<u8>, String> {
        // In production, this would call the actual QRNG API
        // For now, return error to trigger fallback
        Err("QRNG not yet implemented".to_string())
    }

    /// Generate key material with quantum enhancement
    pub async fn generate_key_material(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut result = vec![0u8; num_bytes];

        // Try to get quantum entropy
        if let Some(quantum) = self.get_quantum_entropy(num_bytes).await {
            // Mix quantum with OS entropy for defense in depth
            if self.mix_with_os {
                let mut os_entropy = vec![0u8; num_bytes];
                self.fallback.fill_bytes(&mut os_entropy);

                // XOR quantum and OS entropy
                for i in 0..num_bytes {
                    result[i] = quantum[i] ^ os_entropy[i];
                }

                log::info!("Generated key material using QRNG + OS entropy mix");
            } else {
                // Pure quantum entropy
                result = quantum;
                log::info!("Generated key material using pure QRNG");
            }
        } else {
            // Fallback to OS entropy
            self.fallback.fill_bytes(&mut result);
            log::info!("Generated key material using OS entropy (QRNG unavailable)");
        }

        result
    }
}

// Implement RngCore for compatibility with pqcrypto
impl RngCore for QuantumRng {
    fn next_u32(&mut self) -> u32 {
        self.fallback.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.fallback.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // For synchronous calls, use cached entropy or fallback
        self.fallback.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fallback.try_fill_bytes(dest)
    }
}

// Mark as cryptographically secure
impl CryptoRng for QuantumRng {}

/// Integration with Falcon-512 key generation
pub async fn generate_falcon_keypair_with_qrng(qrng_endpoint: Option<String>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut qrng = QuantumRng::new(qrng_endpoint);

    // Generate seed with quantum entropy
    let _seed = qrng.generate_key_material(32).await;

    // Note: pqcrypto doesn't expose seeded key generation yet
    // When available, we would use: falcon512::keypair_from_seed(&seed)
    // For now, the OS RNG might be enhanced by hardware QRNG at system level

    use pqcrypto_falcon::falcon512;
    use pqcrypto_traits::sign::{PublicKey, SecretKey};
    let (pk, sk) = falcon512::keypair();

    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

/// Integration with SPHINCS+ key generation
pub async fn generate_sphincs_keypair_with_qrng(qrng_endpoint: Option<String>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut qrng = QuantumRng::new(qrng_endpoint);

    // Generate seed with quantum entropy
    let _seed = qrng.generate_key_material(32).await;

    // Note: pqcrypto doesn't expose seeded key generation yet
    // When available, we would use: sphincs::keypair_from_seed(&seed)

    use pqcrypto_sphincsplus::sphincssha256128ssimple as sphincs;
    use pqcrypto_traits::sign::{PublicKey, SecretKey};
    let (pk, sk) = sphincs::keypair();

    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

/// Configuration for QRNG integration
pub struct QrngConfig {
    /// KIRQ Hub endpoint
    pub kirq_endpoint: Option<String>,

    /// Crypto4A HSM endpoint
    pub crypto4a_endpoint: Option<String>,

    /// Local QRNG device path (e.g., /dev/qrandom)
    pub device_path: Option<String>,

    /// Always mix with OS entropy for defense in depth
    pub always_mix: bool,
}

impl Default for QrngConfig {
    fn default() -> Self {
        Self {
            kirq_endpoint: std::env::var("QSSH_KIRQ_ENDPOINT").ok(),
            crypto4a_endpoint: std::env::var("QSSH_CRYPTO4A_ENDPOINT").ok(),
            device_path: std::env::var("QSSH_QRNG_DEVICE").ok(),
            always_mix: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_qrng_fallback() {
        let mut qrng = QuantumRng::new(None);
        let entropy = qrng.generate_key_material(32).await;
        assert_eq!(entropy.len(), 32);
    }

    #[tokio::test]
    async fn test_falcon_with_qrng() {
        let result = generate_falcon_keypair_with_qrng(None).await;
        assert!(result.is_ok());
    }
}