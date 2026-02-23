//! QRNG Integration for Post-Quantum Cryptography
//!
//! This module ensures that PQC algorithms (Falcon-512, SPHINCS+)
//! use quantum entropy when available, providing true quantum randomness
//! for key generation and nonces.
//!
//! Entropy sources (tried in order):
//! 1. Local QRNG device (`/dev/qrandom` or `QSSH_QRNG_DEVICE`)
//! 2. KIRQ Hub HTTP endpoint (`QSSH_KIRQ_ENDPOINT`)
//! 3. Crypto4A HSM endpoint (`QSSH_CRYPTO4A_ENDPOINT`)
//! 4. OS entropy (fallback — always mixed in for defense in depth)

use rand::{RngCore, SeedableRng, CryptoRng};
use fn_dsa::KeyPairGenerator as _;
use signature::Keypair as _;
use rand_chacha::ChaCha20Rng;
use sha2::{Sha256, Digest};
/// Quantum Random Number Generator for PQC
pub struct QuantumRng {
    /// Internal RNG — seeded from quantum + OS entropy mix
    rng: ChaCha20Rng,

    /// QRNG configuration
    config: QrngConfig,

    /// Whether quantum entropy was successfully used for seeding
    quantum_seeded: bool,
}

impl QuantumRng {
    /// Create new QRNG with optional endpoint
    pub fn new(qrng_endpoint: Option<String>) -> Self {
        let config = if let Some(ep) = qrng_endpoint {
            QrngConfig {
                kirq_endpoint: Some(ep),
                ..QrngConfig::default()
            }
        } else {
            QrngConfig::default()
        };

        // Seed from OS entropy initially — quantum seeding happens in generate_key_material()
        let rng = ChaCha20Rng::from_entropy();

        Self {
            rng,
            config,
            quantum_seeded: false,
        }
    }

    /// Create with full configuration
    pub fn with_config(config: QrngConfig) -> Self {
        let rng = ChaCha20Rng::from_entropy();
        Self {
            rng,
            config,
            quantum_seeded: false,
        }
    }

    /// Whether this RNG was seeded with quantum entropy
    pub fn is_quantum_seeded(&self) -> bool {
        self.quantum_seeded
    }

    /// Seed the internal RNG with quantum entropy (mixed with OS for defense in depth).
    /// Call this once before using the RNG for key generation.
    pub async fn seed_from_quantum(&mut self) -> bool {
        match self.fetch_quantum_entropy(32).await {
            Some(quantum_bytes) => {
                // Mix quantum entropy with OS entropy via SHA-256
                let mut os_bytes = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut os_bytes);

                let mut hasher = Sha256::new();
                hasher.update(b"QSSH-QRNG-SEED-V1");
                hasher.update(&quantum_bytes);
                hasher.update(&os_bytes);
                let seed: [u8; 32] = hasher.finalize().into();

                self.rng = ChaCha20Rng::from_seed(seed);
                self.quantum_seeded = true;
                log::info!("RNG seeded with quantum + OS entropy mix");
                true
            }
            None => {
                log::debug!("No quantum entropy available, using OS entropy");
                false
            }
        }
    }

    /// Try all configured quantum entropy sources in priority order
    async fn fetch_quantum_entropy(&self, num_bytes: usize) -> Option<Vec<u8>> {
        // 1. Local QRNG device (fastest, no network)
        if let Some(ref device) = self.config.device_path {
            match Self::read_device_entropy(device, num_bytes) {
                Ok(bytes) => {
                    log::info!("QRNG entropy from device: {}", device);
                    return Some(bytes);
                }
                Err(e) => {
                    log::debug!("QRNG device {} unavailable: {}", device, e);
                }
            }
        }

        // 2. KIRQ Hub endpoint
        if let Some(ref endpoint) = self.config.kirq_endpoint {
            match Self::fetch_http_entropy(endpoint, num_bytes).await {
                Ok(bytes) => {
                    log::info!("QRNG entropy from KIRQ Hub: {}", endpoint);
                    return Some(bytes);
                }
                Err(e) => {
                    log::debug!("KIRQ Hub {} unavailable: {}", endpoint, e);
                }
            }
        }

        // 3. Crypto4A HSM endpoint
        if let Some(ref endpoint) = self.config.crypto4a_endpoint {
            match Self::fetch_http_entropy(endpoint, num_bytes).await {
                Ok(bytes) => {
                    log::info!("QRNG entropy from Crypto4A HSM: {}", endpoint);
                    return Some(bytes);
                }
                Err(e) => {
                    log::debug!("Crypto4A HSM {} unavailable: {}", endpoint, e);
                }
            }
        }

        None
    }

    /// Read entropy from a local QRNG device file
    fn read_device_entropy(device_path: &str, num_bytes: usize) -> std::result::Result<Vec<u8>, String> {
        use std::io::Read;

        let path = std::path::Path::new(device_path);
        if !path.exists() {
            return Err(format!("Device not found: {}", device_path));
        }

        let mut file = std::fs::File::open(path)
            .map_err(|e| format!("Failed to open {}: {}", device_path, e))?;

        let mut buf = vec![0u8; num_bytes];
        file.read_exact(&mut buf)
            .map_err(|e| format!("Failed to read from {}: {}", device_path, e))?;

        // Basic entropy sanity check: reject all-zeros or all-ones
        if buf.iter().all(|&b| b == 0) || buf.iter().all(|&b| b == 0xff) {
            return Err("Device returned degenerate entropy (all zeros or all ones)".into());
        }

        Ok(buf)
    }

    /// Fetch entropy from an HTTP QRNG endpoint
    async fn fetch_http_entropy(endpoint: &str, num_bytes: usize) -> std::result::Result<Vec<u8>, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        let url = format!("{}/api/random?size={}", endpoint.trim_end_matches('/'), num_bytes);

        let response = client.get(&url)
            .send()
            .await
            .map_err(|e| format!("QRNG request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("QRNG endpoint returned status {}", response.status()));
        }

        // Try JSON response first ({"entropy": "base64..."})
        let bytes = response.bytes().await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        // If the response is JSON with a base64 entropy field, decode it
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(entropy_b64) = json.get("entropy").and_then(|v| v.as_str()) {
                use base64::Engine;
                let decoded = base64::engine::general_purpose::STANDARD.decode(entropy_b64)
                    .map_err(|e| format!("Invalid base64 entropy: {}", e))?;
                if decoded.len() >= num_bytes {
                    return Ok(decoded[..num_bytes].to_vec());
                }
                return Err(format!("Insufficient entropy: got {} bytes, need {}", decoded.len(), num_bytes));
            }
            // Check for raw hex field
            if let Some(hex_str) = json.get("data").and_then(|v| v.as_str()) {
                let decoded = hex::decode(hex_str)
                    .map_err(|e| format!("Invalid hex entropy: {}", e))?;
                if decoded.len() >= num_bytes {
                    return Ok(decoded[..num_bytes].to_vec());
                }
            }
        }

        // Raw binary response
        if bytes.len() >= num_bytes {
            Ok(bytes[..num_bytes].to_vec())
        } else {
            Err(format!("Insufficient entropy: got {} bytes, need {}", bytes.len(), num_bytes))
        }
    }

    /// Generate key material with quantum enhancement
    pub async fn generate_key_material(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut result = vec![0u8; num_bytes];

        // Try to get quantum entropy
        if let Some(quantum) = self.fetch_quantum_entropy(num_bytes).await {
            if self.config.always_mix {
                // Mix quantum with OS entropy for defense in depth
                let mut os_entropy = vec![0u8; num_bytes];
                self.rng.fill_bytes(&mut os_entropy);

                // XOR quantum and OS entropy
                for i in 0..num_bytes {
                    result[i] = quantum[i] ^ os_entropy[i];
                }
                log::info!("Generated key material using QRNG + OS entropy mix");
            } else {
                result = quantum;
                log::info!("Generated key material using pure QRNG");
            }

            // Also re-seed the internal RNG for future synchronous calls
            let mut hasher = Sha256::new();
            hasher.update(b"QSSH-QRNG-RESEED");
            hasher.update(&result);
            let seed: [u8; 32] = hasher.finalize().into();
            self.rng = ChaCha20Rng::from_seed(seed);
            self.quantum_seeded = true;
        } else {
            // Fallback to OS-seeded ChaCha20
            self.rng.fill_bytes(&mut result);
            log::debug!("Generated key material using OS entropy (QRNG unavailable)");
        }

        result
    }
}

// Implement RngCore for compatibility with crypto APIs (fn-dsa, slh-dsa)
impl RngCore for QuantumRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Uses the internal ChaCha20 RNG, which may be quantum-seeded
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

// Mark as cryptographically secure (ChaCha20 is CSPRNG, quantum seed adds entropy)
impl CryptoRng for QuantumRng {}

/// Integration with FN-DSA (Falcon-512) key generation using quantum entropy
pub async fn generate_falcon_keypair_with_qrng(qrng_endpoint: Option<String>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut qrng = QuantumRng::new(qrng_endpoint);

    // Seed with quantum entropy if available
    qrng.seed_from_quantum().await;

    // Use the quantum-seeded RNG for key generation
    let mut sk = vec![0u8; fn_dsa::sign_key_size(fn_dsa::FN_DSA_LOGN_512)];
    let mut pk = vec![0u8; fn_dsa::vrfy_key_size(fn_dsa::FN_DSA_LOGN_512)];
    fn_dsa::KeyPairGeneratorStandard::default()
        .keygen(fn_dsa::FN_DSA_LOGN_512, &mut qrng, &mut sk, &mut pk);

    if qrng.is_quantum_seeded() {
        log::info!("Falcon-512 keypair generated with quantum entropy");
    }

    Ok((pk, sk))
}

/// Integration with SLH-DSA (SPHINCS+) key generation using quantum entropy
pub async fn generate_sphincs_keypair_with_qrng(qrng_endpoint: Option<String>) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut qrng = QuantumRng::new(qrng_endpoint);

    // Seed with quantum entropy if available
    qrng.seed_from_quantum().await;

    // Use the quantum-seeded RNG for key generation
    use slh_dsa::Sha2_128s;
    let sk = slh_dsa::SigningKey::<Sha2_128s>::new(&mut qrng);
    let pk = sk.verifying_key().clone();

    if qrng.is_quantum_seeded() {
        log::info!("SPHINCS+ keypair generated with quantum entropy");
    }

    Ok((pk.to_bytes().to_vec(), sk.to_bytes().to_vec()))
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
        // Without any QRNG source, should not be quantum-seeded
        assert!(!qrng.is_quantum_seeded());
    }

    #[tokio::test]
    async fn test_falcon_with_qrng() {
        let result = generate_falcon_keypair_with_qrng(None).await;
        assert!(result.is_ok());
        let (pk, sk) = result.unwrap();
        assert_eq!(pk.len(), fn_dsa::vrfy_key_size(fn_dsa::FN_DSA_LOGN_512));
        assert_eq!(sk.len(), fn_dsa::sign_key_size(fn_dsa::FN_DSA_LOGN_512));
    }

    #[tokio::test]
    async fn test_sphincs_with_qrng() {
        let result = generate_sphincs_keypair_with_qrng(None).await;
        assert!(result.is_ok());
        let (pk, sk) = result.unwrap();
        assert_eq!(pk.len(), 32);  // SPHINCS+-SHA2-128s public key
        assert_eq!(sk.len(), 64);  // SPHINCS+-SHA2-128s secret key
    }

    #[tokio::test]
    async fn test_qrng_seed_from_quantum_no_source() {
        let mut qrng = QuantumRng::new(None);
        let seeded = qrng.seed_from_quantum().await;
        assert!(!seeded, "Should not seed without quantum source");
    }

    #[tokio::test]
    async fn test_qrng_device_entropy_nonexistent() {
        let result = QuantumRng::read_device_entropy("/dev/nonexistent_qrng", 32);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_qrng_config_from_env() {
        // Default config reads from env vars (which are typically unset in tests)
        let config = QrngConfig::default();
        assert!(config.always_mix);
    }

    #[test]
    fn test_quantum_rng_implements_rng_core() {
        let mut qrng = QuantumRng::new(None);
        // Verify it produces non-degenerate output
        let a = qrng.next_u64();
        let b = qrng.next_u64();
        // Extremely unlikely to be equal (2^-64 probability)
        assert_ne!(a, b);
    }

    #[test]
    fn test_quantum_rng_fill_bytes() {
        let mut qrng = QuantumRng::new(None);
        let mut buf = [0u8; 64];
        qrng.fill_bytes(&mut buf);
        // Should not be all zeros
        assert!(!buf.iter().all(|&b| b == 0));
    }
}
