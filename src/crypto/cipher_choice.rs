//! Cipher selection module - choose between AES (quantum-resistant) and SHA3 (quantum-proof)

use crate::{Result, QsshError};
use super::{SymmetricCrypto, QuantumCipher};

/// Cipher algorithm choice
#[derive(Debug, Clone, Copy)]
pub enum CipherAlgorithm {
    /// AES-256-GCM (quantum-resistant, ~128-bit post-quantum security)
    Aes256Gcm,
    /// SHA3-256 stream cipher (quantum-proof, 256-bit post-quantum security)
    Sha3Stream,
}

/// Universal cipher interface
pub enum UniversalCipher {
    Aes(SymmetricCrypto),
    Sha3(QuantumCipher),
}

impl UniversalCipher {
    /// Create from shared secret with specified algorithm
    pub fn from_shared_secret(shared_secret: &[u8], algorithm: CipherAlgorithm) -> Result<Self> {
        match algorithm {
            CipherAlgorithm::Aes256Gcm => {
                Ok(UniversalCipher::Aes(SymmetricCrypto::from_shared_secret(shared_secret)?))
            }
            CipherAlgorithm::Sha3Stream => {
                Ok(UniversalCipher::Sha3(QuantumCipher::from_shared_secret(shared_secret)?))
            }
        }
    }
    
    /// Encrypt data
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            UniversalCipher::Aes(cipher) => cipher.encrypt(plaintext),
            UniversalCipher::Sha3(cipher) => cipher.encrypt(plaintext),
        }
    }
    
    /// Decrypt data
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        match self {
            UniversalCipher::Aes(cipher) => cipher.decrypt(ciphertext, nonce),
            UniversalCipher::Sha3(cipher) => cipher.decrypt(ciphertext, nonce),
        }
    }
    
    /// Get algorithm name
    pub fn algorithm_name(&self) -> &str {
        match self {
            UniversalCipher::Aes(_) => "AES-256-GCM",
            UniversalCipher::Sha3(_) => "SHA3-256-CTR",
        }
    }
}

impl Default for CipherAlgorithm {
    fn default() -> Self {
        // Default to quantum-proof SHA3
        CipherAlgorithm::Sha3Stream
    }
}