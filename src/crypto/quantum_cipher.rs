//! Quantum-proof symmetric encryption using SHA3-based stream cipher
//! 
//! This implements a hash-based stream cipher that is quantum-secure.
//! Unlike AES which has reduced security against quantum computers,
//! hash functions like SHA3 maintain their security level.

use sha3::{Sha3_256, Digest};
use crate::{Result, QsshError};

/// Quantum-proof stream cipher using SHA3-256
/// 
/// This creates a keystream using SHA3 in counter mode (CTR)
/// which is then XORed with the plaintext for encryption.
/// This approach is quantum-secure as it relies on the one-wayness
/// of the hash function, which is not significantly weakened by quantum computers.
pub struct QuantumCipher {
    key: Vec<u8>,
    nonce_counter: u64,
}

impl QuantumCipher {
    /// Create from shared secret
    pub fn from_shared_secret(shared_secret: &[u8]) -> Result<Self> {
        if shared_secret.len() < 32 {
            return Err(QsshError::Crypto("Shared secret too short".into()));
        }
        
        // Use first 32 bytes as key
        let key = shared_secret[..32].to_vec();
        
        Ok(Self {
            key,
            nonce_counter: 0,
        })
    }
    
    /// Generate keystream using SHA3-256
    fn generate_keystream(&self, nonce: &[u8], counter: u64, length: usize) -> Vec<u8> {
        let mut keystream = Vec::with_capacity(length);
        let mut block_counter = counter;
        
        while keystream.len() < length {
            // Create input: key || nonce || counter
            let mut hasher = Sha3_256::new();
            hasher.update(&self.key);
            hasher.update(nonce);
            hasher.update(&block_counter.to_le_bytes());
            
            let block = hasher.finalize();
            keystream.extend_from_slice(&block);
            block_counter += 1;
        }
        
        keystream.truncate(length);
        keystream
    }
    
    /// Encrypt data using SHA3 stream cipher
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate deterministic nonce using SHA3 (quantum-safe)
        // This uses a counter-based approach that's unpredictable without the key
        let mut hasher = Sha3_256::new();
        hasher.update(&self.key);
        hasher.update(b"nonce");
        hasher.update(&self.nonce_counter.to_le_bytes());
        let nonce_hash = hasher.finalize();
        let nonce = nonce_hash[..16].to_vec();
        
        // Increment counter for next nonce
        self.nonce_counter += 1;
        
        // Generate keystream
        let keystream = self.generate_keystream(&nonce, 0, plaintext.len());
        
        // XOR plaintext with keystream
        let ciphertext: Vec<u8> = plaintext.iter()
            .zip(keystream.iter())
            .map(|(p, k)| p ^ k)
            .collect();
        
        Ok((ciphertext, nonce))
    }
    
    /// Decrypt data using SHA3 stream cipher
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        // Generate same keystream
        let keystream = self.generate_keystream(nonce, 0, ciphertext.len());
        
        // XOR ciphertext with keystream (same operation as encryption)
        let plaintext: Vec<u8> = ciphertext.iter()
            .zip(keystream.iter())
            .map(|(c, k)| c ^ k)
            .collect();
        
        Ok(plaintext)
    }
    
    /// Encrypt with authentication (adds HMAC-SHA3)
    pub fn encrypt_authenticated(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let (ciphertext, nonce) = self.encrypt(plaintext)?;
        
        // Create authentication tag using SHA3
        let mut hasher = Sha3_256::new();
        hasher.update(&self.key);
        hasher.update(&nonce);
        hasher.update(&ciphertext);
        let tag = hasher.finalize().to_vec();
        
        Ok((ciphertext, nonce, tag))
    }
    
    /// Decrypt with authentication verification
    pub fn decrypt_authenticated(&self, ciphertext: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        // Verify authentication tag
        let mut hasher = Sha3_256::new();
        hasher.update(&self.key);
        hasher.update(nonce);
        hasher.update(ciphertext);
        let computed_tag = hasher.finalize();
        
        // Constant-time comparison
        if tag.len() != computed_tag.len() {
            return Err(QsshError::Crypto("Authentication failed".into()));
        }
        
        let mut diff = 0u8;
        for (a, b) in tag.iter().zip(computed_tag.iter()) {
            diff |= a ^ b;
        }
        
        if diff != 0 {
            return Err(QsshError::Crypto("Authentication failed".into()));
        }
        
        self.decrypt(ciphertext, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_quantum_cipher() {
        let shared_secret = vec![0x42u8; 32];
        let mut cipher = QuantumCipher::from_shared_secret(&shared_secret).expect("Failed to create cipher");

        let plaintext = b"Hello, quantum world!";
        let (ciphertext, nonce) = cipher.encrypt(plaintext).expect("Failed to encrypt");

        assert_ne!(ciphertext, plaintext);

        let decrypted = cipher.decrypt(&ciphertext, &nonce).expect("Failed to decrypt");
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_authenticated_encryption() {
        let shared_secret = vec![0x42u8; 32];
        let mut cipher = QuantumCipher::from_shared_secret(&shared_secret).expect("Failed to create cipher");

        let plaintext = b"Secret quantum message";
        let (ciphertext, nonce, tag) = cipher.encrypt_authenticated(plaintext).expect("Failed to encrypt with auth");

        let decrypted = cipher.decrypt_authenticated(&ciphertext, &nonce, &tag).expect("Failed to decrypt with auth");
        assert_eq!(decrypted, plaintext);
        
        // Test with wrong tag
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 1;
        assert!(cipher.decrypt_authenticated(&ciphertext, &nonce, &bad_tag).is_err());
    }
}