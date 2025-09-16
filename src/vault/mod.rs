//! Quantum Vault for QSSH
//! 
//! Implements secure key storage with Double Ratchet and Lamport signatures
//! Compatible with QuantumHarmony's cryptographic architecture

use crate::{Result, QsshError};
use sha3::{Sha3_256, Sha3_512, Digest};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;
use zeroize::Zeroize;

pub mod ratchet;
pub mod lamport;

pub use ratchet::DoubleRatchet;
pub use lamport::{LamportKeypair, LamportSignature};

/// Quantum Vault for secure key management
pub struct QuantumVault {
    /// Master keys protected by the vault
    master_keys: Arc<RwLock<HashMap<String, ProtectedKey>>>,
    /// Active ratchet sessions
    ratchets: Arc<RwLock<HashMap<String, DoubleRatchet>>>,
    /// Lamport key storage
    lamport_keys: Arc<RwLock<HashMap<String, LamportKeyChain>>>,
    /// Vault seal key (derived from TPM or master password)
    seal_key: Option<[u8; 32]>,
}

/// Protected key storage
#[derive(Clone)]
struct ProtectedKey {
    /// Encrypted key material
    encrypted_data: Vec<u8>,
    /// Key type identifier
    key_type: KeyType,
    /// Usage counter (for one-time keys)
    usage_count: u64,
    /// Maximum uses allowed (0 = unlimited)
    max_uses: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeyType {
    FalconPrivate,
    SphincsPrivate,
    QkdMaster,
    SessionKey,
    LamportSeed,
}

/// Lamport key chain for one-time signatures
struct LamportKeyChain {
    /// Current key index
    current_index: usize,
    /// Pre-generated keypairs
    keypairs: Vec<LamportKeypair>,
    /// Root seed for deterministic generation
    root_seed: [u8; 32],
}

impl QuantumVault {
    /// Create a new quantum vault
    pub fn new() -> Self {
        Self {
            master_keys: Arc::new(RwLock::new(HashMap::new())),
            ratchets: Arc::new(RwLock::new(HashMap::new())),
            lamport_keys: Arc::new(RwLock::new(HashMap::new())),
            seal_key: None,
        }
    }
    
    /// Initialize vault with master key (from TPM or password)
    pub async fn init(&mut self, master_key: &[u8]) -> Result<()> {
        // Derive seal key using KDF
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-VAULT-SEAL-V1");
        hasher.update(master_key);
        
        let mut seal_key = [0u8; 32];
        seal_key.copy_from_slice(&hasher.finalize());
        self.seal_key = Some(seal_key);
        
        Ok(())
    }
    
    /// Store a key in the vault
    pub async fn store_key(
        &self, 
        key_id: &str, 
        key_data: &[u8], 
        key_type: KeyType,
        max_uses: u64,
    ) -> Result<()> {
        let seal_key = self.seal_key
            .ok_or_else(|| QsshError::Crypto("Vault not initialized".into()))?;
        
        // Encrypt key data
        let encrypted = self.encrypt_key(key_data, &seal_key)?;
        
        let protected = ProtectedKey {
            encrypted_data: encrypted,
            key_type,
            usage_count: 0,
            max_uses,
        };
        
        let mut keys = self.master_keys.write().await;
        keys.insert(key_id.to_string(), protected);
        
        Ok(())
    }
    
    /// Retrieve a key from the vault
    pub async fn get_key(&self, key_id: &str) -> Result<Vec<u8>> {
        let seal_key = self.seal_key
            .ok_or_else(|| QsshError::Crypto("Vault not initialized".into()))?;
        
        let mut keys = self.master_keys.write().await;
        let protected = keys.get_mut(key_id)
            .ok_or_else(|| QsshError::Crypto("Key not found".into()))?;
        
        // Check usage limit
        if protected.max_uses > 0 {
            if protected.usage_count >= protected.max_uses {
                return Err(QsshError::Crypto("Key usage limit exceeded".into()));
            }
            protected.usage_count += 1;
        }
        
        // Decrypt key data
        self.decrypt_key(&protected.encrypted_data, &seal_key)
    }
    
    /// Create a new ratchet session
    pub async fn create_ratchet(&self, session_id: &str, root_key: &[u8]) -> Result<()> {
        let ratchet = DoubleRatchet::new(root_key);
        
        let mut ratchets = self.ratchets.write().await;
        ratchets.insert(session_id.to_string(), ratchet);
        
        Ok(())
    }
    
    /// Ratchet forward to get next key
    pub async fn ratchet_forward(&self, session_id: &str) -> Result<[u8; 32]> {
        let mut ratchets = self.ratchets.write().await;
        let ratchet = ratchets.get_mut(session_id)
            .ok_or_else(|| QsshError::Crypto("Ratchet session not found".into()))?;
        
        Ok(ratchet.next_key())
    }
    
    /// Initialize Lamport key chain
    pub async fn init_lamport_chain(&self, chain_id: &str, seed: &[u8], count: usize) -> Result<()> {
        // Derive root seed
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-LAMPORT-SEED");
        hasher.update(seed);
        let mut root_seed = [0u8; 32];
        root_seed.copy_from_slice(&hasher.finalize());
        
        // Pre-generate keypairs
        let mut keypairs = Vec::with_capacity(count);
        for i in 0..count {
            let mut key_seed = [0u8; 32];
            let mut hasher = Sha3_256::new();
            hasher.update(&root_seed);
            hasher.update(&i.to_le_bytes());
            key_seed.copy_from_slice(&hasher.finalize());
            
            keypairs.push(LamportKeypair::generate(&key_seed));
        }
        
        let chain = LamportKeyChain {
            current_index: 0,
            keypairs,
            root_seed,
        };
        
        let mut chains = self.lamport_keys.write().await;
        chains.insert(chain_id.to_string(), chain);
        
        Ok(())
    }
    
    /// Get next Lamport keypair from chain
    pub async fn get_lamport_keypair(&self, chain_id: &str) -> Result<LamportKeypair> {
        let mut chains = self.lamport_keys.write().await;
        let chain = chains.get_mut(chain_id)
            .ok_or_else(|| QsshError::Crypto("Lamport chain not found".into()))?;
        
        if chain.current_index >= chain.keypairs.len() {
            return Err(QsshError::Crypto("Lamport chain exhausted".into()));
        }
        
        let keypair = chain.keypairs[chain.current_index].clone();
        chain.current_index += 1;
        
        Ok(keypair)
    }
    
    /// Encrypt key using AES-256-GCM
    fn encrypt_key(&self, key_data: &[u8], seal_key: &[u8; 32]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit, OsRng},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;
        
        let cipher = Aes256Gcm::new_from_slice(seal_key)
            .map_err(|e| QsshError::Crypto(format!("Cipher init failed: {}", e)))?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher
            .encrypt(nonce, key_data)
            .map_err(|e| QsshError::Crypto(format!("Encryption failed: {}", e)))?;
        
        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt key using AES-256-GCM
    fn decrypt_key(&self, encrypted: &[u8], seal_key: &[u8; 32]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        
        if encrypted.len() < 12 {
            return Err(QsshError::Crypto("Invalid encrypted data".into()));
        }
        
        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let cipher = Aes256Gcm::new_from_slice(seal_key)
            .map_err(|e| QsshError::Crypto(format!("Cipher init failed: {}", e)))?;
        
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| QsshError::Crypto(format!("Decryption failed: {}", e)))
    }
}

impl Drop for QuantumVault {
    fn drop(&mut self) {
        // Zeroize seal key on drop
        if let Some(ref mut key) = self.seal_key {
            key.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_vault_basic_operations() {
        let mut vault = QuantumVault::new();
        vault.init(b"test-master-key").await.expect("Failed to initialize vault");

        // Store and retrieve key
        let test_key = b"super-secret-key";
        vault.store_key("test", test_key, KeyType::SessionKey, 0).await.expect("Failed to store key");

        let retrieved = vault.get_key("test").await.expect("Failed to retrieve key");
        assert_eq!(test_key.to_vec(), retrieved);
    }
    
    #[tokio::test]
    async fn test_one_time_key() {
        let mut vault = QuantumVault::new();
        vault.init(b"test-master-key").await.expect("Failed to initialize vault");

        // Store one-time key
        let test_key = b"one-time-secret";
        vault.store_key("once", test_key, KeyType::LamportSeed, 1).await.expect("Failed to store one-time key");

        // First retrieval should succeed
        let retrieved = vault.get_key("once").await.expect("Failed to retrieve one-time key");
        assert_eq!(test_key.to_vec(), retrieved);

        // Second retrieval should fail
        assert!(vault.get_key("once").await.is_err());
    }
}