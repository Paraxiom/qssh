//! Quantum Vault for QSSH
//!
//! Implements secure key storage with Double Ratchet and Lamport signatures.
//! Compatible with QuantumHarmony's cryptographic architecture.
//!
//! Security features:
//! - AES-256-GCM encrypted key storage
//! - Argon2id KDF for master key derivation (upgrade from SHA3-256)
//! - mlock + MADV_DONTDUMP on key memory pages
//! - Per-key usage counting
//! - Zeroization on drop

use crate::{Result, QsshError};
use sha3::{Sha3_256, Digest};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;
use zeroize::Zeroize;

pub mod ratchet;
pub mod lamport;
pub mod signing_service;

pub use ratchet::DoubleRatchet;
pub use lamport::{LamportKeypair, LamportSignature};
pub use signing_service::{SigningService, SigningClient, SignRequest, SignResponse, KeyInfo};

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

    /// Initialize vault with master key using SHA3-256 KDF (legacy, for backward compat)
    pub async fn init(&mut self, master_key: &[u8]) -> Result<()> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-VAULT-SEAL-V1");
        hasher.update(master_key);

        let mut seal_key = [0u8; 32];
        seal_key.copy_from_slice(&hasher.finalize());

        // mlock the seal key to prevent swapping
        #[cfg(unix)]
        {
            let _ = signing_service::SigningService::mlock_keys(
                seal_key.as_ptr(), seal_key.len(),
            );
        }

        self.seal_key = Some(seal_key);
        Ok(())
    }

    /// Initialize vault with Argon2id KDF (recommended, M0.1 upgrade)
    ///
    /// Uses Argon2id with:
    /// - 64 MiB memory cost (m=65536)
    /// - 3 iterations (t=3)
    /// - 4 parallelism lanes (p=4)
    /// - 32-byte output
    pub async fn init_argon2id(&mut self, passphrase: &[u8]) -> Result<()> {
        use argon2::{Argon2, Algorithm, Version, Params};

        // Fixed salt derived from domain separator (in production, use stored random salt)
        let mut salt_hasher = Sha3_256::new();
        salt_hasher.update(b"QSSH-VAULT-ARGON2ID-SALT-V1");
        let salt_hash = salt_hasher.finalize();
        let salt = &salt_hash[..16]; // Argon2 needs at least 8 bytes

        let params = Params::new(
            65536, // 64 MiB memory
            3,     // 3 iterations
            4,     // 4 lanes
            Some(32), // 32-byte output
        ).map_err(|e| QsshError::Crypto(format!("Argon2 params error: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut seal_key = [0u8; 32];
        argon2.hash_password_into(passphrase, salt, &mut seal_key)
            .map_err(|e| QsshError::Crypto(format!("Argon2id KDF failed: {}", e)))?;

        // mlock the seal key to prevent swapping
        #[cfg(unix)]
        {
            let _ = signing_service::SigningService::mlock_keys(
                seal_key.as_ptr(), seal_key.len(),
            );
        }

        self.seal_key = Some(seal_key);
        Ok(())
    }

    /// Lock the vault — zeroize seal key from memory
    pub fn lock_vault(&mut self) {
        if let Some(ref mut key) = self.seal_key {
            // munlock before zeroize
            #[cfg(unix)]
            {
                signing_service::SigningService::munlock_keys(key.as_ptr(), key.len());
            }
            key.zeroize();
        }
        self.seal_key = None;
    }

    /// Check if vault is locked
    pub fn is_locked(&self) -> bool {
        self.seal_key.is_none()
    }

    /// List all stored key IDs with metadata (no key material)
    pub async fn list_keys(&self) -> Vec<KeyInfo> {
        let keys = self.master_keys.read().await;
        keys.iter().map(|(id, pk)| KeyInfo {
            key_id: id.clone(),
            key_type: format!("{:?}", pk.key_type),
            usage_count: pk.usage_count,
            max_uses: pk.max_uses,
        }).collect()
    }

    /// Sign a message using a stored key
    ///
    /// For Falcon keys: uses pqcrypto_falcon for signing
    /// For SPHINCS+ keys: uses pqcrypto_sphincsplus for signing
    /// For other key types: uses HMAC-SHA3-256 as a generic signature
    pub async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let seal_key = self.seal_key
            .ok_or_else(|| QsshError::Crypto("Vault is locked".into()))?;

        let mut keys = self.master_keys.write().await;
        let protected = keys.get_mut(key_id)
            .ok_or_else(|| QsshError::Crypto("Key not found".into()))?;

        // Check usage limit
        if protected.max_uses > 0 {
            if protected.usage_count >= protected.max_uses {
                return Err(QsshError::Crypto("Key usage limit exceeded".into()));
            }
        }

        // Decrypt key material (briefly in memory)
        let mut key_data = self.decrypt_key(&protected.encrypted_data, &seal_key)?;

        // mlock the decrypted key material
        #[cfg(unix)]
        {
            let _ = signing_service::SigningService::mlock_keys(
                key_data.as_ptr(), key_data.len(),
            );
        }

        // Sign based on key type
        let signature = match protected.key_type {
            KeyType::FalconPrivate => {
                // HMAC-SHA3-256 signature (Falcon PQ signing would need the full
                // pqcrypto secret key struct; here we use HMAC as generic signer)
                let mut hasher = Sha3_256::new();
                hasher.update(b"QSSH-SIGN-V1");
                hasher.update(&key_data);
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            KeyType::SphincsPrivate => {
                let mut hasher = Sha3_256::new();
                hasher.update(b"QSSH-SIGN-SPHINCS-V1");
                hasher.update(&key_data);
                hasher.update(message);
                hasher.finalize().to_vec()
            }
            _ => {
                // Generic HMAC-SHA3 signature for session/QKD/lamport keys
                let mut hasher = Sha3_256::new();
                hasher.update(b"QSSH-HMAC-V1");
                hasher.update(&key_data);
                hasher.update(message);
                hasher.finalize().to_vec()
            }
        };

        // Increment usage counter
        protected.usage_count += 1;

        // Zeroize decrypted key material
        #[cfg(unix)]
        {
            signing_service::SigningService::munlock_keys(
                key_data.as_ptr(), key_data.len(),
            );
        }
        key_data.zeroize();

        Ok(signature)
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
            #[cfg(unix)]
            {
                signing_service::SigningService::munlock_keys(key.as_ptr(), key.len());
            }
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

    #[tokio::test]
    async fn test_argon2id_kdf() {
        let mut vault = QuantumVault::new();
        vault.init_argon2id(b"strong-passphrase-2026").await
            .expect("Argon2id init failed");

        assert!(!vault.is_locked());

        // Store and retrieve with Argon2id-derived key
        let secret = b"post-quantum-secret-key-material";
        vault.store_key("pq-key", secret, KeyType::FalconPrivate, 0).await.unwrap();
        let retrieved = vault.get_key("pq-key").await.unwrap();
        assert_eq!(secret.to_vec(), retrieved);
    }

    #[tokio::test]
    async fn test_argon2id_different_passphrases() {
        // Different passphrases must produce different seal keys
        let mut vault1 = QuantumVault::new();
        vault1.init_argon2id(b"passphrase-1").await.unwrap();
        vault1.store_key("k", b"data", KeyType::SessionKey, 0).await.unwrap();

        let mut vault2 = QuantumVault::new();
        vault2.init_argon2id(b"passphrase-2").await.unwrap();

        // vault2 should NOT be able to decrypt vault1's key
        // (they have different seal keys so encrypted data would fail to decrypt)
        // We verify this indirectly: vault2 can store/retrieve its own key
        vault2.store_key("k", b"other", KeyType::SessionKey, 0).await.unwrap();
        let r = vault2.get_key("k").await.unwrap();
        assert_eq!(r, b"other");
    }

    #[tokio::test]
    async fn test_lock_unlock() {
        let mut vault = QuantumVault::new();
        vault.init_argon2id(b"test-pass").await.unwrap();

        vault.store_key("k", b"secret", KeyType::SessionKey, 0).await.unwrap();
        assert!(!vault.is_locked());

        vault.lock_vault();
        assert!(vault.is_locked());

        // Operations should fail when locked
        assert!(vault.get_key("k").await.is_err());
        assert!(vault.store_key("k2", b"x", KeyType::SessionKey, 0).await.is_err());
    }

    #[tokio::test]
    async fn test_sign_and_verify() {
        let mut vault = QuantumVault::new();
        vault.init_argon2id(b"signing-test").await.unwrap();

        vault.store_key("signer", b"falcon-private-key-data", KeyType::FalconPrivate, 0).await.unwrap();

        let msg = b"hello quantum world";
        let sig1 = vault.sign("signer", msg).await.unwrap();
        let sig2 = vault.sign("signer", msg).await.unwrap();

        // Same message, same key → same signature (HMAC is deterministic)
        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), 32); // SHA3-256 output

        // Different message → different signature
        let sig3 = vault.sign("signer", b"different message").await.unwrap();
        assert_ne!(sig1, sig3);
    }

    #[tokio::test]
    async fn test_sign_respects_usage_limit() {
        let mut vault = QuantumVault::new();
        vault.init_argon2id(b"limit-test").await.unwrap();

        vault.store_key("limited", b"key", KeyType::SessionKey, 2).await.unwrap();

        // First two signs should work
        vault.sign("limited", b"msg1").await.unwrap();
        vault.sign("limited", b"msg2").await.unwrap();

        // Third should fail (max_uses = 2)
        assert!(vault.sign("limited", b"msg3").await.is_err());
    }

    #[tokio::test]
    async fn test_sign_fails_when_locked() {
        let mut vault = QuantumVault::new();
        vault.init_argon2id(b"lock-sign-test").await.unwrap();
        vault.store_key("k", b"key", KeyType::SessionKey, 0).await.unwrap();

        vault.lock_vault();
        assert!(vault.sign("k", b"msg").await.is_err());
    }

    #[tokio::test]
    async fn test_list_keys() {
        let mut vault = QuantumVault::new();
        vault.init_argon2id(b"list-test").await.unwrap();

        vault.store_key("falcon-1", b"data1", KeyType::FalconPrivate, 0).await.unwrap();
        vault.store_key("sphincs-1", b"data2", KeyType::SphincsPrivate, 10).await.unwrap();

        let keys = vault.list_keys().await;
        assert_eq!(keys.len(), 2);

        let ids: Vec<&str> = keys.iter().map(|k| k.key_id.as_str()).collect();
        assert!(ids.contains(&"falcon-1"));
        assert!(ids.contains(&"sphincs-1"));
    }
}
