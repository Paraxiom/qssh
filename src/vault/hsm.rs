//! Hardware Security Module (HSM) Key Storage Abstraction
//!
//! Provides a `KeyStorageBackend` trait that abstracts where PQC keys are stored:
//! - `SoftwareBackend`: In-memory with AES-256-GCM encryption (current default)
//! - `Pkcs11Backend`: PKCS#11 HSM interface (stub — returns clear errors)
//! - `FileBackend`: Encrypted key files on disk
//!
//! Configure via environment variables:
//! - `QSSH_HSM_TYPE`: "software" (default), "pkcs11", "file"
//! - `QSSH_HSM_PKCS11_LIB`: Path to PKCS#11 library (.so/.dylib)
//! - `QSSH_HSM_PKCS11_SLOT`: Slot ID for PKCS#11
//! - `QSSH_HSM_PKCS11_PIN`: PIN for PKCS#11 slot
//! - `QSSH_HSM_KEY_DIR`: Directory for file-based key storage

use crate::{Result, QsshError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Metadata about a stored key
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub key_id: String,
    pub key_type: String,
    pub size_bytes: usize,
    pub backend: String,
}

/// Trait for key storage backends
pub trait KeyStorageBackend: Send + Sync {
    /// Store a key with the given ID
    fn store(&mut self, key_id: &str, key_type: &str, key_data: &[u8]) -> Result<()>;

    /// Retrieve a key by ID (briefly in cleartext memory)
    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>>;

    /// Delete a key by ID
    fn delete(&mut self, key_id: &str) -> Result<()>;

    /// List all stored key IDs with metadata
    fn list(&self) -> Vec<KeyMetadata>;

    /// Check if a key exists
    fn exists(&self, key_id: &str) -> bool;

    /// Backend name for logging
    fn backend_name(&self) -> &str;
}

/// Software-based key storage (AES-256-GCM encrypted in memory)
pub struct SoftwareBackend {
    /// Encrypted key material: key_id -> (encrypted_data, key_type)
    keys: HashMap<String, (Vec<u8>, String)>,
    /// Seal key for encryption/decryption
    seal_key: [u8; 32],
}

impl SoftwareBackend {
    /// Create with a seal key (derived from passphrase or master key)
    pub fn new(seal_key: [u8; 32]) -> Self {
        Self {
            keys: HashMap::new(),
            seal_key,
        }
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Nonce};
        use rand::RngCore;

        let cipher = Aes256Gcm::new_from_slice(&self.seal_key)
            .map_err(|e| QsshError::Crypto(format!("Cipher init failed: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| QsshError::Crypto(format!("Encryption failed: {}", e)))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};

        if encrypted.len() < 12 {
            return Err(QsshError::Crypto("Invalid encrypted data (too short)".into()));
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.seal_key)
            .map_err(|e| QsshError::Crypto(format!("Cipher init failed: {}", e)))?;

        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| QsshError::Crypto(format!("Decryption failed: {}", e)))
    }
}

impl KeyStorageBackend for SoftwareBackend {
    fn store(&mut self, key_id: &str, key_type: &str, key_data: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(key_data)?;
        self.keys.insert(key_id.to_string(), (encrypted, key_type.to_string()));
        log::debug!("Stored key '{}' ({}) in software backend", key_id, key_type);
        Ok(())
    }

    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        let (encrypted, _) = self.keys.get(key_id)
            .ok_or_else(|| QsshError::Crypto(format!("Key '{}' not found", key_id)))?;
        self.decrypt(encrypted)
    }

    fn delete(&mut self, key_id: &str) -> Result<()> {
        if let Some((mut data, _)) = self.keys.remove(key_id) {
            data.zeroize();
            Ok(())
        } else {
            Err(QsshError::Crypto(format!("Key '{}' not found", key_id)))
        }
    }

    fn list(&self) -> Vec<KeyMetadata> {
        self.keys.iter().map(|(id, (encrypted, key_type))| KeyMetadata {
            key_id: id.clone(),
            key_type: key_type.clone(),
            size_bytes: encrypted.len().saturating_sub(12 + 16), // nonce + tag
            backend: "software".to_string(),
        }).collect()
    }

    fn exists(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    fn backend_name(&self) -> &str {
        "software"
    }
}

impl Drop for SoftwareBackend {
    fn drop(&mut self) {
        self.seal_key.zeroize();
    }
}

/// PKCS#11 HSM backend (stub implementation)
///
/// Returns clear errors explaining what's needed for real HSM integration.
/// Configure via environment variables: QSSH_HSM_PKCS11_LIB, _SLOT, _PIN
#[derive(Debug)]
pub struct Pkcs11Backend {
    library_path: String,
    slot_id: u64,
    /// Whether the HSM is initialized (would be true after login)
    initialized: bool,
}

impl Pkcs11Backend {
    /// Create a new PKCS#11 backend from configuration
    pub fn new(library_path: &str, slot_id: u64, _pin: &str) -> Result<Self> {
        log::info!("PKCS#11 HSM backend configured: lib={}, slot={}", library_path, slot_id);

        // Verify library exists
        if !Path::new(library_path).exists() {
            return Err(QsshError::Crypto(format!(
                "PKCS#11 library not found: {}. Install the HSM vendor's PKCS#11 driver.",
                library_path
            )));
        }

        Ok(Self {
            library_path: library_path.to_string(),
            slot_id,
            initialized: false,
        })
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self> {
        let lib = std::env::var("QSSH_HSM_PKCS11_LIB")
            .map_err(|_| QsshError::Crypto(
                "QSSH_HSM_PKCS11_LIB not set. Set to path of PKCS#11 .so/.dylib".into()
            ))?;
        let slot: u64 = std::env::var("QSSH_HSM_PKCS11_SLOT")
            .unwrap_or_else(|_| "0".to_string())
            .parse()
            .map_err(|_| QsshError::Crypto("Invalid QSSH_HSM_PKCS11_SLOT".into()))?;
        let pin = std::env::var("QSSH_HSM_PKCS11_PIN")
            .unwrap_or_default();

        Self::new(&lib, slot, &pin)
    }
}

impl KeyStorageBackend for Pkcs11Backend {
    fn store(&mut self, key_id: &str, key_type: &str, _key_data: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(QsshError::Crypto(format!(
                "PKCS#11 HSM not initialized. The PKCS#11 backend requires the vendor's \
                 driver library at '{}'. Real HSM integration needs: \
                 (1) C_Initialize, (2) C_OpenSession(slot={}), (3) C_Login, \
                 (4) C_CreateObject for key '{}'",
                self.library_path, self.slot_id, key_id
            )));
        }
        log::info!("HSM store: key_id={}, type={}", key_id, key_type);
        Err(QsshError::Crypto(
            "PKCS#11 key storage not yet implemented. Use software backend.".into()
        ))
    }

    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        Err(QsshError::Crypto(format!(
            "PKCS#11 key retrieval not yet implemented for key '{}'. \
             Real implementation would call C_FindObjects + C_GetAttributeValue. \
             Use software backend for now.",
            key_id
        )))
    }

    fn delete(&mut self, key_id: &str) -> Result<()> {
        Err(QsshError::Crypto(format!(
            "PKCS#11 key deletion not yet implemented for key '{}'. \
             Real implementation would call C_DestroyObject.",
            key_id
        )))
    }

    fn list(&self) -> Vec<KeyMetadata> {
        log::warn!("PKCS#11 key listing not yet implemented");
        Vec::new()
    }

    fn exists(&self, _key_id: &str) -> bool {
        false
    }

    fn backend_name(&self) -> &str {
        "pkcs11"
    }
}

/// File-based key storage (encrypted keys on disk)
pub struct FileBackend {
    key_dir: PathBuf,
    seal_key: [u8; 32],
}

impl FileBackend {
    /// Create with a directory path and seal key
    pub fn new(key_dir: PathBuf, seal_key: [u8; 32]) -> Result<Self> {
        // Create directory if it doesn't exist
        std::fs::create_dir_all(&key_dir)
            .map_err(|e| QsshError::Io(e))?;

        // Set restrictive permissions (owner-only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| QsshError::Io(e))?;
        }

        Ok(Self { key_dir, seal_key })
    }

    /// Create from environment variable
    pub fn from_env(seal_key: [u8; 32]) -> Result<Self> {
        let dir = std::env::var("QSSH_HSM_KEY_DIR")
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                format!("{}/.qssh/keys", home)
            });
        Self::new(PathBuf::from(dir), seal_key)
    }

    fn key_path(&self, key_id: &str) -> PathBuf {
        // Sanitize key_id to prevent path traversal
        let safe_id: String = key_id.chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        self.key_dir.join(format!("{}.key", safe_id))
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Nonce};
        use rand::RngCore;

        let cipher = Aes256Gcm::new_from_slice(&self.seal_key)
            .map_err(|e| QsshError::Crypto(format!("Cipher init: {}", e)))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| QsshError::Crypto(format!("Encryption: {}", e)))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};

        if encrypted.len() < 12 {
            return Err(QsshError::Crypto("Encrypted data too short".into()));
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.seal_key)
            .map_err(|e| QsshError::Crypto(format!("Cipher init: {}", e)))?;

        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| QsshError::Crypto(format!("Decryption: {}", e)))
    }
}

impl KeyStorageBackend for FileBackend {
    fn store(&mut self, key_id: &str, key_type: &str, key_data: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(key_data)?;

        // Store as: [key_type_len(2)][key_type][encrypted_data]
        let mut file_data = Vec::new();
        let type_bytes = key_type.as_bytes();
        file_data.extend_from_slice(&(type_bytes.len() as u16).to_be_bytes());
        file_data.extend_from_slice(type_bytes);
        file_data.extend_from_slice(&encrypted);

        let path = self.key_path(key_id);
        std::fs::write(&path, &file_data).map_err(QsshError::Io)?;

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(QsshError::Io)?;
        }

        log::debug!("Stored key '{}' ({}) to {:?}", key_id, key_type, path);
        Ok(())
    }

    fn retrieve(&self, key_id: &str) -> Result<Vec<u8>> {
        let path = self.key_path(key_id);
        let file_data = std::fs::read(&path)
            .map_err(|e| QsshError::Crypto(format!("Key file read failed: {}", e)))?;

        if file_data.len() < 2 {
            return Err(QsshError::Crypto("Invalid key file (too short)".into()));
        }

        let type_len = u16::from_be_bytes([file_data[0], file_data[1]]) as usize;
        if file_data.len() < 2 + type_len {
            return Err(QsshError::Crypto("Invalid key file (truncated type)".into()));
        }

        let encrypted = &file_data[2 + type_len..];
        self.decrypt(encrypted)
    }

    fn delete(&mut self, key_id: &str) -> Result<()> {
        let path = self.key_path(key_id);
        if path.exists() {
            // Overwrite with zeros before deleting
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if len > 0 {
                let zeros = vec![0u8; len as usize];
                let _ = std::fs::write(&path, &zeros);
            }
            std::fs::remove_file(&path).map_err(QsshError::Io)?;
            Ok(())
        } else {
            Err(QsshError::Crypto(format!("Key '{}' not found", key_id)))
        }
    }

    fn list(&self) -> Vec<KeyMetadata> {
        let mut results = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.key_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("key") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        let size = std::fs::metadata(&path)
                            .map(|m| m.len() as usize)
                            .unwrap_or(0);
                        results.push(KeyMetadata {
                            key_id: stem.to_string(),
                            key_type: "unknown".to_string(), // Would need to read header
                            size_bytes: size,
                            backend: "file".to_string(),
                        });
                    }
                }
            }
        }
        results
    }

    fn exists(&self, key_id: &str) -> bool {
        self.key_path(key_id).exists()
    }

    fn backend_name(&self) -> &str {
        "file"
    }
}

impl Drop for FileBackend {
    fn drop(&mut self) {
        self.seal_key.zeroize();
    }
}

/// Create a key storage backend from environment configuration
pub fn create_backend(seal_key: [u8; 32]) -> Result<Box<dyn KeyStorageBackend>> {
    let hsm_type = std::env::var("QSSH_HSM_TYPE")
        .unwrap_or_else(|_| "software".to_string());

    match hsm_type.as_str() {
        "software" => {
            log::info!("Using software key storage backend");
            Ok(Box::new(SoftwareBackend::new(seal_key)))
        }
        "pkcs11" => {
            log::info!("Using PKCS#11 HSM key storage backend");
            Ok(Box::new(Pkcs11Backend::from_env()?))
        }
        "file" => {
            log::info!("Using file-based key storage backend");
            Ok(Box::new(FileBackend::from_env(seal_key)?))
        }
        other => {
            Err(QsshError::Crypto(format!(
                "Unknown HSM type: '{}'. Valid options: software, pkcs11, file",
                other
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    fn test_seal_key() -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"test-seal-key-for-unit-tests");
        hasher.finalize().into()
    }

    #[test]
    fn test_software_backend_store_retrieve() {
        let mut backend = SoftwareBackend::new(test_seal_key());
        let key_data = b"super-secret-falcon-key-material";

        backend.store("falcon-1", "falcon", key_data).unwrap();
        assert!(backend.exists("falcon-1"));

        let retrieved = backend.retrieve("falcon-1").unwrap();
        assert_eq!(retrieved, key_data);
    }

    #[test]
    fn test_software_backend_delete() {
        let mut backend = SoftwareBackend::new(test_seal_key());
        backend.store("temp-key", "session", b"temporary").unwrap();
        assert!(backend.exists("temp-key"));

        backend.delete("temp-key").unwrap();
        assert!(!backend.exists("temp-key"));
        assert!(backend.retrieve("temp-key").is_err());
    }

    #[test]
    fn test_software_backend_list() {
        let mut backend = SoftwareBackend::new(test_seal_key());
        backend.store("key-a", "falcon", b"data-a").unwrap();
        backend.store("key-b", "sphincs", b"data-b").unwrap();

        let keys = backend.list();
        assert_eq!(keys.len(), 2);

        let ids: Vec<&str> = keys.iter().map(|k| k.key_id.as_str()).collect();
        assert!(ids.contains(&"key-a"));
        assert!(ids.contains(&"key-b"));
    }

    #[test]
    fn test_software_backend_retrieve_nonexistent() {
        let backend = SoftwareBackend::new(test_seal_key());
        assert!(backend.retrieve("nonexistent").is_err());
    }

    #[test]
    fn test_file_backend_store_retrieve() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut backend = FileBackend::new(tmp.path().to_path_buf(), test_seal_key()).unwrap();

        let key_data = b"pq-key-material-for-file-storage";
        backend.store("file-key", "falcon", key_data).unwrap();
        assert!(backend.exists("file-key"));

        let retrieved = backend.retrieve("file-key").unwrap();
        assert_eq!(retrieved, key_data);
    }

    #[test]
    fn test_file_backend_delete() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut backend = FileBackend::new(tmp.path().to_path_buf(), test_seal_key()).unwrap();

        backend.store("del-key", "session", b"to-delete").unwrap();
        assert!(backend.exists("del-key"));

        backend.delete("del-key").unwrap();
        assert!(!backend.exists("del-key"));
    }

    #[test]
    fn test_file_backend_list() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut backend = FileBackend::new(tmp.path().to_path_buf(), test_seal_key()).unwrap();

        backend.store("list-a", "falcon", b"a").unwrap();
        backend.store("list-b", "sphincs", b"b").unwrap();

        let keys = backend.list();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_file_backend_path_sanitization() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut backend = FileBackend::new(tmp.path().to_path_buf(), test_seal_key()).unwrap();

        // Path traversal attempts should be sanitized
        backend.store("../../../etc/shadow", "session", b"evil").unwrap();
        let path = backend.key_path("../../../etc/shadow");
        // The path should be within the key_dir, not at /etc/shadow
        assert!(path.starts_with(tmp.path()));
    }

    #[test]
    fn test_pkcs11_backend_returns_clear_errors() {
        // PKCS#11 from_env should fail without env vars
        let result = Pkcs11Backend::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("QSSH_HSM_PKCS11_LIB"));
    }

    #[test]
    fn test_create_backend_default() {
        // Default (no QSSH_HSM_TYPE set) should create software backend
        let backend = create_backend(test_seal_key()).unwrap();
        assert_eq!(backend.backend_name(), "software");
    }

    #[test]
    fn test_software_backend_wrong_seal_key() {
        let mut backend = SoftwareBackend::new(test_seal_key());
        backend.store("protected", "falcon", b"secret-data").unwrap();

        // Create a different backend with wrong seal key
        let mut wrong_key = [0u8; 32];
        wrong_key[0] = 0xff;
        let wrong_backend = SoftwareBackend {
            keys: backend.keys.clone(),
            seal_key: wrong_key,
        };

        // Should fail to decrypt
        assert!(wrong_backend.retrieve("protected").is_err());
    }
}
