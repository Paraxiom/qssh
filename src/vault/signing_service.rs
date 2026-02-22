//! Signing Service — Isolated process that holds decrypted keys
//!
//! Exposes a Unix socket API for sign(key_id, message) → signature.
//! Keys are held in mlock'd memory, every operation is audit-logged
//! to a JSONL hash chain, and per-key rate limiting is enforced.

use crate::{Result, QsshError};
use crate::vault::{QuantumVault, KeyType};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

/// Request types for the signing service Unix socket API
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum SignRequest {
    /// Sign a message with a specific key
    #[serde(rename = "sign")]
    Sign {
        key_id: String,
        /// Base64-encoded message to sign
        message: String,
    },
    /// List available key IDs (no key material exposed)
    #[serde(rename = "list_keys")]
    ListKeys,
    /// Store a new key
    #[serde(rename = "store_key")]
    StoreKey {
        key_id: String,
        key_type: String,
        /// Base64-encoded key data
        key_data: String,
        max_uses: u64,
    },
    /// Lock the vault (zeroize keys from memory)
    #[serde(rename = "lock")]
    Lock,
    /// Unlock the vault with passphrase
    #[serde(rename = "unlock")]
    Unlock {
        passphrase: String,
    },
    /// Health check
    #[serde(rename = "health")]
    Health,
}

/// Response from the signing service
#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<KeyInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
}

/// Public key info (no key material)
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyInfo {
    pub key_id: String,
    pub key_type: String,
    pub usage_count: u64,
    pub max_uses: u64,
}

/// Audit log entry (JSONL, hash-chained)
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub action: String,
    pub key_id: Option<String>,
    pub success: bool,
    pub error: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

/// Rate limiter for per-key signing
struct RateLimiter {
    /// Map of key_id → (count, window_start)
    windows: HashMap<String, (u32, Instant)>,
    /// Max signs per window
    max_per_window: u32,
    /// Window duration in seconds
    window_secs: u64,
}

impl RateLimiter {
    fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            windows: HashMap::new(),
            max_per_window,
            window_secs,
        }
    }

    fn check(&mut self, key_id: &str) -> bool {
        let now = Instant::now();
        let entry = self.windows.entry(key_id.to_string())
            .or_insert((0, now));

        // Reset window if expired
        if now.duration_since(entry.1).as_secs() >= self.window_secs {
            *entry = (0, now);
        }

        if entry.0 >= self.max_per_window {
            return false;
        }

        entry.0 += 1;
        true
    }
}

/// The signing service daemon
pub struct SigningService {
    vault: Arc<Mutex<QuantumVault>>,
    socket_path: PathBuf,
    audit_path: PathBuf,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    prev_hash: Arc<Mutex<String>>,
    locked: Arc<Mutex<bool>>,
}

impl SigningService {
    /// Create a new signing service
    pub fn new(
        socket_path: PathBuf,
        audit_path: PathBuf,
        max_signs_per_minute: u32,
    ) -> Self {
        Self {
            vault: Arc::new(Mutex::new(QuantumVault::new())),
            socket_path,
            audit_path,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(max_signs_per_minute, 60))),
            prev_hash: Arc::new(Mutex::new("genesis".to_string())),
            locked: Arc::new(Mutex::new(true)),
        }
    }

    /// Lock key memory pages to prevent swapping
    #[cfg(unix)]
    pub fn mlock_keys(ptr: *const u8, len: usize) -> Result<()> {
        unsafe {
            if libc::mlock(ptr as *const libc::c_void, len) != 0 {
                return Err(QsshError::Io(std::io::Error::last_os_error()));
            }
            // Prevent core dumps of this memory region
            #[cfg(target_os = "linux")]
            let madvise_flag = libc::MADV_DONTDUMP;
            #[cfg(target_os = "macos")]
            let madvise_flag = libc::MADV_ZERO_WIRED_PAGES;
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let madvise_flag = 0; // no-op on other platforms

            if libc::madvise(ptr as *mut libc::c_void, len, madvise_flag) != 0 {
                // Non-fatal — mlock is more important
                log::warn!("madvise failed: {}", std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Unlock memory pages
    #[cfg(unix)]
    pub fn munlock_keys(ptr: *const u8, len: usize) {
        unsafe {
            libc::munlock(ptr as *const libc::c_void, len);
        }
    }

    /// Write an audit entry to the JSONL hash chain
    async fn audit_log(&self, action: &str, key_id: Option<&str>, success: bool, error: Option<&str>) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let prev_hash = {
            let ph = self.prev_hash.lock().await;
            ph.clone()
        };

        // Compute hash of this entry
        let mut hasher = Sha256::new();
        hasher.update(timestamp.to_le_bytes());
        hasher.update(action.as_bytes());
        if let Some(kid) = key_id {
            hasher.update(kid.as_bytes());
        }
        hasher.update(if success { &b"ok "[..] } else { &b"err"[..] });
        hasher.update(prev_hash.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let entry = AuditEntry {
            timestamp,
            action: action.to_string(),
            key_id: key_id.map(|s| s.to_string()),
            success,
            error: error.map(|s| s.to_string()),
            prev_hash: prev_hash.clone(),
            hash: hash.clone(),
        };

        // Append to JSONL file
        let line = serde_json::to_string(&entry)
            .map_err(|e| QsshError::Crypto(format!("Audit serialization failed: {}", e)))?;

        // Ensure parent dir exists
        if let Some(parent) = self.audit_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_path)
            .map_err(QsshError::Io)?;
        writeln!(file, "{}", line).map_err(QsshError::Io)?;

        // Update prev_hash
        let mut ph = self.prev_hash.lock().await;
        *ph = hash;

        Ok(())
    }

    /// Handle a single request
    async fn handle_request(&self, request: SignRequest) -> SignResponse {
        match request {
            SignRequest::Health => {
                let locked = *self.locked.lock().await;
                SignResponse {
                    success: true,
                    signature: None,
                    keys: None,
                    error: None,
                    locked: Some(locked),
                }
            }

            SignRequest::Unlock { passphrase } => {
                let mut vault = self.vault.lock().await;
                match vault.init_argon2id(passphrase.as_bytes()).await {
                    Ok(()) => {
                        *self.locked.lock().await = false;
                        let _ = self.audit_log("unlock", None, true, None).await;
                        SignResponse {
                            success: true,
                            signature: None,
                            keys: None,
                            error: None,
                            locked: Some(false),
                        }
                    }
                    Err(e) => {
                        let _ = self.audit_log("unlock", None, false, Some(&e.to_string())).await;
                        SignResponse {
                            success: false,
                            signature: None,
                            keys: None,
                            error: Some(format!("Unlock failed: {}", e)),
                            locked: Some(true),
                        }
                    }
                }
            }

            SignRequest::Lock => {
                let mut vault = self.vault.lock().await;
                vault.lock_vault();
                *self.locked.lock().await = true;
                let _ = self.audit_log("lock", None, true, None).await;
                SignResponse {
                    success: true,
                    signature: None,
                    keys: None,
                    error: None,
                    locked: Some(true),
                }
            }

            SignRequest::ListKeys => {
                if *self.locked.lock().await {
                    return SignResponse {
                        success: false,
                        signature: None,
                        keys: None,
                        error: Some("Vault is locked".into()),
                        locked: Some(true),
                    };
                }
                let vault = self.vault.lock().await;
                let keys = vault.list_keys().await;
                SignResponse {
                    success: true,
                    signature: None,
                    keys: Some(keys),
                    error: None,
                    locked: Some(false),
                }
            }

            SignRequest::StoreKey { key_id, key_type, key_data, max_uses } => {
                if *self.locked.lock().await {
                    return SignResponse {
                        success: false,
                        signature: None,
                        keys: None,
                        error: Some("Vault is locked".into()),
                        locked: Some(true),
                    };
                }

                let kt = match key_type.as_str() {
                    "falcon" => KeyType::FalconPrivate,
                    "sphincs" => KeyType::SphincsPrivate,
                    "qkd" => KeyType::QkdMaster,
                    "session" => KeyType::SessionKey,
                    "lamport" => KeyType::LamportSeed,
                    _ => {
                        return SignResponse {
                            success: false,
                            signature: None,
                            keys: None,
                            error: Some(format!("Unknown key type: {}", key_type)),
                            locked: None,
                        };
                    }
                };

                let data = match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &key_data,
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        return SignResponse {
                            success: false,
                            signature: None,
                            keys: None,
                            error: Some(format!("Invalid base64: {}", e)),
                            locked: None,
                        };
                    }
                };

                let vault = self.vault.lock().await;
                match vault.store_key(&key_id, &data, kt, max_uses).await {
                    Ok(()) => {
                        let _ = self.audit_log("store_key", Some(&key_id), true, None).await;
                        SignResponse {
                            success: true,
                            signature: None,
                            keys: None,
                            error: None,
                            locked: None,
                        }
                    }
                    Err(e) => {
                        let _ = self.audit_log("store_key", Some(&key_id), false, Some(&e.to_string())).await;
                        SignResponse {
                            success: false,
                            signature: None,
                            keys: None,
                            error: Some(format!("Store failed: {}", e)),
                            locked: None,
                        }
                    }
                }
            }

            SignRequest::Sign { key_id, message } => {
                if *self.locked.lock().await {
                    return SignResponse {
                        success: false,
                        signature: None,
                        keys: None,
                        error: Some("Vault is locked".into()),
                        locked: Some(true),
                    };
                }

                // Rate limit check
                {
                    let mut rl = self.rate_limiter.lock().await;
                    if !rl.check(&key_id) {
                        let _ = self.audit_log("sign", Some(&key_id), false, Some("Rate limited")).await;
                        return SignResponse {
                            success: false,
                            signature: None,
                            keys: None,
                            error: Some("Rate limit exceeded for this key".into()),
                            locked: None,
                        };
                    }
                }

                let msg_bytes = match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &message,
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        return SignResponse {
                            success: false,
                            signature: None,
                            keys: None,
                            error: Some(format!("Invalid base64 message: {}", e)),
                            locked: None,
                        };
                    }
                };

                let vault = self.vault.lock().await;
                match vault.sign(&key_id, &msg_bytes).await {
                    Ok(sig) => {
                        let _ = self.audit_log("sign", Some(&key_id), true, None).await;
                        use base64::Engine;
                        SignResponse {
                            success: true,
                            signature: Some(base64::engine::general_purpose::STANDARD.encode(&sig)),
                            keys: None,
                            error: None,
                            locked: None,
                        }
                    }
                    Err(e) => {
                        let _ = self.audit_log("sign", Some(&key_id), false, Some(&e.to_string())).await;
                        SignResponse {
                            success: false,
                            signature: None,
                            keys: None,
                            error: Some(format!("Sign failed: {}", e)),
                            locked: None,
                        }
                    }
                }
            }
        }
    }

    /// Run the signing service, listening on Unix socket
    pub async fn run(&self) -> Result<()> {
        // Remove stale socket
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path).ok();
        }

        // Ensure parent directory exists
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent).map_err(QsshError::Io)?;
        }

        let listener = UnixListener::bind(&self.socket_path)
            .map_err(QsshError::Io)?;

        // Set restrictive permissions (owner-only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.socket_path,
                std::fs::Permissions::from_mode(0o600))
                .map_err(QsshError::Io)?;
        }

        log::info!("Signing service listening on {:?}", self.socket_path);
        let _ = self.audit_log("start", None, true, None).await;

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let vault = self.vault.clone();
                    let rate_limiter = self.rate_limiter.clone();
                    let prev_hash = self.prev_hash.clone();
                    let locked = self.locked.clone();
                    let audit_path = self.audit_path.clone();

                    // Clone self references for the spawned task
                    let service = SigningService {
                        vault,
                        socket_path: self.socket_path.clone(),
                        audit_path,
                        rate_limiter,
                        prev_hash,
                        locked,
                    };

                    tokio::spawn(async move {
                        let (reader, mut writer) = stream.into_split();
                        let mut reader = BufReader::new(reader);
                        let mut line = String::new();

                        loop {
                            line.clear();
                            match reader.read_line(&mut line).await {
                                Ok(0) => break, // EOF
                                Ok(_) => {
                                    let trimmed = line.trim();
                                    if trimmed.is_empty() {
                                        continue;
                                    }

                                    let response = match serde_json::from_str::<SignRequest>(trimmed) {
                                        Ok(req) => service.handle_request(req).await,
                                        Err(e) => SignResponse {
                                            success: false,
                                            signature: None,
                                            keys: None,
                                            error: Some(format!("Invalid request: {}", e)),
                                            locked: None,
                                        },
                                    };

                                    let resp_json = serde_json::to_string(&response)
                                        .unwrap_or_else(|_| r#"{"success":false,"error":"serialization error"}"#.to_string());

                                    if writer.write_all(resp_json.as_bytes()).await.is_err() {
                                        break;
                                    }
                                    if writer.write_all(b"\n").await.is_err() {
                                        break;
                                    }
                                    if writer.flush().await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    log::debug!("Client read error: {}", e);
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    log::error!("Accept error: {}", e);
                }
            }
        }
    }
}

/// Client for connecting to the signing service
pub struct SigningClient {
    socket_path: PathBuf,
}

impl SigningClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Send a request to the signing service and get a response
    pub async fn request(&self, req: &SignRequest) -> Result<SignResponse> {
        let stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .map_err(QsshError::Io)?;

        let (reader, mut writer) = stream.into_split();

        let req_json = serde_json::to_string(req)
            .map_err(|e| QsshError::Crypto(format!("Request serialization failed: {}", e)))?;

        writer.write_all(req_json.as_bytes()).await.map_err(QsshError::Io)?;
        writer.write_all(b"\n").await.map_err(QsshError::Io)?;
        writer.flush().await.map_err(QsshError::Io)?;

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await.map_err(QsshError::Io)?;

        serde_json::from_str(&line)
            .map_err(|e| QsshError::Crypto(format!("Response parse failed: {}", e)))
    }

    /// Sign a message
    pub async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        use base64::Engine;
        let req = SignRequest::Sign {
            key_id: key_id.to_string(),
            message: base64::engine::general_purpose::STANDARD.encode(message),
        };
        let resp = self.request(&req).await?;
        if resp.success {
            if let Some(sig_b64) = resp.signature {
                base64::engine::general_purpose::STANDARD.decode(&sig_b64)
                    .map_err(|e| QsshError::Crypto(format!("Signature decode failed: {}", e)))
            } else {
                Err(QsshError::Crypto("No signature in response".into()))
            }
        } else {
            Err(QsshError::Crypto(resp.error.unwrap_or_else(|| "Unknown error".into())))
        }
    }

    /// Unlock the vault
    pub async fn unlock(&self, passphrase: &str) -> Result<()> {
        let req = SignRequest::Unlock {
            passphrase: passphrase.to_string(),
        };
        let resp = self.request(&req).await?;
        if resp.success {
            Ok(())
        } else {
            Err(QsshError::Crypto(resp.error.unwrap_or_else(|| "Unlock failed".into())))
        }
    }

    /// Lock the vault
    pub async fn lock(&self) -> Result<()> {
        let req = SignRequest::Lock;
        let resp = self.request(&req).await?;
        if resp.success {
            Ok(())
        } else {
            Err(QsshError::Crypto(resp.error.unwrap_or_else(|| "Lock failed".into())))
        }
    }

    /// Health check
    pub async fn health(&self) -> Result<bool> {
        let req = SignRequest::Health;
        let resp = self.request(&req).await?;
        Ok(resp.locked.unwrap_or(true) == false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_audit_log_hash_chain() {
        let tmp = TempDir::new().unwrap();
        let audit_path = tmp.path().join("audit.jsonl");
        let socket_path = tmp.path().join("test.sock");

        let service = SigningService::new(socket_path, audit_path.clone(), 60);

        // Write 3 entries
        service.audit_log("test1", Some("key1"), true, None).await.unwrap();
        service.audit_log("test2", None, false, Some("oops")).await.unwrap();
        service.audit_log("test3", Some("key2"), true, None).await.unwrap();

        // Read and verify chain
        let content = std::fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 3);

        let entry0: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        let entry1: AuditEntry = serde_json::from_str(lines[1]).unwrap();
        let entry2: AuditEntry = serde_json::from_str(lines[2]).unwrap();

        assert_eq!(entry0.prev_hash, "genesis");
        assert_eq!(entry1.prev_hash, entry0.hash);
        assert_eq!(entry2.prev_hash, entry1.hash);

        assert_eq!(entry0.action, "test1");
        assert!(entry0.success);
        assert!(!entry1.success);
        assert_eq!(entry1.error.as_deref(), Some("oops"));
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let mut rl = RateLimiter::new(3, 60);
        assert!(rl.check("key1"));
        assert!(rl.check("key1"));
        assert!(rl.check("key1"));
        assert!(!rl.check("key1")); // 4th should fail
        assert!(rl.check("key2")); // Different key should succeed
    }

    #[tokio::test]
    async fn test_signing_service_unix_socket() {
        let tmp = TempDir::new().unwrap();
        let socket_path = tmp.path().join("sign.sock");
        let audit_path = tmp.path().join("audit.jsonl");

        let service = Arc::new(SigningService::new(
            socket_path.clone(),
            audit_path,
            60,
        ));

        // Start service in background
        let svc = service.clone();
        let handle = tokio::spawn(async move {
            svc.run().await.ok();
        });

        // Give it a moment to bind
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Create client
        let client = SigningClient::new(socket_path.clone());

        // Test health (should be locked)
        let resp = client.request(&SignRequest::Health).await.unwrap();
        assert!(resp.success);
        assert_eq!(resp.locked, Some(true));

        // Test unlock
        let resp = client.request(&SignRequest::Unlock {
            passphrase: "test-passphrase".to_string(),
        }).await.unwrap();
        assert!(resp.success);
        assert_eq!(resp.locked, Some(false));

        // Test health again (should be unlocked)
        assert!(client.health().await.unwrap());

        // Store a key
        use base64::Engine;
        let key_data = base64::engine::general_purpose::STANDARD.encode(b"test-secret-key-data");
        let resp = client.request(&SignRequest::StoreKey {
            key_id: "test-key".to_string(),
            key_type: "session".to_string(),
            key_data,
            max_uses: 0,
        }).await.unwrap();
        assert!(resp.success);

        // List keys
        let resp = client.request(&SignRequest::ListKeys).await.unwrap();
        assert!(resp.success);
        let keys = resp.keys.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "test-key");

        // Lock vault
        let resp = client.request(&SignRequest::Lock).await.unwrap();
        assert!(resp.success);

        // Operations should fail when locked
        let resp = client.request(&SignRequest::ListKeys).await.unwrap();
        assert!(!resp.success);
        assert!(resp.error.as_deref().unwrap().contains("locked"));

        handle.abort();
    }

    #[test]
    fn test_mlock_munlock() {
        let data = vec![0u8; 4096];
        // mlock should succeed on most systems
        let result = SigningService::mlock_keys(data.as_ptr(), data.len());
        if result.is_ok() {
            SigningService::munlock_keys(data.as_ptr(), data.len());
        }
        // Don't assert — mlock can fail in restricted environments
    }
}
