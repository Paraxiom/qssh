//! QSSH Agent - Post-quantum SSH agent implementation
//!
//! Provides key management and signing services for QSSH clients

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use crate::{Result, QsshError, PqAlgorithm};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
mod tests;

/// Agent protocol version
pub const AGENT_PROTOCOL_VERSION: u8 = 1;

/// Agent protocol messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMessage {
    /// Request agent version
    RequestVersion,
    /// Response with version
    Version(u8),

    /// Add a key to the agent
    AddKey {
        algorithm: PqAlgorithm,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        comment: String,
        lifetime: Option<u32>, // seconds, 0 = forever
    },
    /// Key added successfully
    KeyAdded,

    /// Remove a key from the agent
    RemoveKey {
        public_key: Vec<u8>,
    },
    /// Key removed successfully
    KeyRemoved,

    /// Remove all keys
    RemoveAllKeys,
    /// All keys removed
    AllKeysRemoved,

    /// List all keys in agent
    ListKeys,
    /// Response with key list
    KeyList(Vec<KeyInfo>),

    /// Request signature
    SignRequest {
        public_key: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    },
    /// Response with signature
    SignResponse {
        signature: Vec<u8>,
    },

    /// Lock agent with passphrase
    Lock {
        passphrase: String,
    },
    /// Agent locked
    Locked,

    /// Unlock agent with passphrase
    Unlock {
        passphrase: String,
    },
    /// Agent unlocked
    Unlocked,

    /// Error response
    Error(String),
}

/// Information about a key in the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub algorithm: PqAlgorithm,
    pub public_key: Vec<u8>,
    pub comment: String,
    pub fingerprint: String,
    pub added_at: u64, // Unix timestamp
    pub expires_at: Option<u64>, // Unix timestamp
}

/// Agent response messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentResponse {
    Success,
    KeyList(Vec<KeyInfo>),
    SignResponse { signature: Vec<u8> },
    Error(String),
}

/// A key stored in the agent
struct StoredKey {
    algorithm: PqAlgorithm,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    comment: String,
    added_at: std::time::SystemTime,
    lifetime: Option<std::time::Duration>,
}

/// QSSH Agent daemon
#[derive(Clone)]
pub struct QsshAgent {
    /// Stored keys
    keys: Arc<RwLock<HashMap<Vec<u8>, StoredKey>>>, // indexed by public key
    /// Socket path
    socket_path: PathBuf,
    /// Lock passphrase (if locked)
    lock_passphrase: Arc<RwLock<Option<String>>>,
    /// Maximum number of keys
    max_keys: usize,
}

impl QsshAgent {
    /// Create new agent
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            socket_path,
            lock_passphrase: Arc::new(RwLock::new(None)),
            max_keys: 100,
        }
    }

    /// Start the agent daemon
    pub async fn start(&self) -> Result<()> {
        // Remove existing socket
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        // Create socket directory if needed
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Bind to Unix socket
        let listener = UnixListener::bind(&self.socket_path)?;

        // Set socket permissions (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.socket_path, permissions)?;
        }

        log::info!("QSSH Agent listening on {:?}", self.socket_path);

        // Accept connections
        loop {
            let (stream, _) = listener.accept().await?;
            let keys = self.keys.clone();
            let lock_passphrase = self.lock_passphrase.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, keys, lock_passphrase).await {
                    log::error!("Client handler error: {}", e);
                }
            });
        }
    }

    /// Add a key to the agent
    pub async fn add_key(
        &self,
        algorithm: PqAlgorithm,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        comment: String,
        lifetime: Option<u32>,
    ) -> Result<()> {
        // Check if locked
        if self.lock_passphrase.read().await.is_some() {
            return Err(QsshError::Protocol("Agent is locked".into()));
        }

        let mut keys = self.keys.write().await;

        // Check key limit
        if keys.len() >= self.max_keys {
            return Err(QsshError::Protocol("Maximum number of keys reached".into()));
        }

        // Store the key
        let stored_key = StoredKey {
            algorithm,
            private_key,
            public_key: public_key.clone(),
            comment,
            added_at: std::time::SystemTime::now(),
            lifetime: lifetime.map(|s| std::time::Duration::from_secs(s as u64)),
        };

        keys.insert(public_key, stored_key);

        Ok(())
    }

    /// Remove expired keys
    pub async fn cleanup_expired_keys(&self) {
        let mut keys = self.keys.write().await;
        let now = std::time::SystemTime::now();

        keys.retain(|_, key| {
            if let Some(lifetime) = key.lifetime {
                if let Ok(elapsed) = now.duration_since(key.added_at) {
                    return elapsed < lifetime;
                }
            }
            true
        });
    }

    /// Sign data with a key
    pub async fn sign(&self, public_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        // Check if locked
        if self.lock_passphrase.read().await.is_some() {
            return Err(QsshError::Protocol("Agent is locked".into()));
        }

        let keys = self.keys.read().await;

        let key = keys.get(public_key)
            .ok_or_else(|| QsshError::Protocol("Key not found in agent".into()))?;

        // Delegate to the standalone sign_with_key function
        sign_with_key(&key, data).await
    }

    /// List all keys in the agent
    pub async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        // Check if locked
        if self.lock_passphrase.read().await.is_some() {
            return Err(QsshError::Protocol("Agent is locked".into()));
        }

        let keys = self.keys.read().await;
        let mut key_list = Vec::new();

        for (public_key, stored_key) in keys.iter() {
            let info = KeyInfo {
                algorithm: stored_key.algorithm.clone(),
                public_key: public_key.clone(),
                comment: stored_key.comment.clone(),
                fingerprint: compute_fingerprint(public_key),
                added_at: stored_key.added_at.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0),
                expires_at: stored_key.lifetime.map(|lifetime| {
                    stored_key.added_at.duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() + lifetime.as_secs()).unwrap_or(0)
                }),
            };
            key_list.push(info);
        }

        Ok(key_list)
    }

    /// Remove a specific key from the agent
    pub async fn remove_key(&self, public_key: Vec<u8>) -> Result<()> {
        // Check if locked
        if self.lock_passphrase.read().await.is_some() {
            return Err(QsshError::Protocol("Agent is locked".into()));
        }

        let mut keys = self.keys.write().await;

        if keys.remove(&public_key).is_none() {
            return Err(QsshError::Protocol("Key not found".into()));
        }

        Ok(())
    }

    /// Remove all keys from the agent
    pub async fn remove_all_keys(&self) -> Result<()> {
        // Check if locked
        if self.lock_passphrase.read().await.is_some() {
            return Err(QsshError::Protocol("Agent is locked".into()));
        }

        let mut keys = self.keys.write().await;
        keys.clear();

        Ok(())
    }

    /// Lock the agent with a passphrase
    pub async fn lock(&self, passphrase: String) -> Result<()> {
        let mut lock = self.lock_passphrase.write().await;

        if lock.is_some() {
            return Err(QsshError::Protocol("Agent already locked".into()));
        }

        *lock = Some(passphrase);
        Ok(())
    }

    /// Unlock the agent with the passphrase
    pub async fn unlock(&self, passphrase: String) -> Result<()> {
        let mut lock = self.lock_passphrase.write().await;

        match lock.as_ref() {
            None => return Err(QsshError::Protocol("Agent not locked".into())),
            Some(stored) if stored != &passphrase => {
                return Err(QsshError::Protocol("Invalid passphrase".into()));
            }
            _ => {}
        }

        *lock = None;
        Ok(())
    }

    /// Sign with a specific key (helper for tests)
    pub async fn sign_with_key(&self, public_key: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>> {
        self.sign(&public_key, &data).await
    }

    /// Handle agent protocol messages (for testing)
    pub async fn handle_message(&self, message: AgentMessage) -> Result<AgentResponse> {
        match message {
            AgentMessage::ListKeys => {
                let keys = self.list_keys().await?;
                Ok(AgentResponse::KeyList(keys))
            },
            AgentMessage::AddKey { algorithm, private_key, public_key, comment, lifetime } => {
                self.add_key(algorithm, private_key, public_key, comment, lifetime).await?;
                Ok(AgentResponse::Success)
            },
            AgentMessage::RemoveKey { public_key } => {
                self.remove_key(public_key).await?;
                Ok(AgentResponse::Success)
            },
            AgentMessage::RemoveAllKeys => {
                self.remove_all_keys().await?;
                Ok(AgentResponse::Success)
            },
            AgentMessage::Lock { passphrase } => {
                self.lock(passphrase).await?;
                Ok(AgentResponse::Success)
            },
            AgentMessage::Unlock { passphrase } => {
                self.unlock(passphrase).await?;
                Ok(AgentResponse::Success)
            },
            AgentMessage::SignRequest { public_key, data, .. } => {
                let signature = self.sign_with_key(public_key, data).await?;
                Ok(AgentResponse::SignResponse { signature })
            },
            _ => Err(QsshError::Protocol("Unsupported message".into())),
        }
    }
}

/// Handle a client connection
async fn handle_client(
    mut stream: UnixStream,
    keys: Arc<RwLock<HashMap<Vec<u8>, StoredKey>>>,
    lock_passphrase: Arc<RwLock<Option<String>>>,
) -> Result<()> {
    let mut buffer = vec![0u8; 65536];

    loop {
        // Read message length (4 bytes)
        let n = stream.read(&mut buffer[..4]).await?;
        if n == 0 {
            break; // Connection closed
        }

        let msg_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

        // Read message
        let n = stream.read(&mut buffer[..msg_len]).await?;
        if n != msg_len {
            return Err(QsshError::Protocol("Incomplete message".into()));
        }

        // Parse message
        let request: AgentMessage = bincode::deserialize(&buffer[..msg_len])
            .map_err(|e| QsshError::Protocol(format!("Failed to parse message: {}", e)))?;

        // Handle request
        let response = handle_request(request, &keys, &lock_passphrase).await?;

        // Send response
        let response_bytes = bincode::serialize(&response)
            .map_err(|e| QsshError::Protocol(format!("Failed to serialize response: {}", e)))?;

        let len_bytes = (response_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&response_bytes).await?;
    }

    Ok(())
}

/// Handle an agent request
async fn handle_request(
    request: AgentMessage,
    keys: &Arc<RwLock<HashMap<Vec<u8>, StoredKey>>>,
    lock_passphrase: &Arc<RwLock<Option<String>>>,
) -> Result<AgentMessage> {
    match request {
        AgentMessage::RequestVersion => {
            Ok(AgentMessage::Version(AGENT_PROTOCOL_VERSION))
        }

        AgentMessage::ListKeys => {
            if lock_passphrase.read().await.is_some() {
                return Ok(AgentMessage::Error("Agent is locked".into()));
            }

            let keys = keys.read().await;
            let key_list: Vec<KeyInfo> = keys.values().map(|key| {
                KeyInfo {
                    algorithm: key.algorithm,
                    public_key: key.public_key.clone(),
                    comment: key.comment.clone(),
                    fingerprint: compute_fingerprint(&key.public_key),
                    added_at: key.added_at.duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default().as_secs(),
                    expires_at: key.lifetime.map(|d| {
                        key.added_at.duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default().as_secs() + d.as_secs()
                    }),
                }
            }).collect();

            Ok(AgentMessage::KeyList(key_list))
        }

        AgentMessage::AddKey { algorithm, private_key, public_key, comment, lifetime } => {
            if lock_passphrase.read().await.is_some() {
                return Ok(AgentMessage::Error("Agent is locked".into()));
            }

            let stored_key = StoredKey {
                algorithm,
                private_key,
                public_key: public_key.clone(),
                comment,
                added_at: std::time::SystemTime::now(),
                lifetime: lifetime.map(|s| std::time::Duration::from_secs(s as u64)),
            };

            keys.write().await.insert(public_key, stored_key);
            Ok(AgentMessage::KeyAdded)
        }

        AgentMessage::RemoveKey { public_key } => {
            if lock_passphrase.read().await.is_some() {
                return Ok(AgentMessage::Error("Agent is locked".into()));
            }

            keys.write().await.remove(&public_key);
            Ok(AgentMessage::KeyRemoved)
        }

        AgentMessage::RemoveAllKeys => {
            if lock_passphrase.read().await.is_some() {
                return Ok(AgentMessage::Error("Agent is locked".into()));
            }

            keys.write().await.clear();
            Ok(AgentMessage::AllKeysRemoved)
        }

        AgentMessage::SignRequest { public_key, data, .. } => {
            if lock_passphrase.read().await.is_some() {
                return Ok(AgentMessage::Error("Agent is locked".into()));
            }

            let keys = keys.read().await;
            let key = keys.get(&public_key)
                .ok_or_else(|| QsshError::Protocol("Key not found".into()))?;

            let signature = sign_with_key(key, &data).await?;
            Ok(AgentMessage::SignResponse { signature })
        }

        AgentMessage::Lock { passphrase } => {
            *lock_passphrase.write().await = Some(passphrase);
            Ok(AgentMessage::Locked)
        }

        AgentMessage::Unlock { passphrase } => {
            let lock = lock_passphrase.read().await;
            if let Some(ref stored) = *lock {
                if stored == &passphrase {
                    drop(lock);
                    *lock_passphrase.write().await = None;
                    Ok(AgentMessage::Unlocked)
                } else {
                    Ok(AgentMessage::Error("Invalid passphrase".into()))
                }
            } else {
                Ok(AgentMessage::Error("Agent not locked".into()))
            }
        }

        _ => Ok(AgentMessage::Error("Unsupported operation".into())),
    }
}

/// Sign data with a stored key
async fn sign_with_key(key: &StoredKey, data: &[u8]) -> Result<Vec<u8>> {
    match key.algorithm {
        PqAlgorithm::Falcon512 => {
            use pqcrypto_falcon::falcon512;
            use pqcrypto_traits::sign::{SecretKey as SecretKeyTrait, SignedMessage as SignedMessageTrait};

            // Reconstruct secret key from bytes
            let sk_bytes: [u8; falcon512::secret_key_bytes()] = key.private_key[..falcon512::secret_key_bytes()]
                .try_into()
                .map_err(|_| QsshError::Crypto("Invalid Falcon key size".into()))?;
            let sk = falcon512::SecretKey::from_bytes(&sk_bytes)
                .map_err(|_| QsshError::Crypto("Invalid Falcon key".into()))?;

            let signature = falcon512::sign(data, &sk);
            Ok(signature.as_bytes().to_vec())
        }
        PqAlgorithm::SphincsPlus => {
            use pqcrypto_sphincsplus::sphincssha256128ssimple as sphincs;
            use pqcrypto_traits::sign::{SecretKey as SecretKeyTrait, SignedMessage as SignedMessageTrait};

            // Reconstruct secret key from bytes
            let sk_bytes: Vec<u8> = key.private_key.clone();
            let sk = sphincs::SecretKey::from_bytes(&sk_bytes[..sphincs::secret_key_bytes()])
                .map_err(|_| QsshError::Crypto("Invalid SPHINCS+ key".into()))?;

            let signature = sphincs::sign(data, &sk);
            Ok(signature.as_bytes().to_vec())
        }
        _ => Err(QsshError::Protocol("Unsupported algorithm".into())),
    }
}

/// Compute fingerprint of a public key
fn compute_fingerprint(public_key: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let result = hasher.finalize();

    // Format as colon-separated hex
    result.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|chunk| chunk.join(""))
        .collect::<Vec<_>>()
        .join(":")
}

/// Agent client for communicating with the agent
pub struct AgentClient {
    socket_path: PathBuf,
}

impl AgentClient {
    /// Create new agent client
    pub fn new() -> Self {
        let socket_path = std::env::var("QSSH_AUTH_SOCK")
            .unwrap_or_else(|_| format!("/tmp/qssh-agent-{}", std::process::id()));

        Self {
            socket_path: PathBuf::from(socket_path),
        }
    }

    /// Create client with custom socket path
    pub fn with_socket(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Connect to the agent
    pub async fn connect(&self) -> Result<UnixStream> {
        UnixStream::connect(&self.socket_path).await
            .map_err(|e| QsshError::Connection(format!("Failed to connect to agent: {}", e)))
    }

    /// Send a request and get response
    pub async fn request(&self, msg: AgentMessage) -> Result<AgentMessage> {
        let mut stream = self.connect().await?;

        // Serialize message
        let msg_bytes = bincode::serialize(&msg)
            .map_err(|e| QsshError::Protocol(format!("Failed to serialize: {}", e)))?;

        // Send length and message
        let len_bytes = (msg_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&msg_bytes).await?;

        // Read response length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u32::from_be_bytes(len_buf) as usize;

        // Read response
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;

        // Parse response
        bincode::deserialize(&resp_buf)
            .map_err(|e| QsshError::Protocol(format!("Failed to deserialize: {}", e)))
    }

    /// List keys in agent
    pub async fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        match self.request(AgentMessage::ListKeys).await? {
            AgentMessage::KeyList(keys) => Ok(keys),
            AgentMessage::Error(e) => Err(QsshError::Protocol(e)),
            _ => Err(QsshError::Protocol("Unexpected response".into())),
        }
    }

    /// Add a key to the agent
    pub async fn add_key(
        &self,
        algorithm: PqAlgorithm,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        comment: String,
        lifetime: Option<u32>,
    ) -> Result<()> {
        match self.request(AgentMessage::AddKey {
            algorithm,
            private_key,
            public_key,
            comment,
            lifetime,
        }).await? {
            AgentMessage::KeyAdded => Ok(()),
            AgentMessage::Error(e) => Err(QsshError::Protocol(e)),
            _ => Err(QsshError::Protocol("Unexpected response".into())),
        }
    }

    /// Request signature from agent
    pub async fn sign(&self, public_key: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>> {
        match self.request(AgentMessage::SignRequest {
            public_key,
            data,
            flags: 0,
        }).await? {
            AgentMessage::SignResponse { signature } => Ok(signature),
            AgentMessage::Error(e) => Err(QsshError::Protocol(e)),
            _ => Err(QsshError::Protocol("Unexpected response".into())),
        }
    }
}