//! Session Resumption Support
//!
//! Implements session caching and fast reconnection for mobile and unstable networks

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use tokio::sync::RwLock;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use crate::{Result, QsshError, PqAlgorithm};
use sha2::{Sha256, Digest};
use rand::Rng;

/// Session resumption ticket
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTicket {
    /// Unique session ID
    pub session_id: String,
    /// Server identifier
    pub server_id: String,
    /// Username
    pub username: String,
    /// Timestamp when ticket was issued
    pub issued_at: u64,
    /// Ticket lifetime in seconds
    pub lifetime: u64,
    /// Encrypted session state
    pub encrypted_state: Vec<u8>,
    /// Post-quantum algorithm used
    pub pq_algorithm: PqAlgorithm,
    /// Session keys (encrypted)
    pub session_keys: EncryptedKeys,
    /// Nonce for encryption
    pub nonce: Vec<u8>,
    /// Signature for authenticity
    pub signature: Vec<u8>,
}

/// Encrypted session keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeys {
    /// Encrypted symmetric key
    pub symmetric_key: Vec<u8>,
    /// Encrypted MAC key
    pub mac_key: Vec<u8>,
    /// Key derivation salt
    pub salt: Vec<u8>,
}

/// Session state for resumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Cipher suite in use
    pub cipher_suite: String,
    /// Compression algorithm
    pub compression: String,
    /// Active port forwards
    pub port_forwards: Vec<String>,
    /// Environment variables
    pub environment: HashMap<String, String>,
    /// Terminal settings
    pub terminal: Option<TerminalState>,
    /// X11 forwarding state
    pub x11_forwarding: bool,
    /// Agent forwarding state
    pub agent_forwarding: bool,
}

/// Terminal state for session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalState {
    /// Terminal type
    pub term_type: String,
    /// Terminal width
    pub cols: u32,
    /// Terminal height
    pub rows: u32,
    /// Terminal modes
    pub modes: HashMap<String, u32>,
}

/// Session cache for managing resumption tickets
pub struct SessionCache {
    /// Active sessions by ID
    sessions: Arc<RwLock<HashMap<String, CachedSession>>>,
    /// Maximum cache size
    max_sessions: usize,
    /// Default ticket lifetime
    default_lifetime: Duration,
    /// Cache directory
    cache_dir: PathBuf,
}

/// Cached session information
#[derive(Debug, Clone)]
struct CachedSession {
    /// Session ticket
    ticket: SessionTicket,
    /// Last access time
    last_accessed: Instant,
    /// Number of successful resumptions
    resumption_count: u32,
    /// Session state
    state: SessionState,
}

impl SessionCache {
    /// Create new session cache
    pub fn new(cache_dir: PathBuf) -> Result<Self> {
        // Ensure cache directory exists
        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| QsshError::Config(format!("Failed to create session cache dir: {}", e)))?;

        Ok(Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_sessions: 100,
            default_lifetime: Duration::from_secs(48 * 3600), // 48 hours
            cache_dir,
        })
    }

    /// Create new session ticket
    pub async fn create_ticket(
        &self,
        server_id: &str,
        username: &str,
        state: SessionState,
        pq_algorithm: PqAlgorithm,
    ) -> Result<SessionTicket> {
        let session_id = generate_session_id();

        // Serialize session state
        let state_bytes = bincode::serialize(&state)
            .map_err(|e| QsshError::Protocol(format!("Failed to serialize session state: {}", e)))?;

        // Generate encryption key from session ID
        let encryption_key = derive_ticket_key(&session_id);

        // Encrypt state
        let nonce = generate_nonce();
        let encrypted_state = encrypt_state(&state_bytes, &encryption_key, &nonce)?;

        // Create encrypted keys placeholder (would be actual keys in production)
        let session_keys = EncryptedKeys {
            symmetric_key: vec![0; 32],
            mac_key: vec![0; 32],
            salt: generate_salt(),
        };

        // Create ticket
        let ticket = SessionTicket {
            session_id: session_id.clone(),
            server_id: server_id.to_string(),
            username: username.to_string(),
            issued_at: current_timestamp(),
            lifetime: self.default_lifetime.as_secs(),
            encrypted_state,
            pq_algorithm,
            session_keys,
            nonce,
            signature: vec![0; 64], // Would be actual signature
        };

        // Cache the session
        let cached = CachedSession {
            ticket: ticket.clone(),
            last_accessed: Instant::now(),
            resumption_count: 0,
            state,
        };

        self.sessions.write().await.insert(session_id, cached);

        // Clean up old sessions if needed
        self.cleanup_old_sessions().await?;

        Ok(ticket)
    }

    /// Validate and retrieve session ticket
    pub async fn validate_ticket(&self, ticket: &SessionTicket) -> Result<SessionState> {
        // Check if ticket is expired
        if is_ticket_expired(ticket) {
            return Err(QsshError::Protocol("Session ticket expired".into()));
        }

        // Check if session exists in cache
        let mut sessions = self.sessions.write().await;
        if let Some(cached) = sessions.get_mut(&ticket.session_id) {
            // Update access time and count
            cached.last_accessed = Instant::now();
            cached.resumption_count += 1;

            // Return session state
            Ok(cached.state.clone())
        } else {
            // Try to load from disk
            self.load_from_disk(&ticket.session_id).await
        }
    }

    /// Remove session from cache
    pub async fn remove_session(&self, session_id: &str) -> Result<()> {
        self.sessions.write().await.remove(session_id);

        // Remove from disk
        let session_file = self.cache_dir.join(format!("{}.session", session_id));
        if session_file.exists() {
            std::fs::remove_file(session_file)
                .map_err(|e| QsshError::Io(e))?;
        }

        Ok(())
    }

    /// Save session to disk
    pub async fn save_to_disk(&self, session_id: &str) -> Result<()> {
        let sessions = self.sessions.read().await;
        if let Some(cached) = sessions.get(session_id) {
            let session_file = self.cache_dir.join(format!("{}.session", session_id));

            let data = bincode::serialize(&cached.ticket)
                .map_err(|e| QsshError::Protocol(format!("Failed to serialize ticket: {}", e)))?;

            std::fs::write(session_file, data)
                .map_err(|e| QsshError::Io(e))?;
        }

        Ok(())
    }

    /// Load session from disk
    async fn load_from_disk(&self, session_id: &str) -> Result<SessionState> {
        let session_file = self.cache_dir.join(format!("{}.session", session_id));

        if !session_file.exists() {
            return Err(QsshError::Protocol("Session not found".into()));
        }

        let data = std::fs::read(session_file)
            .map_err(|e| QsshError::Io(e))?;

        let ticket: SessionTicket = bincode::deserialize(&data)
            .map_err(|e| QsshError::Protocol(format!("Failed to deserialize ticket: {}", e)))?;

        // Check expiration
        if is_ticket_expired(&ticket) {
            return Err(QsshError::Protocol("Session ticket expired".into()));
        }

        // Decrypt state
        let encryption_key = derive_ticket_key(&ticket.session_id);
        let state_bytes = decrypt_state(&ticket.encrypted_state, &encryption_key, &ticket.nonce)?;

        let state: SessionState = bincode::deserialize(&state_bytes)
            .map_err(|e| QsshError::Protocol(format!("Failed to deserialize state: {}", e)))?;

        Ok(state)
    }

    /// Clean up old sessions
    async fn cleanup_old_sessions(&self) -> Result<()> {
        let mut sessions = self.sessions.write().await;

        // Remove expired sessions
        let now = Instant::now();
        sessions.retain(|_, cached| {
            let age = now.duration_since(cached.last_accessed);
            age < Duration::from_secs(cached.ticket.lifetime)
        });

        // If still over limit, remove least recently used
        if sessions.len() > self.max_sessions {
            let mut entries: Vec<_> = sessions.iter().map(|(id, s)| (id.clone(), s.last_accessed)).collect();
            entries.sort_by_key(|e| e.1);

            let to_remove = sessions.len() - self.max_sessions;
            for (id, _) in entries.iter().take(to_remove) {
                sessions.remove(id);
            }
        }

        Ok(())
    }

    /// Get session statistics
    pub async fn get_stats(&self) -> SessionCacheStats {
        let sessions = self.sessions.read().await;

        SessionCacheStats {
            total_sessions: sessions.len(),
            total_resumptions: sessions.values().map(|s| s.resumption_count).sum(),
            average_lifetime: if sessions.is_empty() {
                Duration::ZERO
            } else {
                let total: Duration = sessions.values()
                    .map(|s| Instant::now().duration_since(s.last_accessed))
                    .sum();
                total / sessions.len() as u32
            },
        }
    }
}

/// Session cache statistics
#[derive(Debug, Clone)]
pub struct SessionCacheStats {
    /// Total cached sessions
    pub total_sessions: usize,
    /// Total successful resumptions
    pub total_resumptions: u32,
    /// Average session lifetime
    pub average_lifetime: Duration,
}

/// Fast reconnection handler
pub struct FastReconnect {
    /// Session cache
    cache: Arc<SessionCache>,
    /// Maximum reconnection attempts
    max_attempts: u32,
    /// Backoff strategy
    backoff: BackoffStrategy,
}

/// Backoff strategy for reconnection
#[derive(Debug, Clone)]
pub enum BackoffStrategy {
    /// Fixed delay between attempts
    Fixed(Duration),
    /// Exponential backoff
    Exponential {
        initial: Duration,
        max: Duration,
        multiplier: f64,
    },
    /// Linear backoff
    Linear {
        initial: Duration,
        increment: Duration,
        max: Duration,
    },
}

impl FastReconnect {
    /// Create new fast reconnect handler
    pub fn new(cache: Arc<SessionCache>) -> Self {
        Self {
            cache,
            max_attempts: 5,
            backoff: BackoffStrategy::Exponential {
                initial: Duration::from_millis(100),
                max: Duration::from_secs(30),
                multiplier: 2.0,
            },
        }
    }

    /// Attempt fast reconnection
    pub async fn reconnect(&self, ticket: &SessionTicket) -> Result<SessionState> {
        let mut attempt = 0;
        let mut delay = self.initial_delay();

        loop {
            attempt += 1;

            // Try to validate ticket
            match self.cache.validate_ticket(ticket).await {
                Ok(state) => return Ok(state),
                Err(e) if attempt >= self.max_attempts => return Err(e),
                Err(_) => {
                    // Wait before retry
                    tokio::time::sleep(delay).await;
                    delay = self.next_delay(delay, attempt);
                }
            }
        }
    }

    /// Get initial delay
    fn initial_delay(&self) -> Duration {
        match &self.backoff {
            BackoffStrategy::Fixed(d) => *d,
            BackoffStrategy::Exponential { initial, .. } => *initial,
            BackoffStrategy::Linear { initial, .. } => *initial,
        }
    }

    /// Calculate next delay
    fn next_delay(&self, current: Duration, attempt: u32) -> Duration {
        match &self.backoff {
            BackoffStrategy::Fixed(d) => *d,
            BackoffStrategy::Exponential { max, multiplier, .. } => {
                let next = current.mul_f64(*multiplier);
                if next > *max { *max } else { next }
            }
            BackoffStrategy::Linear { increment, max, .. } => {
                let next = current + *increment * attempt;
                if next > *max { *max } else { next }
            }
        }
    }
}

// Helper functions

fn generate_session_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    hex::encode(bytes)
}

fn generate_nonce() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..12).map(|_| rng.gen()).collect()
}

fn generate_salt() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen()).collect()
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}

fn is_ticket_expired(ticket: &SessionTicket) -> bool {
    let now = current_timestamp();
    now > ticket.issued_at + ticket.lifetime
}

fn derive_ticket_key(session_id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(b"QSSH_SESSION_TICKET");
    hasher.finalize().to_vec()
}

fn encrypt_state(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    // Simplified - would use actual encryption
    Ok(data.to_vec())
}

fn decrypt_state(data: &[u8], _key: &[u8], _nonce: &[u8]) -> Result<Vec<u8>> {
    // Simplified - would use actual decryption
    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_session_ticket_creation() {
        let temp_dir = TempDir::new().unwrap();
        let cache = SessionCache::new(temp_dir.path().to_path_buf()).unwrap();

        let state = SessionState {
            cipher_suite: "chacha20-poly1305".to_string(),
            compression: "zlib".to_string(),
            port_forwards: vec![],
            environment: HashMap::new(),
            terminal: None,
            x11_forwarding: false,
            agent_forwarding: true,
        };

        let ticket = cache.create_ticket(
            "server.example.com",
            "user",
            state,
            PqAlgorithm::Falcon512,
        ).await.unwrap();

        assert_eq!(ticket.server_id, "server.example.com");
        assert_eq!(ticket.username, "user");
        assert!(!ticket.session_id.is_empty());
    }

    #[tokio::test]
    async fn test_session_validation() {
        let temp_dir = TempDir::new().unwrap();
        let cache = SessionCache::new(temp_dir.path().to_path_buf()).unwrap();

        let state = SessionState {
            cipher_suite: "aes256-gcm".to_string(),
            compression: "none".to_string(),
            port_forwards: vec!["8080:localhost:80".to_string()],
            environment: HashMap::new(),
            terminal: Some(TerminalState {
                term_type: "xterm-256color".to_string(),
                cols: 80,
                rows: 24,
                modes: HashMap::new(),
            }),
            x11_forwarding: true,
            agent_forwarding: false,
        };

        let ticket = cache.create_ticket(
            "test.server",
            "testuser",
            state.clone(),
            PqAlgorithm::Kyber1024,
        ).await.unwrap();

        // Validate ticket
        let retrieved_state = cache.validate_ticket(&ticket).await.unwrap();
        assert_eq!(retrieved_state.cipher_suite, state.cipher_suite);
        assert_eq!(retrieved_state.compression, state.compression);
        assert_eq!(retrieved_state.port_forwards, state.port_forwards);
        assert!(retrieved_state.terminal.is_some());
    }

    #[test]
    fn test_backoff_strategies() {
        let fixed = BackoffStrategy::Fixed(Duration::from_secs(1));
        let exponential = BackoffStrategy::Exponential {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(10),
            multiplier: 2.0,
        };
        let linear = BackoffStrategy::Linear {
            initial: Duration::from_millis(100),
            increment: Duration::from_millis(100),
            max: Duration::from_secs(5),
        };

        // Just verify they can be created
        assert!(matches!(fixed, BackoffStrategy::Fixed(_)));
        assert!(matches!(exponential, BackoffStrategy::Exponential { .. }));
        assert!(matches!(linear, BackoffStrategy::Linear { .. }));
    }

    #[test]
    fn test_ticket_expiration() {
        let ticket = SessionTicket {
            session_id: "test".to_string(),
            server_id: "server".to_string(),
            username: "user".to_string(),
            issued_at: current_timestamp() - 3600, // 1 hour ago
            lifetime: 1800, // 30 minutes
            encrypted_state: vec![],
            pq_algorithm: PqAlgorithm::Falcon512,
            session_keys: EncryptedKeys {
                symmetric_key: vec![],
                mac_key: vec![],
                salt: vec![],
            },
            nonce: vec![],
            signature: vec![],
        };

        assert!(is_ticket_expired(&ticket));
    }
}