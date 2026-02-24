//! Structured audit logging with SHA-256 hash chain.
//!
//! Each event is appended as a JSONL line with a hash linking to the
//! previous entry, producing a tamper-evident log.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// A single hash-chained audit entry (JSONL line).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unix epoch seconds
    pub timestamp: u64,
    /// Event category (e.g. "auth", "exec", "connect", "disconnect")
    pub event: String,
    /// Username if known
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Remote address if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,
    /// Human-readable detail
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Success/failure
    pub success: bool,
    /// SHA-256 of the previous entry (hex)
    pub prev_hash: String,
    /// SHA-256 of this entry (hex)
    pub hash: String,
}

/// Hash-chained JSONL audit logger.
///
/// Thread-safe (uses `Arc<Mutex>` internally). Clone-friendly.
#[derive(Clone)]
pub struct AuditLogger {
    path: PathBuf,
    prev_hash: Arc<Mutex<String>>,
}

impl AuditLogger {
    /// Create a new audit logger writing to `path`.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            prev_hash: Arc::new(Mutex::new("genesis".to_string())),
        }
    }

    /// Log a structured event.
    pub async fn log(
        &self,
        event: &str,
        username: Option<&str>,
        remote_addr: Option<&str>,
        detail: Option<&str>,
        success: bool,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let prev_hash = {
            let ph = self.prev_hash.lock().await;
            ph.clone()
        };

        // Compute hash over all fields + previous hash
        let mut hasher = Sha256::new();
        hasher.update(timestamp.to_le_bytes());
        hasher.update(event.as_bytes());
        if let Some(u) = username { hasher.update(u.as_bytes()); }
        if let Some(a) = remote_addr { hasher.update(a.as_bytes()); }
        if let Some(d) = detail { hasher.update(d.as_bytes()); }
        hasher.update(if success { &b"ok "[..] } else { &b"err"[..] });
        hasher.update(prev_hash.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let entry = AuditEntry {
            timestamp,
            event: event.to_string(),
            username: username.map(|s| s.to_string()),
            remote_addr: remote_addr.map(|s| s.to_string()),
            detail: detail.map(|s| s.to_string()),
            success,
            prev_hash: prev_hash.clone(),
            hash: hash.clone(),
        };

        // Update chain head
        {
            let mut ph = self.prev_hash.lock().await;
            *ph = hash;
        }

        // Append to JSONL file (best-effort — don't crash server on I/O error)
        if let Err(e) = self.write_entry(&entry) {
            log::error!("Audit log write failed: {}", e);
        }
    }

    fn write_entry(&self, entry: &AuditEntry) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let line = serde_json::to_string(entry)
            .map_err(std::io::Error::other)?;

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_hash_chain() {
        let dir = std::env::temp_dir().join("qssh_audit_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        let logger = AuditLogger::new(path.clone());

        logger.log("connect", Some("alice"), Some("10.0.0.1:5555"), None, true).await;
        logger.log("auth", Some("alice"), Some("10.0.0.1:5555"), Some("pubkey falcon512"), true).await;
        logger.log("exec", Some("alice"), Some("10.0.0.1:5555"), Some("ls -la"), true).await;
        logger.log("disconnect", Some("alice"), Some("10.0.0.1:5555"), None, true).await;

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 4);

        // Verify chain
        let e0: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        let e1: AuditEntry = serde_json::from_str(lines[1]).unwrap();
        let e2: AuditEntry = serde_json::from_str(lines[2]).unwrap();
        let e3: AuditEntry = serde_json::from_str(lines[3]).unwrap();

        assert_eq!(e0.prev_hash, "genesis");
        assert_eq!(e1.prev_hash, e0.hash);
        assert_eq!(e2.prev_hash, e1.hash);
        assert_eq!(e3.prev_hash, e2.hash);

        assert_eq!(e0.event, "connect");
        assert_eq!(e1.event, "auth");
        assert_eq!(e2.event, "exec");
        assert_eq!(e3.event, "disconnect");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_audit_failed_auth() {
        let dir = std::env::temp_dir().join("qssh_audit_fail_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        let logger = AuditLogger::new(path.clone());
        logger.log("auth", Some("eve"), Some("192.168.1.99:4444"), Some("password rejected"), false).await;

        let content = std::fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(content.trim()).unwrap();
        assert!(!entry.success);
        assert_eq!(entry.username.as_deref(), Some("eve"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_audit_clone_shared_state() {
        let dir = std::env::temp_dir().join("qssh_audit_clone_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        let logger = AuditLogger::new(path.clone());
        let logger2 = logger.clone();

        logger.log("event1", None, None, None, true).await;
        logger2.log("event2", None, None, None, true).await;

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        // Chain should be linked even across clones
        let e0: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        let e1: AuditEntry = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(e1.prev_hash, e0.hash);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
