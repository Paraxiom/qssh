//! Authentication module for QSSH
//!
//! Handles authorized_keys parsing and public key validation

use crate::{Result, QsshError, PqAlgorithm};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};
use sha3::{Sha3_256, Digest};
use argon2::{Argon2, Algorithm, Version, Params, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};

/// Authorized key entry
#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    /// Key type (e.g., "qssh-falcon", "qssh-sphincs")
    pub key_type: String,
    /// Base64-encoded public key
    pub key_data: String,
    /// Optional comment
    pub comment: Option<String>,
    /// Key options
    pub options: KeyOptions,
}

/// Key options from authorized_keys
#[derive(Debug, Clone, Default)]
pub struct KeyOptions {
    /// Command to execute
    pub command: Option<String>,
    /// Environment variables
    pub environment: HashMap<String, String>,
    /// Allowed source addresses
    pub from: Option<Vec<String>>,
    /// Permit agent forwarding
    pub agent_forwarding: bool,
    /// Permit port forwarding
    pub port_forwarding: bool,
    /// Permit PTY allocation
    pub pty: bool,
    /// Permit X11 forwarding
    pub x11_forwarding: bool,
}

/// Manages authorized keys for users
pub struct AuthorizedKeysManager {
    /// Base path for authorized_keys files
    base_path: PathBuf,
    /// Cache of loaded keys
    cache: tokio::sync::Mutex<HashMap<String, Vec<AuthorizedKey>>>,
}

impl AuthorizedKeysManager {
    /// Create new authorized keys manager
    pub fn new(base_path: PathBuf) -> Self {
        Self {
            base_path,
            cache: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
    
    /// Load authorized keys for a user
    pub async fn load_user_keys(&self, username: &str) -> Result<Vec<AuthorizedKey>> {
        // Check cache first
        {
            let cache = self.cache.lock().await;
            if let Some(keys) = cache.get(username) {
                return Ok(keys.clone());
            }
        }
        
        // Construct path to authorized_keys file
        // Try .qssh first, then fall back to .ssh
        let qssh_path = self.base_path
            .join(username)
            .join(".qssh")
            .join("authorized_keys");
        
        let ssh_path = self.base_path
            .join(username)
            .join(".ssh")
            .join("authorized_keys");
        
        let keys_path = if qssh_path.exists() {
            qssh_path
        } else {
            ssh_path
        };
        
        log::info!("Looking for authorized_keys at: {:?}", keys_path);
        
        // Load keys from file
        let keys = self.load_keys_from_file(&keys_path).await?;
        
        // Update cache
        {
            let mut cache = self.cache.lock().await;
            cache.insert(username.to_string(), keys.clone());
        }
        
        Ok(keys)
    }
    
    /// Load keys from a file
    async fn load_keys_from_file(&self, path: &Path) -> Result<Vec<AuthorizedKey>> {
        let file = fs::File::open(path).await
            .map_err(|e| QsshError::Io(e))?;
        
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut keys = Vec::new();
        
        while let Some(line) = lines.next_line().await? {
            // Skip empty lines and comments
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            // Parse the line
            if let Some(key) = self.parse_key_line(line) {
                keys.push(key);
            }
        }
        
        Ok(keys)
    }
    
    /// Parse a single authorized_keys line
    fn parse_key_line(&self, line: &str) -> Option<AuthorizedKey> {
        let mut parts = line.split_whitespace();
        let mut key_type = parts.next()?;
        let key_data;
        let mut comment = None;
        let mut options = KeyOptions::default();
        
        // Check if the first part is options
        if !key_type.starts_with("qssh-") && !key_type.starts_with("ssh-") {
            // Parse options
            options = self.parse_options(key_type)?;
            key_type = parts.next()?;
        }
        
        // Get key data
        key_data = parts.next()?.to_string();
        
        // Rest is comment
        let remaining: Vec<&str> = parts.collect();
        if !remaining.is_empty() {
            comment = Some(remaining.join(" "));
        }
        
        // Only accept quantum-safe key types
        if !key_type.starts_with("qssh-") {
            log::warn!("Ignoring non-quantum-safe key type: {}", key_type);
            return None;
        }
        
        Some(AuthorizedKey {
            key_type: key_type.to_string(),
            key_data,
            comment,
            options,
        })
    }
    
    /// Parse key options
    fn parse_options(&self, options_str: &str) -> Option<KeyOptions> {
        let mut options = KeyOptions::default();
        
        // Default permissions for QSSH
        options.pty = true;
        options.port_forwarding = true;
        
        // Parse comma-separated options
        for option in options_str.split(',') {
            let option = option.trim();
            
            if let Some(cmd) = option.strip_prefix("command=\"") {
                if let Some(end) = cmd.rfind('"') {
                    options.command = Some(cmd[..end].to_string());
                }
            } else if let Some(env) = option.strip_prefix("environment=\"") {
                if let Some(end) = env.rfind('"') {
                    // Parse VAR=value
                    if let Some((var, val)) = env[..end].split_once('=') {
                        options.environment.insert(var.to_string(), val.to_string());
                    }
                }
            } else if let Some(from) = option.strip_prefix("from=\"") {
                if let Some(end) = from.rfind('"') {
                    options.from = Some(from[..end].split(',').map(|s| s.to_string()).collect());
                }
            } else if option == "no-agent-forwarding" {
                options.agent_forwarding = false;
            } else if option == "no-port-forwarding" {
                options.port_forwarding = false;
            } else if option == "no-pty" {
                options.pty = false;
            } else if option == "no-X11-forwarding" {
                options.x11_forwarding = false;
            }
        }
        
        Some(options)
    }
    
    /// Verify a public key against authorized keys
    pub async fn verify_public_key(
        &self,
        username: &str,
        algorithm: PqAlgorithm,
        public_key: &[u8],
    ) -> Result<Option<AuthorizedKey>> {
        let keys = self.load_user_keys(username).await?;
        
        // Convert algorithm to key type
        let expected_type = match algorithm {
            PqAlgorithm::Falcon512 => "qssh-falcon512",
            PqAlgorithm::SphincsPlus => "qssh-sphincs+",
            _ => return Ok(None),
        };
        
        // Encode public key to base64 for comparison
        use base64::Engine;
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
        
        // Find matching key
        for key in keys {
            if key.key_type == expected_type && key.key_data == key_b64 {
                return Ok(Some(key));
            }
        }
        
        Ok(None)
    }
}

/// Create default authorized_keys manager for system
pub fn system_authorized_keys() -> AuthorizedKeysManager {
    let base_path = std::env::var("QSSH_AUTH_PATH")
        .unwrap_or_else(|_| {
            #[cfg(target_os = "macos")]
            { "/Users".to_string() }
            #[cfg(not(target_os = "macos"))]
            { "/home".to_string() }
        });

    AuthorizedKeysManager::new(PathBuf::from(base_path))
}

/// Password authentication manager
pub struct PasswordAuthManager {
    /// Path to shadow-like password file for QSSH
    password_file: PathBuf,
    /// In-memory password cache (username -> hashed password)
    passwords: tokio::sync::RwLock<HashMap<String, String>>,
}

impl PasswordAuthManager {
    /// Create new password auth manager
    pub fn new(password_file: PathBuf) -> Self {
        Self {
            password_file,
            passwords: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Load passwords from file
    pub async fn load_passwords(&self) -> Result<()> {
        if !self.password_file.exists() {
            log::warn!("Password file does not exist: {:?}", self.password_file);
            return Ok(());
        }

        let file = fs::File::open(&self.password_file).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut passwords = HashMap::new();

        while let Some(line) = lines.next_line().await? {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Format: username:hashed_password
            if let Some((username, hash)) = line.split_once(':') {
                passwords.insert(username.to_string(), hash.to_string());
            }
        }

        *self.passwords.write().await = passwords;
        Ok(())
    }

    /// Verify password for user.
    /// Supports both Argon2id (PHC format, starting with `$argon2id$`) and
    /// legacy SHA3-256 hex hashes for backward compatibility.
    pub async fn verify_password(&self, username: &str, password: &str) -> Result<bool> {
        let passwords = self.passwords.read().await;

        if let Some(stored_hash) = passwords.get(username) {
            if stored_hash.starts_with("$argon2id$") {
                // New Argon2id PHC string format
                Ok(verify_password_argon2id(password, stored_hash))
            } else {
                // Legacy SHA3-256 hex hash — verify then auto-upgrade
                let legacy_hash = hash_password_sha3(password);
                if stored_hash == &legacy_hash {
                    // Upgrade to Argon2id on successful legacy login
                    drop(passwords); // release read lock
                    if let Ok(new_hash) = hash_password_argon2id(password) {
                        let mut passwords = self.passwords.write().await;
                        passwords.insert(username.to_string(), new_hash);
                        // Best-effort save — don't fail login if save fails
                        drop(passwords);
                        let _ = self.save_passwords().await;
                    }
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        } else {
            // User not found — constant-time-ish: still hash to avoid timing leak
            let _ = hash_password_argon2id(password);
            Ok(false)
        }
    }

    /// Set password for user (admin function). Uses Argon2id with random salt.
    pub async fn set_password(&self, username: &str, password: &str) -> Result<()> {
        let password_hash = hash_password_argon2id(password)
            .map_err(|e| QsshError::Crypto(format!("Failed to hash password: {}", e)))?;

        {
            let mut passwords = self.passwords.write().await;
            passwords.insert(username.to_string(), password_hash);
        }

        // Save to file
        self.save_passwords().await?;
        Ok(())
    }

    /// Save passwords to file
    async fn save_passwords(&self) -> Result<()> {
        let passwords = self.passwords.read().await;
        let mut content = String::new();

        content.push_str("# QSSH Password File\n");
        content.push_str("# Format: username:argon2id_phc_string (or legacy sha3_256_hex)\n\n");

        for (username, hash) in passwords.iter() {
            content.push_str(&format!("{}:{}\n", username, hash));
        }

        fs::write(&self.password_file, content).await?;
        Ok(())
    }
}

/// Hash password using Argon2id with random 16-byte salt.
/// Returns a PHC string: `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`
///
/// Parameters: m=19 MiB, t=2 iterations, p=1 lane (OWASP minimum recommendation)
pub fn hash_password_argon2id(password: &str) -> std::result::Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Argon2 hash error: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id PHC string.
pub fn verify_password_argon2id(password: &str, phc_string: &str) -> bool {
    let parsed = match argon2::PasswordHash::new(phc_string) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Legacy SHA3-256 password hash (for backward compatibility with existing password files).
pub fn hash_password_sha3(password: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Hash password — public API, now uses Argon2id.
/// Callers that need the legacy SHA3-256 hash should call `hash_password_sha3()`.
pub fn hash_password(password: &str) -> String {
    hash_password_argon2id(password)
        .unwrap_or_else(|_| hash_password_sha3(password))
}

/// Create default password manager
pub fn system_password_auth() -> PasswordAuthManager {
    let password_file = std::env::var("QSSH_PASSWORD_FILE")
        .unwrap_or_else(|_| "/etc/qssh/passwords".to_string());

    PasswordAuthManager::new(PathBuf::from(password_file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_key() {
        let mgr = AuthorizedKeysManager::new(PathBuf::from("/tmp"));
        let line = "qssh-falcon512 AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@host";

        let key = mgr.parse_key_line(line).unwrap();
        assert_eq!(key.key_type, "qssh-falcon512");
        assert_eq!(key.comment.as_deref(), Some("user@host"));
    }

    #[test]
    fn test_parse_key_with_options() {
        let mgr = AuthorizedKeysManager::new(PathBuf::from("/tmp"));
        let line = "command=\"/bin/date\",no-pty qssh-sphincs+ AAAAB3NzaC...";

        let key = mgr.parse_key_line(line).unwrap();
        assert_eq!(key.key_type, "qssh-sphincs+");
        assert_eq!(key.options.command.as_deref(), Some("/bin/date"));
        assert!(!key.options.pty);
    }

    #[test]
    fn test_argon2id_hash_and_verify() {
        let phc = hash_password_argon2id("test-password-2026").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password_argon2id("test-password-2026", &phc));
        assert!(!verify_password_argon2id("wrong-password", &phc));
    }

    #[test]
    fn test_argon2id_unique_salts() {
        let h1 = hash_password_argon2id("same-password").unwrap();
        let h2 = hash_password_argon2id("same-password").unwrap();
        // Different salts produce different PHC strings
        assert_ne!(h1, h2);
        // Both still verify
        assert!(verify_password_argon2id("same-password", &h1));
        assert!(verify_password_argon2id("same-password", &h2));
    }

    #[test]
    fn test_legacy_sha3_still_works() {
        let legacy = hash_password_sha3("old-password");
        // Legacy hashes are 64-char hex (SHA3-256)
        assert_eq!(legacy.len(), 64);
        assert!(!legacy.starts_with("$argon2id$"));
    }

    #[test]
    fn test_hash_password_public_api_returns_argon2id() {
        let h = hash_password("new-password");
        assert!(h.starts_with("$argon2id$"));
    }

    #[tokio::test]
    async fn test_password_manager_argon2id() {
        let dir = std::env::temp_dir().join("qssh_test_argon2id");
        let _ = std::fs::create_dir_all(&dir);
        let pw_file = dir.join("passwords");
        let _ = std::fs::write(&pw_file, "");

        let mgr = PasswordAuthManager::new(pw_file.clone());
        mgr.set_password("alice", "quantum-secure!").await.unwrap();

        // Reload and verify
        let mgr2 = PasswordAuthManager::new(pw_file.clone());
        mgr2.load_passwords().await.unwrap();
        assert!(mgr2.verify_password("alice", "quantum-secure!").await.unwrap());
        assert!(!mgr2.verify_password("alice", "wrong").await.unwrap());
        assert!(!mgr2.verify_password("bob", "quantum-secure!").await.unwrap());

        // Verify file contains Argon2id PHC string
        let content = std::fs::read_to_string(&pw_file).unwrap();
        assert!(content.contains("$argon2id$"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_legacy_sha3_auto_upgrade() {
        let dir = std::env::temp_dir().join("qssh_test_upgrade");
        let _ = std::fs::create_dir_all(&dir);
        let pw_file = dir.join("passwords");

        // Write a legacy SHA3-256 hash
        let legacy_hash = hash_password_sha3("old-password");
        std::fs::write(&pw_file, format!("bob:{}\n", legacy_hash)).unwrap();

        let mgr = PasswordAuthManager::new(pw_file.clone());
        mgr.load_passwords().await.unwrap();

        // Verify with legacy hash works
        assert!(mgr.verify_password("bob", "old-password").await.unwrap());

        // After successful login, file should now contain Argon2id
        let content = std::fs::read_to_string(&pw_file).unwrap();
        assert!(content.contains("$argon2id$"), "Password should have been auto-upgraded");

        let _ = std::fs::remove_dir_all(&dir);
    }
}