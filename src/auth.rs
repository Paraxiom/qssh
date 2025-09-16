//! Authentication module for QSSH
//!
//! Handles authorized_keys parsing and public key validation

use crate::{Result, QsshError, PqAlgorithm};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};
use sha3::{Sha3_256, Digest};

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
        let mut key_data;
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
        .unwrap_or_else(|_| "/home".to_string());

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

    /// Verify password for user
    pub async fn verify_password(&self, username: &str, password: &str) -> Result<bool> {
        let passwords = self.passwords.read().await;

        if let Some(stored_hash) = passwords.get(username) {
            let password_hash = hash_password(password);
            Ok(stored_hash == &password_hash)
        } else {
            // User not found
            Ok(false)
        }
    }

    /// Set password for user (admin function)
    pub async fn set_password(&self, username: &str, password: &str) -> Result<()> {
        let password_hash = hash_password(password);

        {
            let mut passwords = self.passwords.write().await;
            passwords.insert(username.to_string(), password_hash.clone());
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
        content.push_str("# Format: username:sha3_256_hash\n\n");

        for (username, hash) in passwords.iter() {
            content.push_str(&format!("{}:{}\n", username, hash));
        }

        fs::write(&self.password_file, content).await?;
        Ok(())
    }
}

/// Hash password using SHA3-256
pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
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
}