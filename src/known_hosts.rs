//! Known Hosts Management
//!
//! Handles verification and storage of host keys for TOFU (Trust On First Use)

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use crate::{Result, QsshError, PqAlgorithm};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

/// Known hosts database
pub struct KnownHosts {
    /// Path to known_hosts file
    file_path: PathBuf,
    /// In-memory cache of host entries
    entries: HashMap<String, Vec<HostKey>>,
    /// Strict host key checking mode
    strict_checking: bool,
}

/// A host key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostKey {
    /// Hostname or IP address (may include wildcards)
    pub hostname: String,
    /// Port number (if non-standard)
    pub port: Option<u16>,
    /// Key algorithm (Falcon, SPHINCS+, etc.)
    pub algorithm: PqAlgorithm,
    /// The actual public key
    pub public_key: Vec<u8>,
    /// SHA256 fingerprint of the key
    pub fingerprint: String,
    /// Comments (e.g., date added)
    pub comment: Option<String>,
    /// When this entry was added
    pub added_at: DateTime<Utc>,
    /// Certificate authority key (if CA-signed)
    pub ca_key: bool,
    /// Revoked key marker
    pub revoked: bool,
}

/// Result of host key verification
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// Key matches known host
    Known,
    /// Host not in database (first connection)
    Unknown,
    /// Key doesn't match known host (potential MITM)
    Changed {
        old_fingerprint: String,
        new_fingerprint: String,
    },
    /// Key is explicitly revoked
    Revoked,
}

impl KnownHosts {
    /// Create new known hosts manager
    pub fn new(file_path: PathBuf, strict_checking: bool) -> Result<Self> {
        let mut known_hosts = Self {
            file_path,
            entries: HashMap::new(),
            strict_checking,
        };

        // Load existing entries
        known_hosts.load()?;

        Ok(known_hosts)
    }

    /// Load known hosts from file
    pub fn load(&mut self) -> Result<()> {
        if !self.file_path.exists() {
            // Create file if it doesn't exist
            self.ensure_file_exists()?;
            return Ok(());
        }

        let file = fs::File::open(&self.file_path)
            .map_err(|e| QsshError::Config(format!("Failed to open known_hosts: {}", e)))?;

        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.map_err(|e| QsshError::Config(format!("Failed to read known_hosts: {}", e)))?;

            // Skip comments and empty lines
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse host key entry
            if let Ok(entry) = self.parse_line(&line) {
                let hostname = entry.hostname.clone();
                self.entries.entry(hostname)
                    .or_insert_with(Vec::new)
                    .push(entry);
            }
        }

        Ok(())
    }

    /// Parse a known_hosts line
    fn parse_line(&self, line: &str) -> Result<HostKey> {
        // Format: [markers] hostname [port] algorithm base64-key [comment]
        // Example: @revoked example.com falcon512 AAAAB3Nza... Added 2024-01-01

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(QsshError::Config("Invalid known_hosts line".into()));
        }

        let mut idx = 0;
        let mut revoked = false;
        let mut ca_key = false;

        // Check for markers
        if parts[idx].starts_with('@') {
            match parts[idx] {
                "@revoked" => revoked = true,
                "@cert-authority" => ca_key = true,
                _ => {}
            }
            idx += 1;
        }

        // Parse hostname (may include port as [host]:port)
        let (hostname, port) = if parts[idx].starts_with('[') {
            // Format: [hostname]:port
            let host_part = parts[idx].trim_start_matches('[');
            let parts: Vec<&str> = host_part.split("]:").collect();
            if parts.len() == 2 {
                let port = parts[1].parse().ok();
                (parts[0].to_string(), port)
            } else {
                (parts[idx].to_string(), None)
            }
        } else {
            (parts[idx].to_string(), None)
        };
        idx += 1;

        // Parse algorithm
        let algorithm = match parts[idx] {
            "falcon512" => PqAlgorithm::Falcon512,
            "falcon1024" => PqAlgorithm::Falcon1024,
            "sphincs+" | "sphincsplus" => PqAlgorithm::SphincsPlus,
            // Legacy/deprecated algorithms - warn but continue
            "kyber512" | "kyber768" | "kyber1024" => {
                log::warn!("Deprecated Kyber algorithm '{}' detected in known_hosts. Using Falcon512 instead.", parts[idx]);
                PqAlgorithm::Falcon512
            },
            _ => return Err(QsshError::Config(format!("Unknown algorithm: {}", parts[idx]))),
        };
        idx += 1;

        // Parse base64-encoded key
        let public_key = BASE64.decode(parts[idx])
            .map_err(|e| QsshError::Config(format!("Invalid base64 key: {}", e)))?;
        idx += 1;

        // Remaining parts are comment
        let comment = if idx < parts.len() {
            Some(parts[idx..].join(" "))
        } else {
            None
        };

        // Generate fingerprint
        let fingerprint = Self::generate_fingerprint(&public_key);

        Ok(HostKey {
            hostname,
            port,
            algorithm,
            public_key,
            fingerprint,
            comment,
            added_at: Utc::now(),
            ca_key,
            revoked,
        })
    }

    /// Verify a host key
    pub fn verify(&self, hostname: &str, port: u16, algorithm: PqAlgorithm, public_key: &[u8]) -> VerificationResult {
        let fingerprint = Self::generate_fingerprint(public_key);
        let lookup_key = if port != 22 {
            format!("[{}]:{}", hostname, port)
        } else {
            hostname.to_string()
        };

        // Check exact match first
        if let Some(entries) = self.entries.get(&lookup_key) {
            for entry in entries {
                if entry.revoked {
                    return VerificationResult::Revoked;
                }

                if entry.algorithm == algorithm {
                    if entry.public_key == public_key {
                        return VerificationResult::Known;
                    } else {
                        return VerificationResult::Changed {
                            old_fingerprint: entry.fingerprint.clone(),
                            new_fingerprint: fingerprint,
                        };
                    }
                }
            }
        }

        // Check wildcard patterns
        for (pattern, entries) in &self.entries {
            if self.matches_pattern(hostname, pattern) {
                for entry in entries {
                    if entry.revoked && entry.public_key == public_key {
                        return VerificationResult::Revoked;
                    }

                    if entry.algorithm == algorithm && entry.public_key == public_key {
                        return VerificationResult::Known;
                    }
                }
            }
        }

        VerificationResult::Unknown
    }

    /// Add a new host key
    pub fn add(&mut self, hostname: &str, port: u16, algorithm: PqAlgorithm, public_key: Vec<u8>) -> Result<()> {
        let lookup_key = if port != 22 {
            format!("[{}]:{}", hostname, port)
        } else {
            hostname.to_string()
        };

        let entry = HostKey {
            hostname: lookup_key.clone(),
            port: if port != 22 { Some(port) } else { None },
            algorithm,
            public_key: public_key.clone(),
            fingerprint: Self::generate_fingerprint(&public_key),
            comment: Some(format!("Added {}", Utc::now().format("%Y-%m-%d"))),
            added_at: Utc::now(),
            ca_key: false,
            revoked: false,
        };

        // Add to memory
        self.entries.entry(lookup_key)
            .or_insert_with(Vec::new)
            .push(entry.clone());

        // Append to file
        self.append_entry(&entry)?;

        Ok(())
    }

    /// Remove a host key
    pub fn remove(&mut self, hostname: &str, port: u16) -> Result<()> {
        let lookup_key = if port != 22 {
            format!("[{}]:{}", hostname, port)
        } else {
            hostname.to_string()
        };

        self.entries.remove(&lookup_key);
        self.save()?;

        Ok(())
    }

    /// Mark a key as revoked
    pub fn revoke(&mut self, hostname: &str, port: u16, fingerprint: &str) -> Result<()> {
        let lookup_key = if port != 22 {
            format!("[{}]:{}", hostname, port)
        } else {
            hostname.to_string()
        };

        if let Some(entries) = self.entries.get_mut(&lookup_key) {
            for entry in entries {
                if entry.fingerprint == fingerprint {
                    entry.revoked = true;
                    self.save()?;
                    return Ok(());
                }
            }
        }

        Err(QsshError::Config("Host key not found".into()))
    }

    /// Save all entries to file
    fn save(&self) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&self.file_path)
            .map_err(|e| QsshError::Config(format!("Failed to save known_hosts: {}", e)))?;

        // Write header
        writeln!(file, "# QSSH Known Hosts File")?;
        writeln!(file, "# Format: [markers] hostname algorithm base64-key [comment]")?;
        writeln!(file, "#")?;

        // Write entries
        for entries in self.entries.values() {
            for entry in entries {
                self.write_entry(&mut file, entry)?;
            }
        }

        Ok(())
    }

    /// Append a single entry to file
    fn append_entry(&self, entry: &HostKey) -> Result<()> {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.file_path)
            .map_err(|e| QsshError::Config(format!("Failed to append to known_hosts: {}", e)))?;

        self.write_entry(&mut file, entry)?;
        Ok(())
    }

    /// Write a single entry
    fn write_entry(&self, file: &mut fs::File, entry: &HostKey) -> Result<()> {
        let mut line = String::new();

        // Add markers
        if entry.revoked {
            line.push_str("@revoked ");
        } else if entry.ca_key {
            line.push_str("@cert-authority ");
        }

        // Add hostname
        line.push_str(&entry.hostname);
        line.push(' ');

        // Add algorithm
        let algo_str = match entry.algorithm {
            PqAlgorithm::Falcon512 => "falcon512",
            PqAlgorithm::Falcon1024 => "falcon1024",
            PqAlgorithm::SphincsPlus => "sphincs+",
        };
        line.push_str(algo_str);
        line.push(' ');

        // Add base64-encoded key
        line.push_str(&BASE64.encode(&entry.public_key));

        // Add comment if present
        if let Some(ref comment) = entry.comment {
            line.push(' ');
            line.push_str(comment);
        }

        writeln!(file, "{}", line)?;
        Ok(())
    }

    /// Generate SHA256 fingerprint of a public key
    pub fn generate_fingerprint(public_key: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();

        // Format as SHA256:base64
        format!("SHA256:{}", BASE64.encode(hash))
    }

    /// Check if hostname matches a pattern (supports wildcards)
    fn matches_pattern(&self, hostname: &str, pattern: &str) -> bool {
        // Simple wildcard matching
        if pattern == "*" {
            return true;
        }

        if pattern.starts_with("*.") {
            // Match domain wildcard
            let domain = &pattern[2..];
            return hostname.ends_with(domain);
        }

        // Hash-based patterns (OpenSSH hashed format)
        if pattern.starts_with("|1|") {
            // TODO: Implement hashed hostname matching
            return false;
        }

        hostname == pattern
    }

    /// Ensure known_hosts file exists with proper permissions
    fn ensure_file_exists(&self) -> Result<()> {
        if let Some(parent) = self.file_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| QsshError::Config(format!("Failed to create known_hosts directory: {}", e)))?;
        }

        if !self.file_path.exists() {
            fs::File::create(&self.file_path)
                .map_err(|e| QsshError::Config(format!("Failed to create known_hosts file: {}", e)))?;

            // Set permissions to 600 (owner read/write only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = fs::metadata(&self.file_path)?;
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                fs::set_permissions(&self.file_path, permissions)?;
            }
        }

        Ok(())
    }

    /// Interactive prompt for unknown host
    pub fn prompt_unknown_host(&self, hostname: &str, fingerprint: &str) -> Result<bool> {
        println!("The authenticity of host '{}' can't be established.", hostname);
        println!("Post-quantum key fingerprint is {}.", fingerprint);
        print!("Are you sure you want to continue connecting (yes/no/[fingerprint])? ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        match input.trim().to_lowercase().as_str() {
            "yes" => Ok(true),
            "no" => Ok(false),
            fp if fp == fingerprint => Ok(true),
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_fingerprint_generation() {
        let key1 = vec![1, 2, 3, 4, 5];
        let key2 = vec![1, 2, 3, 4, 5];
        let key3 = vec![5, 4, 3, 2, 1];

        let fp1 = KnownHosts::generate_fingerprint(&key1);
        let fp2 = KnownHosts::generate_fingerprint(&key2);
        let fp3 = KnownHosts::generate_fingerprint(&key3);

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
        assert!(fp1.starts_with("SHA256:"));
    }

    #[tokio::test]
    async fn test_known_hosts_operations() {
        let temp_dir = TempDir::new().unwrap();
        let known_hosts_path = temp_dir.path().join("known_hosts");

        let mut known_hosts = KnownHosts::new(known_hosts_path, true).unwrap();

        // Test adding a host
        let key = vec![1, 2, 3, 4, 5];
        known_hosts.add("example.com", 22, PqAlgorithm::Falcon512, key.clone()).unwrap();

        // Test verification
        let result = known_hosts.verify("example.com", 22, PqAlgorithm::Falcon512, &key);
        assert!(matches!(result, VerificationResult::Known));

        // Test unknown host
        let result = known_hosts.verify("unknown.com", 22, PqAlgorithm::Falcon512, &key);
        assert!(matches!(result, VerificationResult::Unknown));

        // Test changed key
        let different_key = vec![5, 4, 3, 2, 1];
        let result = known_hosts.verify("example.com", 22, PqAlgorithm::Falcon512, &different_key);
        assert!(matches!(result, VerificationResult::Changed { .. }));
    }

    #[test]
    fn test_pattern_matching() {
        let temp_dir = TempDir::new().unwrap();
        let known_hosts_path = temp_dir.path().join("known_hosts");
        let known_hosts = KnownHosts::new(known_hosts_path, true).unwrap();

        assert!(known_hosts.matches_pattern("example.com", "example.com"));
        assert!(known_hosts.matches_pattern("sub.example.com", "*.example.com"));
        assert!(known_hosts.matches_pattern("anything", "*"));
        assert!(!known_hosts.matches_pattern("example.org", "*.example.com"));
    }
}