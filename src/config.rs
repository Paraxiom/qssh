//! Configuration file parsing for QSSH
//! Compatible with OpenSSH config format

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use crate::{Result, QsshError, QsshConfig, PortForward, PqAlgorithm};

/// Host configuration from config file
#[derive(Debug, Clone)]
pub struct HostConfig {
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity_file: Option<PathBuf>,
    pub local_forward: Vec<String>,
    pub remote_forward: Vec<String>,
    pub dynamic_forward: Vec<String>,
    pub pq_algorithm: Option<PqAlgorithm>,
    pub use_qkd: bool,
    pub qkd_endpoint: Option<String>,
    pub qkd_cert_path: Option<String>,
    pub qkd_key_path: Option<String>,
    pub qkd_ca_path: Option<String>,
    pub key_rotation_interval: Option<u64>,
    pub compression: bool,
    pub server_alive_interval: Option<u64>,
    pub server_alive_count_max: Option<u32>,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            hostname: None,
            port: None,
            user: None,
            identity_file: None,
            local_forward: Vec::new(),
            remote_forward: Vec::new(),
            dynamic_forward: Vec::new(),
            pq_algorithm: None,
            use_qkd: false,
            qkd_endpoint: None,
            qkd_cert_path: None,
            qkd_key_path: None,
            qkd_ca_path: None,
            key_rotation_interval: None,
            compression: false,
            server_alive_interval: None,
            server_alive_count_max: None,
        }
    }
}

/// SSH config file parser
pub struct ConfigParser {
    hosts: HashMap<String, HostConfig>,
    default_config: HostConfig,
}

impl ConfigParser {
    /// Load config from default location (~/.qssh/config or ~/.ssh/config)
    pub fn load_default() -> Result<Self> {
        let home = std::env::var("HOME")
            .map_err(|_| QsshError::Config("HOME environment variable not set".into()))?;

        let qssh_config = PathBuf::from(&home).join(".qssh").join("config");
        let ssh_config = PathBuf::from(&home).join(".ssh").join("config");

        if qssh_config.exists() {
            Self::load_from_file(&qssh_config)
        } else if ssh_config.exists() {
            Self::load_from_file(&ssh_config)
        } else {
            Ok(Self {
                hosts: HashMap::new(),
                default_config: HostConfig::default(),
            })
        }
    }

    /// Load config from specific file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| QsshError::Config(format!("Failed to read config file: {}", e)))?;

        Self::parse(&content)
    }

    /// Parse config content
    pub fn parse(content: &str) -> Result<Self> {
        let mut parser = Self {
            hosts: HashMap::new(),
            default_config: HostConfig::default(),
        };

        let mut current_host: Option<String> = None;
        let mut current_config = HostConfig::default();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse key-value pairs
            let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
            if parts.len() != 2 {
                continue;
            }

            let key = parts[0].to_lowercase();
            let value = parts[1].trim();

            match key.as_str() {
                "host" => {
                    // Save previous host config
                    if let Some(host) = current_host.take() {
                        parser.hosts.insert(host, current_config.clone());
                    }

                    // Start new host section
                    if value != "*" {
                        current_host = Some(value.to_string());
                        current_config = HostConfig::default();
                    } else {
                        // Global defaults
                        current_host = None;
                        current_config = HostConfig::default();
                    }
                }
                "hostname" => {
                    current_config.hostname = Some(value.to_string());
                }
                "port" => {
                    current_config.port = value.parse().ok();
                }
                "user" => {
                    current_config.user = Some(value.to_string());
                }
                "identityfile" => {
                    let path = expand_tilde(value);
                    current_config.identity_file = Some(PathBuf::from(path));
                }
                "localforward" => {
                    current_config.local_forward.push(value.to_string());
                }
                "remoteforward" => {
                    current_config.remote_forward.push(value.to_string());
                }
                "dynamicforward" => {
                    current_config.dynamic_forward.push(value.to_string());
                }
                "pqalgorithm" => {
                    current_config.pq_algorithm = match value.to_lowercase().as_str() {
                        "sphincs" | "sphincsplus" => Some(PqAlgorithm::SphincsPlus),
                        "kyber512" => Some(PqAlgorithm::Kyber512),
                        "kyber768" => Some(PqAlgorithm::Kyber768),
                        "kyber1024" => Some(PqAlgorithm::Kyber1024),
                        "falcon" | "falcon512" => Some(PqAlgorithm::Falcon512),
                        _ => None,
                    };
                }
                "useqkd" => {
                    current_config.use_qkd = value.to_lowercase() == "yes" || value == "1";
                }
                "qkdendpoint" => {
                    current_config.qkd_endpoint = Some(value.to_string());
                }
                "qkdcertpath" => {
                    current_config.qkd_cert_path = Some(expand_tilde(value));
                }
                "qkdkeypath" => {
                    current_config.qkd_key_path = Some(expand_tilde(value));
                }
                "qkdcapath" => {
                    current_config.qkd_ca_path = Some(expand_tilde(value));
                }
                "keyrotationinterval" => {
                    current_config.key_rotation_interval = value.parse().ok();
                }
                "compression" => {
                    current_config.compression = value.to_lowercase() == "yes" || value == "1";
                }
                "serveraliveinterval" => {
                    current_config.server_alive_interval = value.parse().ok();
                }
                "serveralivecountmax" => {
                    current_config.server_alive_count_max = value.parse().ok();
                }
                _ => {
                    // Ignore unknown options (for OpenSSH compatibility)
                }
            }
        }

        // Save last host config
        if let Some(host) = current_host {
            parser.hosts.insert(host, current_config);
        } else {
            // If no host was being parsed, these were global defaults
            parser.default_config = current_config;
        }

        Ok(parser)
    }

    /// Get configuration for a specific host
    pub fn get_host_config(&self, hostname: &str) -> HostConfig {
        // Check for exact match
        if let Some(config) = self.hosts.get(hostname) {
            return self.merge_with_defaults(config.clone());
        }

        // Check for wildcard matches
        for (pattern, config) in &self.hosts {
            if pattern_matches(pattern, hostname) {
                return self.merge_with_defaults(config.clone());
            }
        }

        // Return defaults
        self.default_config.clone()
    }

    /// Merge host config with defaults
    fn merge_with_defaults(&self, mut config: HostConfig) -> HostConfig {
        if config.port.is_none() {
            config.port = self.default_config.port.or(Some(22222));
        }
        if config.user.is_none() {
            config.user = self.default_config.user.clone();
        }
        if config.identity_file.is_none() {
            config.identity_file = self.default_config.identity_file.clone();
        }
        if config.pq_algorithm.is_none() {
            config.pq_algorithm = self.default_config.pq_algorithm.or(Some(PqAlgorithm::Falcon512));
        }
        if config.key_rotation_interval.is_none() {
            config.key_rotation_interval = self.default_config.key_rotation_interval.or(Some(3600));
        }
        
        // Merge QKD settings
        if !config.use_qkd && self.default_config.use_qkd {
            config.use_qkd = self.default_config.use_qkd;
        }
        if config.qkd_endpoint.is_none() {
            config.qkd_endpoint = self.default_config.qkd_endpoint.clone();
        }
        if config.qkd_cert_path.is_none() {
            config.qkd_cert_path = self.default_config.qkd_cert_path.clone();
        }
        if config.qkd_key_path.is_none() {
            config.qkd_key_path = self.default_config.qkd_key_path.clone();
        }
        if config.qkd_ca_path.is_none() {
            config.qkd_ca_path = self.default_config.qkd_ca_path.clone();
        }

        // Merge forward lists
        config.local_forward.extend(self.default_config.local_forward.clone());
        config.remote_forward.extend(self.default_config.remote_forward.clone());
        config.dynamic_forward.extend(self.default_config.dynamic_forward.clone());

        config
    }

    /// Convert host config to QsshConfig
    pub fn to_qssh_config(&self, hostname: &str, username: Option<String>) -> Result<QsshConfig> {
        let host_config = self.get_host_config(hostname);

        let server = if let Some(h) = host_config.hostname {
            format!("{}:{}", h, host_config.port.unwrap_or(22222))
        } else {
            format!("{}:{}", hostname, host_config.port.unwrap_or(22222))
        };

        let username = username.or(host_config.user)
            .ok_or_else(|| QsshError::Config("Username not specified".into()))?;

        let mut port_forwards = Vec::new();
        for forward_spec in &host_config.local_forward {
            if let Some(pf) = parse_port_forward(forward_spec) {
                port_forwards.push(pf);
            }
        }

        Ok(QsshConfig {
            server,
            username,
            password: None,  // Password should be provided via command line for security
            port_forwards,
            use_qkd: host_config.use_qkd,
            qkd_endpoint: host_config.qkd_endpoint,
            qkd_cert_path: host_config.qkd_cert_path,
            qkd_key_path: host_config.qkd_key_path,
            qkd_ca_path: host_config.qkd_ca_path,
            pq_algorithm: host_config.pq_algorithm.unwrap_or(PqAlgorithm::Falcon512),
            key_rotation_interval: host_config.key_rotation_interval.unwrap_or(3600),
        })
    }
}

/// Expand ~ in paths
fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen("~", &home, 1);
        }
    }
    path.to_string()
}

/// Check if pattern matches hostname (supports * wildcard)
fn pattern_matches(pattern: &str, hostname: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            return hostname.starts_with(parts[0]) && hostname.ends_with(parts[1]);
        }
    }

    pattern == hostname
}

/// Parse port forward specification
fn parse_port_forward(spec: &str) -> Option<PortForward> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() != 3 {
        // Try space-separated format
        let parts: Vec<&str> = spec.split_whitespace().collect();
        if parts.len() != 3 {
            return None;
        }

        let local_port = parts[0].parse().ok()?;
        let remote_host = parts[1].to_string();
        let remote_port = parts[2].parse().ok()?;

        return Some(PortForward {
            local_port,
            remote_host,
            remote_port,
        });
    }

    let local_port = parts[0].parse().ok()?;
    let remote_host = parts[1].to_string();
    let remote_port = parts[2].parse().ok()?;

    Some(PortForward {
        local_port,
        remote_host,
        remote_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let config = r#"
# Global defaults
User alice
Port 2222

Host github
    Hostname github.com
    User git
    IdentityFile ~/.ssh/id_rsa

Host *.internal
    Port 22
    User admin

Host quantum-server
    Hostname quantum.example.com
    Port 22222
    PqAlgorithm falcon
    UseQkd yes
    LocalForward 8080:localhost:80
        "#;

        let parser = ConfigParser::parse(config).unwrap();

        // Test github config
        let github = parser.get_host_config("github");
        assert_eq!(github.hostname, Some("github.com".to_string()));
        assert_eq!(github.user, Some("git".to_string()));

        // Test wildcard match
        let internal = parser.get_host_config("server.internal");
        assert_eq!(internal.port, Some(22));
        assert_eq!(internal.user, Some("admin".to_string()));

        // Test quantum server
        let quantum = parser.get_host_config("quantum-server");
        assert_eq!(quantum.pq_algorithm, Some(PqAlgorithm::Falcon512));
        assert!(quantum.use_qkd);
        assert_eq!(quantum.local_forward.len(), 1);
    }
}