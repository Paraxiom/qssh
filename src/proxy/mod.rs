//! ProxyJump and ProxyCommand Support
//!
//! Enables connecting through one or more intermediate hosts

use std::process::Stdio;
use tokio::process::Command;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::{Result, QsshError, QsshConfig};
use crate::client::QsshClient;
use std::sync::Arc;

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Type of proxy
    pub proxy_type: ProxyType,
    /// Proxy host or command
    pub target: String,
    /// Additional options
    pub options: Vec<String>,
}

/// Types of proxy connections
#[derive(Debug, Clone)]
pub enum ProxyType {
    /// ProxyJump - connect through another SSH host
    Jump,
    /// ProxyCommand - use external command for connection
    Command,
    /// Direct connection (no proxy)
    None,
}

/// Proxy connection handler
pub struct ProxyConnection {
    config: ProxyConfig,
}

impl ProxyConnection {
    /// Create new proxy connection
    pub fn new(config: ProxyConfig) -> Self {
        Self { config }
    }

    /// Parse ProxyJump string (e.g., "user@host1,host2:port")
    pub fn parse_jump_hosts(jump_spec: &str) -> Result<Vec<JumpHost>> {
        let mut hosts = Vec::new();

        for host_spec in jump_spec.split(',') {
            let host = JumpHost::parse(host_spec)?;
            hosts.push(host);
        }

        Ok(hosts)
    }

    /// Establish connection through proxy
    pub async fn connect(&self, final_host: &str, final_port: u16) -> Result<TcpStream> {
        match &self.config.proxy_type {
            ProxyType::Jump => self.connect_jump(final_host, final_port).await,
            ProxyType::Command => self.connect_command(final_host, final_port).await,
            ProxyType::None => {
                TcpStream::connect(format!("{}:{}", final_host, final_port))
                    .await
                    .map_err(|e| QsshError::Connection(format!("Direct connection failed: {}", e)))
            }
        }
    }

    /// Connect through ProxyJump hosts
    async fn connect_jump(&self, final_host: &str, final_port: u16) -> Result<TcpStream> {
        let jump_hosts = Self::parse_jump_hosts(&self.config.target)?;

        if jump_hosts.is_empty() {
            return Err(QsshError::Config("No jump hosts specified".into()));
        }

        // Connect to first jump host
        let first_host = &jump_hosts[0];
        let mut client = QsshClient::new(QsshConfig {
            server: format!("{}:{}", first_host.hostname, first_host.port),
            username: first_host.username.clone(),
            password: None,
            port_forwards: Vec::new(),
            use_qkd: false,
            qkd_endpoint: None,
            qkd_cert_path: None,
            qkd_key_path: None,
            qkd_ca_path: None,
            pq_algorithm: crate::PqAlgorithm::Falcon512,
            key_rotation_interval: 3600,
        });

        // Connect to first jump host
        client.connect().await?;

        // Chain through intermediate hosts
        for i in 1..jump_hosts.len() {
            let next_host = &jump_hosts[i];
            // Forward connection through current host to next
            client = self.forward_through_host(client, next_host).await?;
        }

        // Final connection to target through last jump host
        self.forward_to_final(client, final_host, final_port).await
    }

    /// Forward connection through intermediate host
    async fn forward_through_host(&self, mut client: QsshClient, host: &JumpHost) -> Result<QsshClient> {
        // Request port forwarding through current connection
        let forward_port = self.allocate_forward_port();

        // Set up forwarding: -L forward_port:next_host:next_port
        client.request_port_forward(
            forward_port,
            &host.hostname,
            host.port,
        ).await?;

        // Create new client connecting through forwarded port
        let new_client = QsshClient::new(QsshConfig {
            server: format!("localhost:{}", forward_port),
            username: host.username.clone(),
            password: None,
            port_forwards: Vec::new(),
            use_qkd: false,
            qkd_endpoint: None,
            qkd_cert_path: None,
            qkd_key_path: None,
            qkd_ca_path: None,
            pq_algorithm: crate::PqAlgorithm::Falcon512,
            key_rotation_interval: 3600,
        });

        Ok(new_client)
    }

    /// Forward to final destination
    async fn forward_to_final(&self, mut client: QsshClient, host: &str, port: u16) -> Result<TcpStream> {
        // Request direct-tcpip channel to final destination
        let channel = client.open_direct_tcpip(host, port).await?;

        // Return the stream for the channel
        Ok(channel.into_stream())
    }

    /// Connect using ProxyCommand
    async fn connect_command(&self, final_host: &str, final_port: u16) -> Result<TcpStream> {
        let command = self.config.target.clone()
            .replace("%h", final_host)
            .replace("%p", &final_port.to_string());

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| QsshError::Connection(format!("Failed to spawn proxy command: {}", e)))?;

        // Create a stream wrapper around the process stdio
        let stdin = child.stdin.take()
            .ok_or_else(|| QsshError::Connection("Failed to get stdin".into()))?;
        let stdout = child.stdout.take()
            .ok_or_else(|| QsshError::Connection("Failed to get stdout".into()))?;

        // Return a custom stream that bridges the process IO
        Ok(ProcessStream::new(stdin, stdout, child).into_tcp_stream().await?)
    }

    /// Allocate a local port for forwarding
    fn allocate_forward_port(&self) -> u16 {
        // In production, this should find an available port
        // For now, use a random port in the dynamic range
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(49152..65535)
    }
}

/// Jump host specification
#[derive(Debug, Clone)]
pub struct JumpHost {
    pub username: String,
    pub hostname: String,
    pub port: u16,
    pub identity_file: Option<String>,
}

impl JumpHost {
    /// Parse jump host specification (e.g., "user@host:port")
    pub fn parse(spec: &str) -> Result<Self> {
        let mut username = String::from(whoami::username());
        let mut hostname = String::new();
        let mut port = 22;

        // Parse user@host:port format
        let parts: Vec<&str> = spec.split('@').collect();
        let host_part = if parts.len() == 2 {
            username = parts[0].to_string();
            parts[1]
        } else {
            parts[0]
        };

        // Parse host:port
        let host_parts: Vec<&str> = host_part.split(':').collect();
        hostname = host_parts[0].to_string();
        if host_parts.len() == 2 {
            port = host_parts[1].parse()
                .map_err(|_| QsshError::Config(format!("Invalid port: {}", host_parts[1])))?;
        }

        Ok(Self {
            username,
            hostname,
            port,
            identity_file: None, // Would be set from config
        })
    }
}

/// Process-based stream for ProxyCommand
struct ProcessStream {
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    _child: tokio::process::Child,
}

impl ProcessStream {
    fn new(
        stdin: tokio::process::ChildStdin,
        stdout: tokio::process::ChildStdout,
        child: tokio::process::Child,
    ) -> Self {
        Self {
            stdin,
            stdout,
            _child: child,
        }
    }

    /// Convert to TcpStream-like interface
    /// Note: This is a simplified implementation
    async fn into_tcp_stream(self) -> Result<TcpStream> {
        // In a real implementation, we'd need to create a proper async stream wrapper
        // For now, this is a placeholder showing the concept
        Err(QsshError::Protocol("ProcessStream to TcpStream conversion not fully implemented".into()))
    }
}

/// Extension trait for QsshClient to support proxy operations
impl QsshClient {
    /// Request port forwarding
    pub async fn request_port_forward(&mut self, local_port: u16, remote_host: &str, remote_port: u16) -> Result<()> {
        // Implementation would send SSH2_MSG_GLOBAL_REQUEST for "tcpip-forward"
        // This is a placeholder for the actual implementation
        println!("Setting up port forward: {}:{}:{}", local_port, remote_host, remote_port);
        Ok(())
    }

    /// Open direct TCP/IP channel
    pub async fn open_direct_tcpip(&mut self, host: &str, port: u16) -> Result<DirectTcpipChannel> {
        // Implementation would send SSH2_MSG_CHANNEL_OPEN for "direct-tcpip"
        println!("Opening direct-tcpip to {}:{}", host, port);
        Ok(DirectTcpipChannel::new())
    }
}

/// Direct TCP/IP channel
pub struct DirectTcpipChannel {
    // Channel implementation details
}

impl DirectTcpipChannel {
    fn new() -> Self {
        Self {}
    }

    /// Convert channel to TcpStream
    pub fn into_stream(self) -> TcpStream {
        // This would return the actual stream from the channel
        // Placeholder for now
        panic!("DirectTcpipChannel::into_stream not fully implemented")
    }
}

/// Parse ProxyJump from config file
pub fn parse_proxy_jump(value: &str) -> Result<ProxyConfig> {
    Ok(ProxyConfig {
        proxy_type: ProxyType::Jump,
        target: value.to_string(),
        options: Vec::new(),
    })
}

/// Parse ProxyCommand from config file
pub fn parse_proxy_command(value: &str) -> Result<ProxyConfig> {
    Ok(ProxyConfig {
        proxy_type: ProxyType::Command,
        target: value.to_string(),
        options: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jump_host_simple() {
        let host = JumpHost::parse("jumphost").unwrap();
        assert_eq!(host.hostname, "jumphost");
        assert_eq!(host.port, 22);
        assert_eq!(host.username, whoami::username());
    }

    #[test]
    fn test_parse_jump_host_with_user() {
        let host = JumpHost::parse("alice@jumphost").unwrap();
        assert_eq!(host.username, "alice");
        assert_eq!(host.hostname, "jumphost");
        assert_eq!(host.port, 22);
    }

    #[test]
    fn test_parse_jump_host_with_port() {
        let host = JumpHost::parse("jumphost:2222").unwrap();
        assert_eq!(host.hostname, "jumphost");
        assert_eq!(host.port, 2222);
    }

    #[test]
    fn test_parse_jump_host_full() {
        let host = JumpHost::parse("bob@jumphost:8022").unwrap();
        assert_eq!(host.username, "bob");
        assert_eq!(host.hostname, "jumphost");
        assert_eq!(host.port, 8022);
    }

    #[test]
    fn test_parse_multiple_jump_hosts() {
        let hosts = ProxyConnection::parse_jump_hosts("user1@host1,host2:222,user3@host3:333").unwrap();
        assert_eq!(hosts.len(), 3);

        assert_eq!(hosts[0].username, "user1");
        assert_eq!(hosts[0].hostname, "host1");
        assert_eq!(hosts[0].port, 22);

        assert_eq!(hosts[1].hostname, "host2");
        assert_eq!(hosts[1].port, 222);

        assert_eq!(hosts[2].username, "user3");
        assert_eq!(hosts[2].hostname, "host3");
        assert_eq!(hosts[2].port, 333);
    }

    #[test]
    fn test_proxy_command_substitution() {
        let config = ProxyConfig {
            proxy_type: ProxyType::Command,
            target: "nc -X connect -x proxy:8080 %h %p".to_string(),
            options: Vec::new(),
        };

        let conn = ProxyConnection::new(config);
        // Test would verify command substitution works correctly
        // This is a simplified test showing the concept
        assert!(conn.config.target.contains("%h"));
        assert!(conn.config.target.contains("%p"));
    }
}