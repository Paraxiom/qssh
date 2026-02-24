//! ProxyJump and ProxyCommand Support
//!
//! Enables connecting through one or more intermediate hosts.
//! ProxyJump opens a DirectTcpip channel through the jump host's PQ-encrypted
//! tunnel, then bridges it to a local TCP socket pair so the final connection
//! can perform its own PQ handshake through the tunnel.

use tokio::net::TcpStream;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::{Result, QsshError, QsshConfig};
use crate::client::QsshClient;
use crate::transport::{Transport, Message, ChannelMessage, ChannelType};

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
    /// QsshConfig to use when connecting to jump hosts
    jump_config: QsshConfig,
}

impl ProxyConnection {
    /// Create new proxy connection
    pub fn new(config: ProxyConfig, jump_config: QsshConfig) -> Self {
        Self { config, jump_config }
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

    /// Establish connection through proxy, returning a TcpStream to the final host.
    ///
    /// For ProxyJump:
    /// 1. Connects to jump host (full PQ handshake)
    /// 2. Opens a DirectTcpip channel through the jump host targeting final_host:final_port
    /// 3. Creates a local TCP socket pair bridged to the channel
    /// 4. Returns one end of the socket pair for the caller to use
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

    /// Connect through ProxyJump hosts (supports multi-hop chaining)
    async fn connect_jump(&self, final_host: &str, final_port: u16) -> Result<TcpStream> {
        let jump_hosts = Self::parse_jump_hosts(&self.config.target)?;

        if jump_hosts.is_empty() {
            return Err(QsshError::Config("No jump hosts specified".into()));
        }

        log::info!("ProxyJump: {} hop(s) to reach {}:{}", jump_hosts.len(), final_host, final_port);

        // Keep all jump clients alive so their transports stay open
        let mut keep_alive: Vec<QsshClient> = Vec::new();
        let mut current_transport: Option<Transport> = None;

        // Chain through each jump host
        for (i, hop) in jump_hosts.iter().enumerate() {
            let hop_addr = format!("{}:{}", hop.hostname, hop.port);
            log::info!("ProxyJump: hop {}/{} — connecting to {} as {}",
                i + 1, jump_hosts.len(), hop_addr, hop.username);

            let mut hop_config = self.jump_config.clone();
            hop_config.server = hop_addr;
            hop_config.username = hop.username.clone();

            let mut hop_client = QsshClient::new(hop_config);

            if let Some(ref prev_transport) = current_transport {
                // Intermediate hop: open DirectTcpip through previous hop, then PQ handshake
                let bridge_stream = open_channel_bridge(
                    prev_transport, &hop.hostname, hop.port,
                ).await?;
                hop_client.connect_via_stream(bridge_stream).await?;
            } else {
                // First hop: direct TCP connection + PQ handshake
                hop_client.connect().await?;
            }

            current_transport = Some(
                hop_client.transport()
                    .ok_or_else(|| QsshError::Protocol("Jump host transport not available".into()))?
                    .clone()
            );
            keep_alive.push(hop_client);
        }

        let transport = current_transport
            .ok_or_else(|| QsshError::Protocol("No transport after jump chain".into()))?;

        // Final leg: open DirectTcpip through the last hop to the actual target
        log::info!("ProxyJump: opening DirectTcpip channel to final target {}:{}", final_host, final_port);

        let client_stream = open_channel_bridge(&transport, final_host, final_port).await?;

        // Spawn a task to keep all jump clients alive for the connection lifetime.
        // When the returned stream is dropped, the bridge tasks will end naturally.
        tokio::spawn(async move {
            // Hold references to keep transports alive
            let _keep = keep_alive;
            // Wait indefinitely — cleaned up when parent task cancels
            tokio::signal::ctrl_c().await.ok();
        });

        log::info!("ProxyJump: multi-hop bridge established to {}:{}", final_host, final_port);

        Ok(client_stream)
    }

    /// Connect using ProxyCommand
    async fn connect_command(&self, final_host: &str, final_port: u16) -> Result<TcpStream> {
        use tokio::process::Command;
        use std::process::Stdio;

        let command = self.config.target.clone()
            .replace("%h", final_host)
            .replace("%p", &final_port.to_string());

        log::info!("ProxyCommand: executing '{}'", command);

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| QsshError::Connection(format!("Failed to spawn proxy command: {}", e)))?;

        let mut child_stdin = child.stdin.take()
            .ok_or_else(|| QsshError::Connection("Failed to get stdin of proxy command".into()))?;
        let mut child_stdout = child.stdout.take()
            .ok_or_else(|| QsshError::Connection("Failed to get stdout of proxy command".into()))?;

        // Create a local TCP socket pair for bridging
        let bridge_listener = TcpListener::bind("127.0.0.1:0").await
            .map_err(|e| QsshError::Connection(format!("Failed to bind bridge listener: {}", e)))?;
        let bridge_addr = bridge_listener.local_addr()
            .map_err(|e| QsshError::Connection(format!("Failed to get bridge address: {}", e)))?;

        let client_stream_task = tokio::spawn(async move {
            TcpStream::connect(bridge_addr).await
        });

        let (bridge_stream, _) = bridge_listener.accept().await
            .map_err(|e| QsshError::Connection(format!("Bridge accept failed: {}", e)))?;

        let client_stream = client_stream_task.await
            .map_err(|e| QsshError::Connection(format!("Bridge connect failed: {}", e)))?
            .map_err(|e| QsshError::Connection(format!("Bridge connect failed: {}", e)))?;

        // Bridge: child process stdio <-> bridge TCP stream
        let (mut bridge_read, mut bridge_write) = bridge_stream.into_split();

        // bridge -> child stdin
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match bridge_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if child_stdin.write_all(&buf[..n]).await.is_err() { break; }
                    }
                }
            }
        });

        // child stdout -> bridge
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match child_stdout.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if bridge_write.write_all(&buf[..n]).await.is_err() { break; }
                    }
                }
            }
            // Keep child alive
            let _ = child;
        });

        Ok(client_stream)
    }
}

/// Open a DirectTcpip channel through a transport and return a bridged TcpStream.
///
/// 1. Sends ChannelOpen(DirectTcpip) targeting target_host:target_port
/// 2. Waits for Accept
/// 3. Creates a local TCP socket pair
/// 4. Spawns a bridge task between the channel and one end of the pair
/// 5. Returns the other end of the pair as a TcpStream
async fn open_channel_bridge(
    transport: &Transport,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let channel_id = rand::random::<u32>() % 65536;

    let open_msg = Message::Channel(ChannelMessage::Open {
        channel_id,
        channel_type: ChannelType::DirectTcpip {
            host: target_host.to_string(),
            port: target_port,
            originator_host: "127.0.0.1".to_string(),
            originator_port: 0,
        },
        window_size: 1024 * 1024,
        max_packet_size: 32768,
    });

    transport.send_message(&open_msg).await?;

    // Wait for Accept
    let accept_timeout = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        wait_for_channel_accept(transport, channel_id),
    ).await;

    match accept_timeout {
        Ok(Ok(())) => {
            log::info!("ProxyJump: DirectTcpip channel {} accepted for {}:{}", channel_id, target_host, target_port);
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(QsshError::Protocol(
                format!("ProxyJump: timeout waiting for channel accept to {}:{}", target_host, target_port)
            ));
        }
    }

    // Create local TCP socket pair
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await
        .map_err(|e| QsshError::Connection(format!("Failed to bind bridge listener: {}", e)))?;
    let bridge_addr = bridge_listener.local_addr()
        .map_err(|e| QsshError::Connection(format!("Failed to get bridge address: {}", e)))?;

    let client_stream_task = tokio::spawn(async move {
        TcpStream::connect(bridge_addr).await
    });

    let (bridge_stream, _) = bridge_listener.accept().await
        .map_err(|e| QsshError::Connection(format!("Failed to accept bridge connection: {}", e)))?;

    let client_stream = client_stream_task.await
        .map_err(|e| QsshError::Connection(format!("Bridge connect task failed: {}", e)))?
        .map_err(|e| QsshError::Connection(format!("Failed to connect to bridge: {}", e)))?;

    // Spawn bridge task: channel data <-> bridge TCP stream
    let transport_bridge = transport.clone();
    tokio::spawn(async move {
        if let Err(e) = run_channel_bridge(bridge_stream, transport_bridge, channel_id).await {
            log::debug!("ProxyJump bridge for channel {} ended: {}", channel_id, e);
        }
    });

    Ok(client_stream)
}

/// Wait for a ChannelMessage::Accept for the given channel_id on the transport.
/// Discards other messages while waiting.
async fn wait_for_channel_accept(transport: &Transport, target_channel_id: u32) -> Result<()> {
    loop {
        match transport.receive_message::<Message>().await? {
            Message::Channel(ChannelMessage::Accept { channel_id, .. })
                if channel_id == target_channel_id =>
            {
                return Ok(());
            }
            Message::Channel(ChannelMessage::Close { channel_id })
                if channel_id == target_channel_id =>
            {
                return Err(QsshError::Protocol(
                    "Jump host rejected DirectTcpip channel (Close received)".into()
                ));
            }
            Message::Disconnect(d) => {
                return Err(QsshError::Connection(
                    format!("Jump host disconnected: {}", d.description)
                ));
            }
            _ => {
                // Discard other messages while waiting
                continue;
            }
        }
    }
}

/// Bridge a TCP stream to a channel on the jump host transport.
/// Reads from both sides and forwards data bidirectionally.
async fn run_channel_bridge(
    bridge_stream: TcpStream,
    transport: Transport,
    channel_id: u32,
) -> Result<()> {
    let (mut bridge_read, mut bridge_write) = bridge_stream.into_split();

    // Bridge TCP -> Channel: read from bridge, send as channel data
    let transport_send = transport.clone();
    let tcp_to_channel = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match bridge_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let msg = Message::Channel(ChannelMessage::Data {
                        channel_id,
                        data: buf[..n].to_vec(),
                    });
                    if transport_send.send_message(&msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Channel -> Bridge TCP: read from transport, write to bridge
    let channel_to_tcp = tokio::spawn(async move {
        loop {
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data }))
                    if ch_id == channel_id =>
                {
                    if bridge_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id }))
                    if ch_id == channel_id =>
                {
                    break;
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id }))
                    if ch_id == channel_id =>
                {
                    break;
                }
                Ok(Message::Disconnect(_)) => break,
                Err(_) => break,
                Ok(_) => {
                    // Discard other messages (pings, etc.)
                    continue;
                }
            }
        }
    });

    // Wait for either direction to finish
    tokio::select! {
        _ = tcp_to_channel => {}
        _ = channel_to_tcp => {}
    }

    Ok(())
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
        let mut username = whoami::username();
        
        let mut port = 22222; // QSSH default port

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
        let hostname = host_parts[0].to_string();
        if host_parts.len() == 2 {
            port = host_parts[1].parse()
                .map_err(|_| QsshError::Config(format!("Invalid port: {}", host_parts[1])))?;
        }

        Ok(Self {
            username,
            hostname,
            port,
            identity_file: None,
        })
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
        assert_eq!(host.port, 22222); // QSSH default
        assert_eq!(host.username, whoami::username());
    }

    #[test]
    fn test_parse_jump_host_with_user() {
        let host = JumpHost::parse("alice@jumphost").unwrap();
        assert_eq!(host.username, "alice");
        assert_eq!(host.hostname, "jumphost");
        assert_eq!(host.port, 22222);
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
        assert_eq!(hosts[0].port, 22222);

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

        // Verify the substitution placeholders are present
        assert!(config.target.contains("%h"));
        assert!(config.target.contains("%p"));
    }
}
