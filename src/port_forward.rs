//! Port forwarding implementation for QSSH
//! Supports local (-L), remote (-R), and dynamic (-D) forwarding

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use crate::{Result, QsshError};
use crate::transport::{Transport, Message, ChannelMessage, ChannelType};

/// Port forwarding types
#[derive(Debug, Clone)]
pub enum ForwardType {
    /// Local port forwarding (-L)
    /// Listen locally, forward to remote
    Local {
        bind_addr: SocketAddr,
        remote_host: String,
        remote_port: u16,
    },
    /// Remote port forwarding (-R)
    /// Listen on remote, forward to local
    Remote {
        remote_bind_addr: SocketAddr,
        local_host: String,
        local_port: u16,
    },
    /// Dynamic port forwarding (-D)
    /// SOCKS proxy
    Dynamic {
        bind_addr: SocketAddr,
    },
}

/// Port forwarding manager
pub struct PortForwardManager {
    transport: Arc<Transport>,
    forwards: Vec<ForwardType>,
}

impl PortForwardManager {
    pub fn new(transport: Arc<Transport>) -> Self {
        Self {
            transport,
            forwards: Vec::new(),
        }
    }
    
    /// Parse forwarding spec (e.g., "8080:localhost:80")
    pub fn parse_forward_spec(spec: &str, forward_type: &str) -> Result<ForwardType> {
        let parts: Vec<&str> = spec.split(':').collect();
        
        match forward_type {
            "local" => {
                if parts.len() != 3 {
                    return Err(QsshError::Config("Invalid local forward spec. Use: local_port:remote_host:remote_port".into()));
                }
                
                let local_port: u16 = parts[0].parse()
                    .map_err(|_| QsshError::Config("Invalid local port".into()))?;
                let remote_host = parts[1].to_string();
                let remote_port: u16 = parts[2].parse()
                    .map_err(|_| QsshError::Config("Invalid remote port".into()))?;
                
                Ok(ForwardType::Local {
                    bind_addr: ([127, 0, 0, 1], local_port).into(),
                    remote_host,
                    remote_port,
                })
            }
            "remote" => {
                if parts.len() != 3 {
                    return Err(QsshError::Config("Invalid remote forward spec. Use: remote_port:local_host:local_port".into()));
                }
                
                let remote_port: u16 = parts[0].parse()
                    .map_err(|_| QsshError::Config("Invalid remote port".into()))?;
                let local_host = parts[1].to_string();
                let local_port: u16 = parts[2].parse()
                    .map_err(|_| QsshError::Config("Invalid local port".into()))?;
                
                Ok(ForwardType::Remote {
                    remote_bind_addr: ([0, 0, 0, 0], remote_port).into(),
                    local_host,
                    local_port,
                })
            }
            "dynamic" => {
                let port: u16 = spec.parse()
                    .map_err(|_| QsshError::Config("Invalid SOCKS port".into()))?;
                
                Ok(ForwardType::Dynamic {
                    bind_addr: ([127, 0, 0, 1], port).into(),
                })
            }
            _ => Err(QsshError::Config("Unknown forward type".into()))
        }
    }
    
    /// Start local port forwarding
    pub async fn start_local_forward(
        &self,
        bind_addr: SocketAddr,
        remote_host: String,
        remote_port: u16,
    ) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        let transport = self.transport.clone();
        
        log::info!("Local port forwarding: {} -> {}:{}", bind_addr, remote_host, remote_port);
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        log::debug!("Accepted connection from {} for forwarding", peer_addr);
                        
                        let transport = transport.clone();
                        let remote_host = remote_host.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = handle_local_forward(
                                stream,
                                transport,
                                remote_host,
                                remote_port,
                            ).await {
                                log::error!("Forward error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Accept error: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Start all configured forwards
    pub async fn start_all(&mut self) -> Result<()> {
        for forward in self.forwards.clone() {
            match forward {
                ForwardType::Local { bind_addr, remote_host, remote_port } => {
                    self.start_local_forward(bind_addr, remote_host, remote_port).await?;
                }
                ForwardType::Remote { .. } => {
                    // Request remote forward from server
                    log::warn!("Remote forwarding not yet implemented");
                }
                ForwardType::Dynamic { bind_addr } => {
                    self.start_socks_proxy(bind_addr).await?;
                }
            }
        }
        Ok(())
    }
    
    /// Start SOCKS proxy for dynamic forwarding
    pub async fn start_socks_proxy(&self, bind_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        let transport = self.transport.clone();
        
        log::info!("SOCKS proxy listening on {}", bind_addr);
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        log::debug!("SOCKS connection from {}", peer_addr);
                        
                        let transport = transport.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_socks_connection(stream, transport).await {
                                log::error!("SOCKS error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("SOCKS accept error: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Add a forward configuration
    pub fn add_forward(&mut self, forward: ForwardType) {
        self.forwards.push(forward);
    }
}

/// Handle a local forward connection
async fn handle_local_forward(
    local_stream: TcpStream,
    transport: Arc<Transport>,
    remote_host: String,
    remote_port: u16,
) -> Result<()> {
    // Request channel open for port forwarding
    let channel_id = rand::random::<u32>() % 65536; // Generate random channel ID
    
    let open_msg = Message::Channel(ChannelMessage::Open {
        channel_id,
        channel_type: ChannelType::DirectTcpIp,
        window_size: 1024 * 1024,
        max_packet_size: 32768,
    });
    
    transport.send_message(&open_msg).await?;
    
    // Send forwarding request
    let forward_request = Message::Channel(ChannelMessage::ForwardRequest {
        channel_id,
        remote_host,
        remote_port,
    });
    
    transport.send_message(&forward_request).await?;
    
    // Split the stream for reading and writing
    let (mut read_half, mut write_half) = local_stream.into_split();
    
    // Create bidirectional forwarding
    let (tx_to_remote, mut rx_to_remote) = mpsc::channel::<Vec<u8>>(256);
    let (tx_from_remote, mut rx_from_remote) = mpsc::channel::<Vec<u8>>(256);
    
    // Forward local -> remote
    let transport_write = transport.clone();
    let local_to_remote = tokio::spawn(async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            match read_half.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let data_msg = Message::Channel(ChannelMessage::Data {
                        channel_id,
                        data: buffer[..n].to_vec(),
                    });
                    if transport_write.send_message(&data_msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    
    // Forward remote -> local
    let remote_to_local = tokio::spawn(async move {
        while let Some(data) = rx_from_remote.recv().await {
            if write_half.write_all(&data).await.is_err() {
                break;
            }
        }
    });
    
    // Wait for either direction to finish
    tokio::select! {
        _ = local_to_remote => {}
        _ = remote_to_local => {}
    }
    
    // Send EOF
    let eof_msg = Message::Channel(ChannelMessage::Eof { channel_id });
    let _ = transport.send_message(&eof_msg).await;
    
    Ok(())
}

/// Handle SOCKS5 connection
async fn handle_socks_connection(
    mut stream: TcpStream,
    transport: Arc<Transport>,
) -> Result<()> {
    // SOCKS5 handshake
    let mut buffer = vec![0u8; 1024];
    
    // Read version and methods
    let n = stream.read(&mut buffer).await?;
    if n < 3 || buffer[0] != 0x05 {
        return Err(QsshError::Protocol("Invalid SOCKS5 handshake".into()));
    }
    
    // Send no auth required
    stream.write_all(&[0x05, 0x00]).await?;
    
    // Read connect request
    let n = stream.read(&mut buffer).await?;
    if n < 10 || buffer[0] != 0x05 || buffer[1] != 0x01 {
        return Err(QsshError::Protocol("Invalid SOCKS5 connect request".into()));
    }
    
    // Parse destination
    let addr_type = buffer[3];
    let (dest_host, dest_port) = match addr_type {
        0x01 => {
            // IPv4
            let addr = format!("{}.{}.{}.{}", buffer[4], buffer[5], buffer[6], buffer[7]);
            let port = u16::from_be_bytes([buffer[8], buffer[9]]);
            (addr, port)
        }
        0x03 => {
            // Domain name
            let len = buffer[4] as usize;
            let domain = String::from_utf8_lossy(&buffer[5..5+len]).to_string();
            let port = u16::from_be_bytes([buffer[5+len], buffer[6+len]]);
            (domain, port)
        }
        _ => return Err(QsshError::Protocol("Unsupported SOCKS5 address type".into())),
    };
    
    // Send success response
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    
    // Forward the connection
    handle_local_forward(stream, transport, dest_host, dest_port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_local_forward() {
        let forward = PortForwardManager::parse_forward_spec("8080:localhost:80", "local").unwrap();
        
        match forward {
            ForwardType::Local { bind_addr, remote_host, remote_port } => {
                assert_eq!(bind_addr.port(), 8080);
                assert_eq!(remote_host, "localhost");
                assert_eq!(remote_port, 80);
            }
            _ => panic!("Wrong forward type"),
        }
    }
    
    #[test]
    fn test_parse_dynamic_forward() {
        let forward = PortForwardManager::parse_forward_spec("1080", "dynamic").unwrap();
        
        match forward {
            ForwardType::Dynamic { bind_addr } => {
                assert_eq!(bind_addr.port(), 1080);
            }
            _ => panic!("Wrong forward type"),
        }
    }
}