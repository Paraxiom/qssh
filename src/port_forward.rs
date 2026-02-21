//! Port forwarding implementation for QSSH
//! Supports local (-L), remote (-R), and dynamic (-D) forwarding

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use crate::{Result, QsshError};
use crate::transport::{Transport, Message, ChannelMessage, ChannelType,
    GlobalRequestMessage, GlobalRequestType, GlobalRequestSuccessMessage};

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

/// Registry mapping (bind_host, bind_port) on the server to (local_host, local_port) on the client.
/// Used by the client to know where to connect when a ForwardedTcpip channel arrives.
#[derive(Debug, Clone)]
pub struct RemoteForwardRegistry {
    mappings: Arc<Mutex<HashMap<(String, u16), (String, u16)>>>,
}

impl RemoteForwardRegistry {
    pub fn new() -> Self {
        Self {
            mappings: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a remote forward mapping
    pub async fn insert(&self, bind_host: String, bind_port: u16, local_host: String, local_port: u16) {
        let mut map = self.mappings.lock().await;
        map.insert((bind_host, bind_port), (local_host, local_port));
    }

    /// Look up the local target for an incoming forwarded connection
    pub async fn lookup(&self, connected_host: &str, connected_port: u16) -> Option<(String, u16)> {
        let map = self.mappings.lock().await;
        map.get(&(connected_host.to_string(), connected_port)).cloned()
    }

    /// Remove a mapping
    pub async fn remove(&self, bind_host: &str, bind_port: u16) -> Option<(String, u16)> {
        let mut map = self.mappings.lock().await;
        map.remove(&(bind_host.to_string(), bind_port))
    }
}

/// Routes channel data from the client's message loop to active forwarded connections.
/// When a ForwardedTcpip channel is set up, a sender is registered here. The client's
/// message loop dispatches `ChannelMessage::Data` to the matching sender.
#[derive(Debug, Clone)]
pub struct ForwardedChannelRouter {
    senders: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
}

impl ForwardedChannelRouter {
    pub fn new() -> Self {
        Self {
            senders: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a sender for a channel
    pub async fn register(&self, channel_id: u32, sender: mpsc::Sender<Vec<u8>>) {
        let mut map = self.senders.lock().await;
        map.insert(channel_id, sender);
    }

    /// Route data to a channel's handler. Returns true if routed, false if no handler.
    pub async fn route_data(&self, channel_id: u32, data: Vec<u8>) -> bool {
        let map = self.senders.lock().await;
        if let Some(sender) = map.get(&channel_id) {
            sender.send(data).await.is_ok()
        } else {
            false
        }
    }

    /// Check if a channel has a registered handler
    pub async fn has_channel(&self, channel_id: u32) -> bool {
        let map = self.senders.lock().await;
        map.contains_key(&channel_id)
    }

    /// Remove a channel's handler (called when the channel closes)
    pub async fn remove(&self, channel_id: u32) {
        let mut map = self.senders.lock().await;
        map.remove(&channel_id);
    }
}

/// Port forwarding manager
pub struct PortForwardManager {
    transport: Arc<Transport>,
    forwards: Vec<ForwardType>,
    remote_registry: RemoteForwardRegistry,
    channel_router: ForwardedChannelRouter,
}

impl PortForwardManager {
    pub fn new(transport: Arc<Transport>) -> Self {
        Self {
            transport,
            forwards: Vec::new(),
            remote_registry: RemoteForwardRegistry::new(),
            channel_router: ForwardedChannelRouter::new(),
        }
    }

    /// Get a clone of the remote forward registry (for sharing with the client message handler)
    pub fn remote_registry(&self) -> RemoteForwardRegistry {
        self.remote_registry.clone()
    }

    /// Get a clone of the forwarded channel router (for sharing with the client message handler)
    pub fn channel_router(&self) -> ForwardedChannelRouter {
        self.channel_router.clone()
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
                ForwardType::Remote { remote_bind_addr, local_host, local_port } => {
                    self.start_remote_forward(remote_bind_addr, local_host, local_port).await?;
                }
                ForwardType::Dynamic { bind_addr } => {
                    self.start_socks_proxy(bind_addr).await?;
                }
            }
        }
        Ok(())
    }

    /// Start remote port forwarding (-R)
    ///
    /// Sends a GlobalRequest(TcpipForward) to the server asking it to listen on
    /// `remote_bind_addr`. When the server accepts connections on that port, it
    /// opens ForwardedTcpip channels back to us; the client-side handler connects
    /// those to `local_host:local_port`.
    pub async fn start_remote_forward(
        &self,
        remote_bind_addr: SocketAddr,
        local_host: String,
        local_port: u16,
    ) -> Result<()> {
        let bind_host = remote_bind_addr.ip().to_string();
        let bind_port = remote_bind_addr.port();

        log::info!("Requesting remote forward: {}:{} (server) -> {}:{} (local)",
            bind_host, bind_port, local_host, local_port);

        // Send TcpipForward global request
        let request = Message::GlobalRequest(GlobalRequestMessage {
            request_type: GlobalRequestType::TcpipForward {
                bind_host: bind_host.clone(),
                bind_port,
            },
            want_reply: true,
        });
        self.transport.send_message(&request).await?;

        // Wait for success or failure
        let reply = self.transport.receive_message::<Message>().await?;
        match reply {
            Message::GlobalRequestSuccess(success) => {
                let actual_port = success.bound_port;
                log::info!("Remote forward established: server listening on {}:{}",
                    bind_host, actual_port);

                // Register mapping so handle_forwarded_channel knows where to connect
                self.remote_registry.insert(
                    bind_host, actual_port, local_host, local_port,
                ).await;

                Ok(())
            }
            Message::GlobalRequestFailure => {
                Err(QsshError::Protocol(format!(
                    "Server refused remote forward on {}:{}", bind_host, bind_port
                )))
            }
            other => {
                Err(QsshError::Protocol(format!(
                    "Unexpected reply to TcpipForward request: {:?}", other
                )))
            }
        }
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

/// Handle an incoming ForwardedTcpip channel from the server (remote forward, client side).
///
/// The server opened a channel because someone connected to the remotely-forwarded port.
/// We look up the registry to find the local target, connect to it, accept the channel,
/// register the channel in the router so the message loop can feed data, and bridge
/// data bidirectionally.
pub async fn handle_forwarded_channel(
    channel_id: u32,
    connected_host: String,
    connected_port: u16,
    transport: Arc<Transport>,
    registry: RemoteForwardRegistry,
    router: ForwardedChannelRouter,
) -> Result<()> {
    // Look up local target
    let (local_host, local_port) = registry
        .lookup(&connected_host, connected_port)
        .await
        .ok_or_else(|| QsshError::Protocol(format!(
            "No remote forward registered for {}:{}", connected_host, connected_port
        )))?;

    log::info!("Forwarded channel {} for {}:{} -> connecting to {}:{}",
        channel_id, connected_host, connected_port, local_host, local_port);

    // Connect to local target
    let local_addr = format!("{}:{}", local_host, local_port);
    let local_stream = TcpStream::connect(&local_addr).await
        .map_err(|e| QsshError::Connection(format!(
            "Failed to connect to local target {}: {}", local_addr, e
        )))?;

    // Accept the channel
    let accept = Message::Channel(ChannelMessage::Accept {
        channel_id,
        sender_channel: channel_id,
        window_size: 1024 * 1024,
        max_packet_size: 32768,
    });
    transport.send_message(&accept).await?;

    // Bridge: local TCP stream <-> channel data (bidirectional)
    let (mut read_half, mut write_half) = local_stream.into_split();

    // Register an mpsc sender so the client's message loop can feed channel data to us
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    router.register(channel_id, tx).await;

    // Local TCP -> channel (read from local, send as channel data to server)
    let transport_send = transport.clone();
    let local_to_channel = tokio::spawn(async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            match read_half.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    let data_msg = Message::Channel(ChannelMessage::Data {
                        channel_id,
                        data: buffer[..n].to_vec(),
                    });
                    if transport_send.send_message(&data_msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Channel -> local TCP (receive data from router's mpsc, write to local TCP)
    let channel_to_local = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if write_half.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    // Wait for either direction to finish
    tokio::select! {
        _ = local_to_channel => {}
        _ = channel_to_local => {}
    }

    // Cleanup: remove from router, send EOF
    router.remove(channel_id).await;
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
    fn test_parse_remote_forward() {
        let forward = PortForwardManager::parse_forward_spec("9090:localhost:8080", "remote").unwrap();

        match forward {
            ForwardType::Remote { remote_bind_addr, local_host, local_port } => {
                assert_eq!(remote_bind_addr.port(), 9090);
                assert_eq!(remote_bind_addr.ip().to_string(), "0.0.0.0");
                assert_eq!(local_host, "localhost");
                assert_eq!(local_port, 8080);
            }
            _ => panic!("Wrong forward type"),
        }
    }

    #[test]
    fn test_parse_remote_forward_different_ports() {
        let forward = PortForwardManager::parse_forward_spec("443:127.0.0.1:3000", "remote").unwrap();

        match forward {
            ForwardType::Remote { remote_bind_addr, local_host, local_port } => {
                assert_eq!(remote_bind_addr.port(), 443);
                assert_eq!(local_host, "127.0.0.1");
                assert_eq!(local_port, 3000);
            }
            _ => panic!("Wrong forward type"),
        }
    }

    #[test]
    fn test_parse_remote_forward_invalid() {
        // Missing local port
        assert!(PortForwardManager::parse_forward_spec("9090:localhost", "remote").is_err());
        // Not a number
        assert!(PortForwardManager::parse_forward_spec("abc:localhost:8080", "remote").is_err());
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

    #[tokio::test]
    async fn test_remote_forward_registry_insert_lookup() {
        let registry = RemoteForwardRegistry::new();

        // Insert a mapping
        registry.insert("0.0.0.0".into(), 9090, "localhost".into(), 8080).await;

        // Lookup should succeed
        let result = registry.lookup("0.0.0.0", 9090).await;
        assert_eq!(result, Some(("localhost".to_string(), 8080)));

        // Lookup for non-existent should return None
        let result = registry.lookup("0.0.0.0", 9999).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_remote_forward_registry_remove() {
        let registry = RemoteForwardRegistry::new();

        registry.insert("0.0.0.0".into(), 9090, "localhost".into(), 8080).await;

        // Remove should return the mapping
        let removed = registry.remove("0.0.0.0", 9090).await;
        assert_eq!(removed, Some(("localhost".to_string(), 8080)));

        // Lookup should now fail
        assert_eq!(registry.lookup("0.0.0.0", 9090).await, None);

        // Remove again should return None
        assert_eq!(registry.remove("0.0.0.0", 9090).await, None);
    }

    #[tokio::test]
    async fn test_remote_forward_registry_multiple_entries() {
        let registry = RemoteForwardRegistry::new();

        registry.insert("0.0.0.0".into(), 9090, "localhost".into(), 8080).await;
        registry.insert("0.0.0.0".into(), 9091, "localhost".into(), 3000).await;
        registry.insert("127.0.0.1".into(), 443, "10.0.0.1".into(), 443).await;

        assert_eq!(registry.lookup("0.0.0.0", 9090).await, Some(("localhost".to_string(), 8080)));
        assert_eq!(registry.lookup("0.0.0.0", 9091).await, Some(("localhost".to_string(), 3000)));
        assert_eq!(registry.lookup("127.0.0.1", 443).await, Some(("10.0.0.1".to_string(), 443)));
    }

    #[tokio::test]
    async fn test_forwarded_channel_router() {
        let router = ForwardedChannelRouter::new();

        // No channel registered
        assert!(!router.has_channel(1).await);
        assert!(!router.route_data(1, vec![1, 2, 3]).await);

        // Register a channel
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        router.register(1, tx).await;

        assert!(router.has_channel(1).await);

        // Route data
        assert!(router.route_data(1, vec![42, 43]).await);
        let received = rx.recv().await.unwrap();
        assert_eq!(received, vec![42, 43]);

        // Remove channel
        router.remove(1).await;
        assert!(!router.has_channel(1).await);
    }

    #[tokio::test]
    async fn test_forwarded_channel_router_multiple_channels() {
        let router = ForwardedChannelRouter::new();

        let (tx1, mut rx1) = tokio::sync::mpsc::channel(16);
        let (tx2, mut rx2) = tokio::sync::mpsc::channel(16);

        router.register(100, tx1).await;
        router.register(200, tx2).await;

        // Route to channel 100
        assert!(router.route_data(100, vec![1]).await);
        assert_eq!(rx1.recv().await.unwrap(), vec![1]);

        // Route to channel 200
        assert!(router.route_data(200, vec![2]).await);
        assert_eq!(rx2.recv().await.unwrap(), vec![2]);

        // Channel 300 doesn't exist
        assert!(!router.route_data(300, vec![3]).await);
    }
}