//! P2P mode for QSSH - Direct peer-to-peer connections without daemon
//! 
//! This module implements a decentralized approach where peers can connect
//! directly without requiring a central daemon process.

use crate::{Result, QsshError, PqAlgorithm};
use crate::crypto::{PqKeyExchange, SymmetricCrypto};
use crate::transport::Transport;
use tokio::net::{TcpListener, TcpStream};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

pub mod discovery;
pub mod nat;

/// P2P connection mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum P2pMode {
    /// Direct connection (both peers have public IPs)
    Direct,
    /// NAT traversal using STUN/TURN
    NatTraversal,
    /// Relay through a trusted peer
    Relay,
}

/// P2P peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer ID (derived from public key)
    pub id: String,
    /// Display name
    pub name: String,
    /// Network addresses
    pub addresses: Vec<String>,
    /// Post-quantum public key
    pub public_key: Vec<u8>,
    /// Supported algorithms
    pub algorithms: Vec<PqAlgorithm>,
    /// Last seen timestamp
    pub last_seen: i64,
}

/// P2P session manager
pub struct P2pSession {
    /// Our peer info
    our_info: PeerInfo,
    /// Our keypair
    keypair: PqKeyExchange,
    /// Known peers
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    /// Active connections
    connections: Arc<RwLock<Vec<P2pConnection>>>,
}

/// Active P2P connection
pub struct P2pConnection {
    /// Remote peer info
    peer: PeerInfo,
    /// Transport layer
    transport: Transport,
    /// Connection mode
    mode: P2pMode,
}

impl P2pSession {
    /// Create new P2P session
    pub async fn new(name: String) -> Result<Self> {
        let keypair = PqKeyExchange::new()?;
        
        // Generate peer ID from public key
        use sha3::{Sha3_256, Digest};
        use pqcrypto_traits::sign::PublicKey;
        
        let mut hasher = Sha3_256::new();
        hasher.update(keypair.falcon_pk.as_bytes());
        let id = hex::encode(&hasher.finalize()[..16]);
        
        let our_info = PeerInfo {
            id,
            name,
            addresses: Self::discover_addresses().await?,
            public_key: keypair.falcon_pk.as_bytes().to_vec(),
            algorithms: vec![PqAlgorithm::Falcon512, PqAlgorithm::SphincsPlus],
            last_seen: chrono::Utc::now().timestamp(),
        };
        
        Ok(Self {
            our_info,
            keypair,
            peers: Arc::new(RwLock::new(Vec::new())),
            connections: Arc::new(RwLock::new(Vec::new())),
        })
    }
    
    /// Get our peer info
    pub fn peer_info(&self) -> &PeerInfo {
        &self.our_info
    }
    
    /// Discover our network addresses
    async fn discover_addresses() -> Result<Vec<String>> {
        let mut addrs = Vec::new();
        
        // Get local IP addresses
        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            for iface in ifaces {
                if !iface.is_loopback() {
                    addrs.push(format!("{}:22222", iface.ip()));
                }
            }
        }
        
        // Try to get public IP (optional)
        // In production, use STUN or similar
        
        if addrs.is_empty() {
            addrs.push("127.0.0.1:22222".to_string());
        }
        
        Ok(addrs)
    }
    
    /// Start listening for incoming connections
    pub async fn listen(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await
            .map_err(|e| QsshError::Connection(format!("Failed to bind: {}", e)))?;
        
        log::info!("P2P listening on {}", addr);
        
        loop {
            let (stream, remote_addr) = listener.accept().await?;
            log::info!("Incoming P2P connection from {}", remote_addr);
            
            let session = self.clone_ref();
            tokio::spawn(async move {
                if let Err(e) = session.handle_incoming(stream).await {
                    log::error!("P2P connection error: {}", e);
                }
            });
        }
    }
    
    /// Connect to a peer directly
    pub async fn connect(&self, peer_addr: &str) -> Result<P2pConnection> {
        log::info!("Connecting to peer at {}", peer_addr);
        
        let stream = TcpStream::connect(peer_addr).await
            .map_err(|e| QsshError::Connection(format!("Failed to connect: {}", e)))?;
        
        // Perform P2P handshake
        let (transport, peer_info) = self.perform_outgoing_handshake(stream).await?;
        
        let connection = P2pConnection {
            peer: peer_info,
            transport,
            mode: P2pMode::Direct,
        };
        
        // Store connection
        self.connections.write().await.push(connection);
        
        Ok(self.connections.read().await.last().unwrap().clone_ref())
    }
    
    /// Handle incoming connection
    async fn handle_incoming(&self, stream: TcpStream) -> Result<()> {
        // Perform P2P handshake
        let (transport, peer_info) = self.perform_incoming_handshake(stream).await?;
        
        let connection = P2pConnection {
            peer: peer_info.clone(),
            transport,
            mode: P2pMode::Direct,
        };
        
        // Store connection
        self.connections.write().await.push(connection);
        
        log::info!("P2P connection established with {}", peer_info.name);
        
        // Handle messages
        // ... message handling loop ...
        
        Ok(())
    }
    
    /// Perform outgoing handshake
    async fn perform_outgoing_handshake(&self, mut stream: TcpStream) -> Result<(Transport, PeerInfo)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        // Send our peer info
        let our_data = bincode::serialize(&self.our_info)
            .map_err(|e| QsshError::Protocol(format!("Serialization failed: {}", e)))?;
        let len = (our_data.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&our_data).await?;
        
        // Receive peer info
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        let mut peer_data = vec![0u8; len];
        stream.read_exact(&mut peer_data).await?;
        
        let peer_info: PeerInfo = bincode::deserialize(&peer_data)
            .map_err(|e| QsshError::Protocol(format!("Deserialization failed: {}", e)))?;
        
        // Perform key exchange
        let shared_secret = self.perform_key_exchange(&mut stream, &peer_info, true).await?;
        
        // Create transport
        let crypto = SymmetricCrypto::from_shared_secret(&shared_secret)?;
        let transport = Transport::new(stream, crypto);
        
        Ok((transport, peer_info))
    }
    
    /// Perform incoming handshake
    async fn perform_incoming_handshake(&self, mut stream: TcpStream) -> Result<(Transport, PeerInfo)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        // Receive peer info
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        let mut peer_data = vec![0u8; len];
        stream.read_exact(&mut peer_data).await?;
        
        let peer_info: PeerInfo = bincode::deserialize(&peer_data)
            .map_err(|e| QsshError::Protocol(format!("Deserialization failed: {}", e)))?;
        
        // Send our peer info
        let our_data = bincode::serialize(&self.our_info)
            .map_err(|e| QsshError::Protocol(format!("Serialization failed: {}", e)))?;
        let len = (our_data.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&our_data).await?;
        
        // Perform key exchange
        let shared_secret = self.perform_key_exchange(&mut stream, &peer_info, false).await?;
        
        // Create transport
        let crypto = SymmetricCrypto::from_shared_secret(&shared_secret)?;
        let transport = Transport::new(stream, crypto);
        
        Ok((transport, peer_info))
    }
    
    /// Perform Diffie-Hellman key exchange
    async fn perform_key_exchange(
        &self, 
        stream: &mut TcpStream, 
        peer_info: &PeerInfo,
        initiator: bool
    ) -> Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        // Generate ephemeral key share
        let (our_share, our_signature) = self.keypair.create_key_share()?;
        
        if initiator {
            // Send our share first
            let len = (our_share.len() as u32).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&our_share).await?;
            
            let sig_len = (our_signature.len() as u32).to_be_bytes();
            stream.write_all(&sig_len).await?;
            stream.write_all(&our_signature).await?;
            
            // Receive peer's share
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            let len = u32::from_be_bytes(len_bytes) as usize;
            
            let mut peer_share = vec![0u8; len];
            stream.read_exact(&mut peer_share).await?;
            
            stream.read_exact(&mut len_bytes).await?;
            let sig_len = u32::from_be_bytes(len_bytes) as usize;
            
            let mut peer_signature = vec![0u8; sig_len];
            stream.read_exact(&mut peer_signature).await?;
            
            // Verify peer's share
            let verified_share = self.keypair.process_key_share(
                &peer_info.public_key,
                &peer_share,
                &peer_signature
            )?;
            
            // Compute shared secret
            Ok(self.keypair.compute_shared_secret(
                &our_share,
                &verified_share,
                &self.our_info.id.as_bytes(),
                &peer_info.id.as_bytes()
            ))
        } else {
            // Receive peer's share first
            let mut len_bytes = [0u8; 4];
            stream.read_exact(&mut len_bytes).await?;
            let len = u32::from_be_bytes(len_bytes) as usize;
            
            let mut peer_share = vec![0u8; len];
            stream.read_exact(&mut peer_share).await?;
            
            stream.read_exact(&mut len_bytes).await?;
            let sig_len = u32::from_be_bytes(len_bytes) as usize;
            
            let mut peer_signature = vec![0u8; sig_len];
            stream.read_exact(&mut peer_signature).await?;
            
            // Send our share
            let len = (our_share.len() as u32).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&our_share).await?;
            
            let sig_len = (our_signature.len() as u32).to_be_bytes();
            stream.write_all(&sig_len).await?;
            stream.write_all(&our_signature).await?;
            
            // Verify peer's share
            let verified_share = self.keypair.process_key_share(
                &peer_info.public_key,
                &peer_share,
                &peer_signature
            )?;
            
            // Compute shared secret
            Ok(self.keypair.compute_shared_secret(
                &our_share,
                &verified_share,
                &self.our_info.id.as_bytes(),
                &peer_info.id.as_bytes()
            ))
        }
    }
    
    /// Clone reference for async spawning
    fn clone_ref(&self) -> P2pSession {
        P2pSession {
            our_info: self.our_info.clone(),
            keypair: self.keypair.clone(),
            peers: self.peers.clone(),
            connections: self.connections.clone(),
        }
    }
}

impl P2pConnection {
    /// Send data to peer
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        use crate::transport::{Message, ChannelMessage};
        
        let msg = Message::Channel(ChannelMessage::Data {
            channel_id: 0,
            data: data.to_vec(),
        });
        
        self.transport.send_message(&msg).await
    }
    
    /// Receive data from peer
    pub async fn receive(&self) -> Result<Vec<u8>> {
        use crate::transport::Message;
        
        match self.transport.receive_message::<Message>().await? {
            Message::Channel(crate::transport::ChannelMessage::Data { data, .. }) => Ok(data),
            _ => Err(QsshError::Protocol("Expected data message".into())),
        }
    }
    
    /// Get peer info
    pub fn peer_info(&self) -> &PeerInfo {
        &self.peer
    }
    
    /// Clone reference for async use
    fn clone_ref(&self) -> P2pConnection {
        P2pConnection {
            peer: self.peer.clone(),
            transport: self.transport.clone(),
            mode: self.mode,
        }
    }
}

// Implement Clone for PqKeyExchange (needed for P2pSession cloning)
impl Clone for PqKeyExchange {
    fn clone(&self) -> Self {
        // Re-generate keys since the crypto structs don't implement Clone
        // In production, store serialized keys instead
        PqKeyExchange::new().expect("Failed to clone PqKeyExchange")
    }
}