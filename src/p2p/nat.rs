//! NAT traversal for P2P connections

use crate::{Result, QsshError};
use tokio::net::UdpSocket;
use std::net::SocketAddr;

/// NAT type detected
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NatType {
    /// No NAT - public IP
    None,
    /// Full cone NAT
    FullCone,
    /// Restricted cone NAT
    RestrictedCone,
    /// Port restricted cone NAT
    PortRestrictedCone,
    /// Symmetric NAT (difficult to traverse)
    Symmetric,
}

/// STUN server for NAT detection
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.services.mozilla.com:3478",
];

/// NAT traversal helper
pub struct NatTraversal {
    local_addr: SocketAddr,
    public_addr: Option<SocketAddr>,
    nat_type: Option<NatType>,
}

impl NatTraversal {
    /// Create new NAT traversal helper
    pub async fn new(local_port: u16) -> Result<Self> {
        let local_addr = format!("0.0.0.0:{}", local_port).parse()
            .map_err(|e| QsshError::Connection(format!("Invalid address: {}", e)))?;
        
        Ok(Self {
            local_addr,
            public_addr: None,
            nat_type: None,
        })
    }
    
    /// Detect NAT type and public address
    pub async fn detect(&mut self) -> Result<(SocketAddr, NatType)> {
        // Simple STUN implementation
        let socket = UdpSocket::bind(self.local_addr).await?;
        
        // Create STUN binding request
        let request = self.create_stun_request();
        
        for server in STUN_SERVERS {
            if let Ok(server_addr) = server.parse::<SocketAddr>() {
                socket.send_to(&request, server_addr).await?;
                
                let mut buf = vec![0u8; 1024];
                match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    socket.recv_from(&mut buf)
                ).await {
                    Ok(Ok((len, _))) => {
                        if let Some(public_addr) = self.parse_stun_response(&buf[..len]) {
                            self.public_addr = Some(public_addr);
                            self.nat_type = Some(self.detect_nat_type(&socket).await?);
                            
                            return Ok((public_addr, self.nat_type.unwrap()));
                        }
                    }
                    _ => continue,
                }
            }
        }
        
        Err(QsshError::Connection("Failed to detect NAT".into()))
    }
    
    /// Create STUN binding request
    fn create_stun_request(&self) -> Vec<u8> {
        // Simplified STUN request (RFC 5389)
        let mut request = vec![
            0x00, 0x01,  // Binding Request
            0x00, 0x00,  // Message Length (will be updated)
            0x21, 0x12, 0xA4, 0x42,  // Magic Cookie
        ];
        
        // Transaction ID (12 bytes)
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut tx_id = vec![0u8; 12];
        rng.fill_bytes(&mut tx_id);
        request.extend_from_slice(&tx_id);
        
        request
    }
    
    /// Parse STUN response to get public address
    fn parse_stun_response(&self, data: &[u8]) -> Option<SocketAddr> {
        if data.len() < 20 {
            return None;
        }
        
        // Check message type (Binding Response)
        if data[0] != 0x01 || data[1] != 0x01 {
            return None;
        }
        
        // Parse attributes
        let mut i = 20;
        while i + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[i], data[i + 1]]);
            let attr_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
            
            if i + 4 + attr_len > data.len() {
                break;
            }
            
            // XOR-MAPPED-ADDRESS (0x0020)
            if attr_type == 0x0020 && attr_len >= 8 {
                let family = data[i + 5];
                if family == 0x01 {  // IPv4
                    let port = u16::from_be_bytes([data[i + 6], data[i + 7]]) ^ 0x2112;
                    let ip = u32::from_be_bytes([
                        data[i + 8] ^ 0x21,
                        data[i + 9] ^ 0x12,
                        data[i + 10] ^ 0xA4,
                        data[i + 11] ^ 0x42,
                    ]);
                    
                    use std::net::{IpAddr, Ipv4Addr};
                    let ip_addr = IpAddr::V4(Ipv4Addr::from(ip));
                    return Some(SocketAddr::new(ip_addr, port));
                }
            }
            
            i += 4 + attr_len;
            // Align to 4 bytes
            i = (i + 3) & !3;
        }
        
        None
    }
    
    /// Detect specific NAT type
    async fn detect_nat_type(&self, socket: &UdpSocket) -> Result<NatType> {
        // Simplified detection - in production, use multiple STUN servers
        // and perform various tests
        
        if let Some(public_addr) = self.public_addr {
            if public_addr.ip() == self.local_addr.ip() {
                Ok(NatType::None)
            } else {
                // For now, assume restricted cone NAT
                // Full detection would require multiple tests
                Ok(NatType::RestrictedCone)
            }
        } else {
            Ok(NatType::Symmetric)
        }
    }
    
    /// Perform UDP hole punching
    pub async fn hole_punch(
        &self,
        peer_public: SocketAddr,
        peer_private: SocketAddr,
    ) -> Result<UdpSocket> {
        let socket = UdpSocket::bind(self.local_addr).await?;
        
        // Send packets to both addresses to punch holes
        let punch_msg = b"QSSH-PUNCH";
        
        for _ in 0..10 {
            socket.send_to(punch_msg, peer_public).await?;
            socket.send_to(punch_msg, peer_private).await?;
            
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        
        Ok(socket)
    }
}