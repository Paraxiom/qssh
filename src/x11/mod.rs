//! X11 Forwarding Implementation for QSSH
//!
//! Enables running GUI applications on remote server with local display

use std::sync::Arc;
use std::collections::HashMap;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{RwLock, mpsc};
use crate::{Result, QsshError};
use crate::transport::{Transport, Message, ChannelMessage};

/// X11 forwarding configuration
#[derive(Debug, Clone)]
pub struct X11Config {
    /// Display number to use (e.g., 10 for :10.0)
    pub display_number: u32,

    /// Single connection only (more secure)
    pub single_connection: bool,

    /// Trusted forwarding (less secure, more compatible)
    pub trusted: bool,

    /// X11 authentication protocol (usually "MIT-MAGIC-COOKIE-1")
    pub auth_protocol: String,

    /// X11 authentication cookie (hex-encoded)
    pub auth_cookie: Vec<u8>,

    /// Screen number (usually 0)
    pub screen: u32,
}

impl Default for X11Config {
    fn default() -> Self {
        Self {
            display_number: 10,
            single_connection: false,
            trusted: false,
            auth_protocol: "MIT-MAGIC-COOKIE-1".to_string(),
            auth_cookie: generate_auth_cookie(),
            screen: 0,
        }
    }
}

/// X11 forwarding manager
pub struct X11Forwarder {
    config: X11Config,
    transport: Arc<Transport>,
    listeners: Arc<RwLock<HashMap<u32, Arc<TcpListener>>>>,
    active_channels: Arc<RwLock<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
}

impl X11Forwarder {
    /// Create new X11 forwarder
    pub fn new(transport: Arc<Transport>) -> Self {
        Self::with_config(transport, X11Config::default())
    }

    /// Create with custom configuration
    pub fn with_config(transport: Arc<Transport>, config: X11Config) -> Self {
        Self {
            config,
            transport,
            listeners: Arc::new(RwLock::new(HashMap::new())),
            active_channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start X11 forwarding listener
    pub async fn start(&self) -> Result<()> {
        // Bind to localhost on port 6000 + display_number
        let port = 6000 + self.config.display_number;
        let addr = format!("127.0.0.1:{}", port);

        let listener = TcpListener::bind(&addr).await?;
        log::info!("X11 forwarding listening on :{} (DISPLAY=:{})",
                  port, self.config.display_number);

        // Store listener wrapped in Arc for sharing
        let listener = Arc::new(listener);
        self.listeners.write().await.insert(self.config.display_number, listener.clone());

        // Accept loop
        let listeners = self.listeners.clone();
        let display_num = self.config.display_number;
        let transport = self.transport.clone();
        let config = self.config.clone();
        let active_channels = self.active_channels.clone();

        tokio::spawn(async move {
            // Get listener from the map
            let listener = {
                let lock = listeners.read().await;
                match lock.get(&display_num) {
                    Some(l) => l.clone(),
                    None => return,
                }
            };

            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        log::debug!("X11 connection from {}", peer_addr);

                        let transport = transport.clone();
                        let config_clone = config.clone();
                        let active_channels = active_channels.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_x11_connection(
                                stream,
                                transport,
                                config_clone,
                                active_channels
                            ).await {
                                log::error!("X11 forwarding error: {}", e);
                            }
                        });

                        if config.single_connection {
                            log::info!("Single connection mode - stopping listener");
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("X11 accept error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop X11 forwarding
    pub async fn stop(&self) -> Result<()> {
        self.listeners.write().await.clear();
        self.active_channels.write().await.clear();
        Ok(())
    }

    /// Get DISPLAY environment variable value
    pub fn get_display(&self) -> String {
        format!("localhost:{}.{}", self.config.display_number, self.config.screen)
    }

    /// Get X11 authentication data for setup
    pub fn get_auth_data(&self) -> (&str, &[u8]) {
        (&self.config.auth_protocol, &self.config.auth_cookie)
    }

    /// Handle incoming X11 channel data from server
    pub async fn handle_channel_data(&self, channel_id: u32, data: Vec<u8>) -> Result<()> {
        if let Some(sender) = self.active_channels.read().await.get(&channel_id) {
            sender.send(data).await
                .map_err(|_| QsshError::Protocol("X11 channel closed".into()))?;
        }
        Ok(())
    }
}

/// Handle individual X11 connection
async fn handle_x11_connection(
    mut stream: TcpStream,
    transport: Arc<Transport>,
    config: X11Config,
    active_channels: Arc<RwLock<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
) -> Result<()> {
    // Read X11 authentication from client
    let mut auth_buffer = vec![0u8; 12]; // X11 auth header
    stream.read_exact(&mut auth_buffer).await?;

    // Parse X11 authentication
    let byte_order = auth_buffer[0];
    let protocol_major = u16::from_be_bytes([auth_buffer[2], auth_buffer[3]]);
    let protocol_minor = u16::from_be_bytes([auth_buffer[4], auth_buffer[5]]);
    let auth_proto_len = u16::from_be_bytes([auth_buffer[6], auth_buffer[7]]) as usize;
    let auth_data_len = u16::from_be_bytes([auth_buffer[8], auth_buffer[9]]) as usize;

    // Read auth protocol name and data
    let mut auth_proto = vec![0u8; auth_proto_len];
    stream.read_exact(&mut auth_proto).await?;

    // Padding
    let proto_pad = (4 - (auth_proto_len % 4)) % 4;
    if proto_pad > 0 {
        let mut pad = vec![0u8; proto_pad];
        stream.read_exact(&mut pad).await?;
    }

    let mut auth_data = vec![0u8; auth_data_len];
    stream.read_exact(&mut auth_data).await?;

    // Verify authentication if not trusted
    if !config.trusted {
        let auth_proto_str = String::from_utf8_lossy(&auth_proto);

        if auth_proto_str != config.auth_protocol {
            log::warn!("X11 auth protocol mismatch: {} vs {}",
                      auth_proto_str, config.auth_protocol);
            return Err(QsshError::Protocol("X11 authentication failed".into()));
        }

        if auth_data != config.auth_cookie {
            log::warn!("X11 auth cookie mismatch");
            return Err(QsshError::Protocol("X11 authentication failed".into()));
        }
    }

    // Request X11 channel from server
    let channel_id = rand::random::<u32>() % 65536;

    let x11_request = Message::Channel(ChannelMessage::X11Request {
        channel_id,
        single_connection: config.single_connection,
        auth_protocol: config.auth_protocol.clone(),
        auth_cookie: hex::encode(&config.auth_cookie),
        screen_number: config.screen,
    });

    transport.send_message(&x11_request).await?;

    // Create channel for receiving data from server
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    active_channels.write().await.insert(channel_id, tx);

    // Split the stream
    let (mut read_half, mut write_half) = stream.into_split();

    // Forward client -> server
    let transport_write = transport.clone();
    let client_to_server = tokio::spawn(async move {
        // First, reconstruct and forward the auth packet
        let mut full_auth = Vec::new();
        full_auth.extend_from_slice(&auth_buffer);
        full_auth.extend_from_slice(&auth_proto);
        // Add padding
        let proto_pad = (4 - (auth_proto_len % 4)) % 4;
        full_auth.extend(vec![0u8; proto_pad]);
        full_auth.extend_from_slice(&auth_data);

        let auth_msg = Message::Channel(ChannelMessage::Data {
            channel_id,
            data: full_auth,
        });

        if transport_write.send_message(&auth_msg).await.is_err() {
            return;
        }

        // Then forward the rest
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

    // Forward server -> client
    let server_to_client = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if write_half.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    // Wait for either direction to finish
    tokio::select! {
        _ = client_to_server => {}
        _ = server_to_client => {}
    }

    // Clean up
    active_channels.write().await.remove(&channel_id);

    // Send channel close
    let close_msg = Message::Channel(ChannelMessage::Close { channel_id });
    let _ = transport.send_message(&close_msg).await;

    Ok(())
}

/// Generate random X11 authentication cookie
fn generate_auth_cookie() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut cookie = vec![0u8; 16]; // 128-bit cookie
    rng.fill(&mut cookie[..]);
    cookie
}

/// Setup X11 forwarding environment
pub async fn setup_x11_forwarding(
    transport: Arc<Transport>,
    enable_x11: bool,
    trusted: bool,
) -> Result<Option<X11Forwarder>> {
    if !enable_x11 {
        return Ok(None);
    }

    // Check if X11 is available on client
    if std::env::var("DISPLAY").is_err() {
        log::warn!("X11 forwarding requested but DISPLAY not set");
        return Ok(None);
    }

    // Create X11 configuration
    let mut config = X11Config::default();
    config.trusted = trusted;

    // Find available display number
    for display_num in 10..100 {
        config.display_number = display_num;
        let port = 6000 + display_num;

        // Check if port is available
        if TcpListener::bind(format!("127.0.0.1:{}", port)).await.is_ok() {
            break;
        }
    }

    // Create and start forwarder
    let forwarder = X11Forwarder::with_config(transport, config);
    forwarder.start().await?;

    Ok(Some(forwarder))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_cookie_generation() {
        let cookie1 = generate_auth_cookie();
        let cookie2 = generate_auth_cookie();

        assert_eq!(cookie1.len(), 16);
        assert_eq!(cookie2.len(), 16);
        assert_ne!(cookie1, cookie2); // Should be random
    }

    // #[test]
    // fn test_display_format() {
    //     let config = X11Config {
    //         display_number: 10,
    //         screen: 0,
    //         ..Default::default()
    //     };

    //     // TODO: Create proper mock Transport for testing
    //     // let forwarder = X11Forwarder::with_config(
    //     //     Arc::new(Transport::new()),
    //     //     config
    //     // );

    //     // assert_eq!(forwarder.get_display(), "localhost:10.0");
    // }
}