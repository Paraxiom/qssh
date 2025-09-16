//! Channel multiplexing for QSSH

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use crate::{Result, QsshError};
use super::protocol::{ChannelMessage, ChannelType};

/// Channel manager for multiplexing
pub struct ChannelManager {
    channels: Arc<Mutex<HashMap<u32, Channel>>>,
    next_channel_id: Arc<Mutex<u32>>,
    data_handlers: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(Mutex::new(HashMap::new())),
            next_channel_id: Arc::new(Mutex::new(0)),
            data_handlers: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Open a new channel
    pub async fn open_channel(&self, channel_type: ChannelType) -> Result<u32> {
        let channel_id = {
            let mut next_id = self.next_channel_id.lock().await;
            let id = *next_id;
            *next_id += 1;
            id
        };
        
        let (tx, rx) = mpsc::channel(1024);
        let channel = Channel {
            id: channel_id,
            channel_type,
            sender: tx,
            receiver: Arc::new(Mutex::new(rx)),
            window_size: 1024 * 1024, // 1MB
            max_packet_size: 32768,    // 32KB
            remote_window: 0,
            sent_eof: false,
            received_eof: false,
        };
        
        let mut channels = self.channels.lock().await;
        channels.insert(channel_id, channel);
        
        Ok(channel_id)
    }
    
    /// Get channel by ID
    pub async fn get_channel(&self, id: u32) -> Option<Channel> {
        let channels = self.channels.lock().await;
        channels.get(&id).cloned()
    }
    
    /// Remove channel
    pub async fn remove_channel(&self, id: u32) -> Option<Channel> {
        let mut channels = self.channels.lock().await;
        channels.remove(&id)
    }
    
    /// Handle incoming channel message
    pub async fn handle_message(&self, msg: ChannelMessage) -> Result<()> {
        match msg {
            ChannelMessage::Data { channel_id, data } => {
                // First check if there's a registered data handler
                let handlers = self.data_handlers.lock().await;
                if let Some(handler) = handlers.get(&channel_id) {
                    // Send data to handler
                    handler.send(data.clone()).await
                        .map_err(|_| QsshError::Protocol("Data handler closed".into()))?;
                }
                
                // Also send to channel receiver
                let channels = self.channels.lock().await;
                if let Some(channel) = channels.get(&channel_id) {
                    // Send data to channel receiver
                    channel.sender.send(data).await
                        .map_err(|_| QsshError::Protocol("Channel closed".into()))?;
                } else {
                    return Err(QsshError::Protocol("Unknown channel".into()));
                }
            }
            ChannelMessage::WindowAdjust { channel_id, bytes_to_add } => {
                let mut channels = self.channels.lock().await;
                if let Some(channel) = channels.get_mut(&channel_id) {
                    channel.remote_window += bytes_to_add;
                }
            }
            ChannelMessage::Eof { channel_id } => {
                let mut channels = self.channels.lock().await;
                if let Some(channel) = channels.get_mut(&channel_id) {
                    channel.received_eof = true;
                }
            }
            ChannelMessage::Close { channel_id } => {
                self.remove_channel(channel_id).await;
            }
            _ => {
                // Other messages handled elsewhere
            }
        }
        Ok(())
    }
    
    /// Register a data handler for a specific channel
    pub async fn register_data_handler(&self, channel_id: u32, handler: mpsc::Sender<Vec<u8>>) {
        let mut handlers = self.data_handlers.lock().await;
        handlers.insert(channel_id, handler);
    }
    
    /// Get channel receiver
    pub async fn get_receiver(&self, channel_id: u32) -> Option<Arc<Mutex<mpsc::Receiver<Vec<u8>>>>> {
        let channels = self.channels.lock().await;
        channels.get(&channel_id).map(|ch| ch.receiver.clone())
    }
}

#[derive(Clone)]
pub struct Channel {
    pub id: u32,
    pub channel_type: ChannelType,
    pub sender: mpsc::Sender<Vec<u8>>,
    pub receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    pub window_size: u32,
    pub max_packet_size: u32,
    pub remote_window: u32,
    pub sent_eof: bool,
    pub received_eof: bool,
}

/// Port forwarding handler
pub struct PortForward {
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    channel_id: Option<u32>,
}

impl PortForward {
    pub fn new(local_port: u16, remote_host: String, remote_port: u16) -> Self {
        Self {
            local_port,
            remote_host,
            remote_port,
            channel_id: None,
        }
    }
    
    /// Start port forwarding
    pub async fn start(&mut self, channel_manager: Arc<ChannelManager>) -> Result<()> {
        use tokio::net::TcpListener;
        
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.local_port)).await
            .map_err(|e| QsshError::Io(e))?;
        
        log::info!("Port forward listening on 127.0.0.1:{}", self.local_port);
        
        loop {
            let (socket, addr) = listener.accept().await
                .map_err(|e| QsshError::Io(e))?;
            
            log::debug!("New connection from {}", addr);
            
            // Open channel for this connection
            let channel_type = ChannelType::DirectTcpip {
                host: self.remote_host.clone(),
                port: self.remote_port,
                originator_host: addr.ip().to_string(),
                originator_port: addr.port(),
            };
            
            let channel_id = channel_manager.open_channel(channel_type).await?;
            
            // Handle forwarding in background
            let channel_manager = channel_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_forwarding(socket, channel_id, channel_manager).await {
                    log::error!("Forwarding error: {}", e);
                }
            });
        }
    }
}

async fn handle_forwarding(
    socket: tokio::net::TcpStream,
    channel_id: u32,
    channel_manager: Arc<ChannelManager>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    let (mut socket_rx, mut socket_tx) = socket.into_split();
    let channel = channel_manager.get_channel(channel_id).await
        .ok_or_else(|| QsshError::Protocol("Channel not found".into()))?;
    
    // Forward data from socket to channel
    let channel_sender = channel.sender.clone();
    let socket_to_channel = tokio::spawn(async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            match socket_rx.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if channel_sender.send(buffer[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    
    // Forward data from channel to socket
    let channel_rx = channel_manager.get_receiver(channel_id).await
        .ok_or_else(|| QsshError::Protocol("Channel receiver not found".into()))?;
    
    let channel_to_socket = tokio::spawn(async move {
        let mut rx = channel_rx.lock().await;
        while let Some(data) = rx.recv().await {
            if socket_tx.write_all(&data).await.is_err() {
                break;
            }
        }
    });
    
    // Wait for either direction to finish
    tokio::select! {
        _ = socket_to_channel => {},
        _ = channel_to_socket => {},
    }
    
    // Clean up
    channel_manager.remove_channel(channel_id).await;
    
    Ok(())
}