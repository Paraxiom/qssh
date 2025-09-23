//! QSSH server implementation

use crate::{
    Result, QsshError,
    crypto::PqKeyExchange,
    transport::{Transport, Message, ChannelMessage, ChannelType},
    handshake::ServerHandshake,
    shell_handler_thread::ShellSessionThread,
};
use tokio::net::{TcpListener, TcpStream};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// QSSH server configuration
#[derive(Clone)]
pub struct QsshServerConfig {
    pub listen_addr: String,
    pub host_key: Arc<PqKeyExchange>,
    pub max_connections: usize,
    pub authorized_keys: HashMap<String, Vec<u8>>, // username -> public key
    pub qkd_enabled: bool,
    pub qkd_endpoint: Option<String>,
    pub quantum_native: bool,
}

impl QsshServerConfig {
    pub fn new(listen_addr: &str) -> Result<Self> {
        let host_key = PqKeyExchange::new()?;
        
        Ok(Self {
            listen_addr: listen_addr.to_string(),
            host_key: Arc::new(host_key),
            max_connections: 100,
            authorized_keys: HashMap::new(),
            qkd_enabled: false,
            qkd_endpoint: None,
            quantum_native: true,  // Default to quantum-native
        })
    }
    
    pub fn add_authorized_key(&mut self, username: &str, public_key: Vec<u8>) {
        self.authorized_keys.insert(username.to_string(), public_key);
    }
}

/// QSSH server
pub struct QsshServer {
    config: QsshServerConfig,
    connections: Arc<Mutex<HashMap<String, ClientConnection>>>,
}

impl QsshServer {
    /// Create new QSSH server
    pub fn new(config: QsshServerConfig) -> Self {
        Self {
            config,
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Start the server
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.listen_addr).await
            .map_err(|e| QsshError::Connection(format!("Failed to bind: {}", e)))?;
        
        log::info!("QSSH server listening on {}", self.config.listen_addr);
        
        loop {
            let (stream, addr) = listener.accept().await
                .map_err(|e| QsshError::Connection(format!("Accept failed: {}", e)))?;
            
            log::info!("New connection from {}", addr);
            
            // Check connection limit
            {
                let connections = self.connections.lock().await;
                if connections.len() >= self.config.max_connections {
                    log::warn!("Connection limit reached, rejecting {}", addr);
                    continue;
                }
            }
            
            // Handle connection
            let config = self.config.clone();
            let connections = self.connections.clone();
            
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, config, connections).await {
                    log::error!("Connection error: {}", e);
                }
            });
        }
    }
}

/// Client connection state
struct ClientConnection {
    username: String,
    transport: Transport,
    channels: HashMap<u32, Channel>,
}

/// Channel state
struct Channel {
    id: u32,
    channel_type: ChannelType,
}

/// Handle a client connection
async fn handle_connection(
    stream: TcpStream,
    config: QsshServerConfig,
    connections: Arc<Mutex<HashMap<String, ClientConnection>>>,
) -> Result<()> {
    // Perform handshake
    // For now, recreate the host key since PqKeyExchange doesn't implement Clone
    let host_key = PqKeyExchange::new()?;
    let handshake = ServerHandshake::new(stream, host_key)
        .with_qkd_endpoint(config.qkd_endpoint.clone());
    let (transport, username) = handshake.perform().await?;
    
    log::info!("User {} authenticated successfully", username);
    
    // Create connection state
    let connection = ClientConnection {
        username: username.clone(),
        transport: transport.clone(),
        channels: HashMap::new(),
    };
    
    // Store connection
    {
        let mut conns = connections.lock().await;
        conns.insert(username.clone(), connection);
    }
    
    // Handle messages
    loop {
        log::debug!("Main loop waiting for message...");
        match transport.receive_message::<Message>().await {
            Ok(msg) => {
                log::debug!("Main loop received message: {:?}", 
                    match &msg {
                        Message::Channel(ChannelMessage::ShellRequest { .. }) => "ShellRequest",
                        Message::Channel(ChannelMessage::Data { .. }) => "Data",
                        _ => "Other"
                    });
                
                if let Err(e) = handle_client_message(msg, &transport, &username, &connections).await {
                    // Check if this is the special shell completion signal
                    if let QsshError::Protocol(ref msg) = e {
                        if msg == "SHELL_SESSION_COMPLETE" {
                            log::info!("Shell session completed normally");
                            break;
                        }
                    }
                    log::error!("Error handling message: {}", e);
                    break;
                }
            }
            Err(e) => {
                log::error!("Transport error: {}", e);
                break;
            }
        }
    }
    
    // Remove connection
    {
        let mut conns = connections.lock().await;
        conns.remove(&username);
    }
    
    log::info!("User {} disconnected", username);
    
    Ok(())
}

/// Handle client message
async fn handle_client_message(
    msg: Message,
    transport: &Transport,
    username: &str,
    connections: &Arc<Mutex<HashMap<String, ClientConnection>>>,
) -> Result<()> {
    match msg {
        Message::Channel(channel_msg) => {
            handle_channel_message(channel_msg, transport, username, connections).await?;
        }
        Message::Disconnect(d) => {
            log::info!("Client {} disconnecting: {}", username, d.description);
            return Err(QsshError::Connection("Client disconnected".into()));
        }
        Message::Ping(nonce) => {
            transport.send_message(&Message::Pong(nonce)).await?;
        }
        Message::Rekey(rekey) => {
            log::info!("Client {} requesting rekey", username);
            // Handle rekey request
        }
        _ => {
            log::debug!("Unhandled message from {}", username);
        }
    }
    Ok(())
}

/// Handle channel message
async fn handle_channel_message(
    msg: ChannelMessage,
    transport: &Transport,
    username: &str,
    connections: &Arc<Mutex<HashMap<String, ClientConnection>>>,
) -> Result<()> {
    match msg {
        ChannelMessage::Open { channel_id, channel_type, window_size, max_packet_size } => {
            log::info!("User {} opening channel {} ({:?})", username, channel_id, channel_type);
            
            // Accept channel
            let accept = Message::Channel(ChannelMessage::Accept {
                channel_id,
                sender_channel: channel_id,
                window_size,
                max_packet_size,
            });
            
            transport.send_message(&accept).await?;
            
            // Store channel
            let mut conns = connections.lock().await;
            if let Some(conn) = conns.get_mut(username) {
                conn.channels.insert(channel_id, Channel {
                    id: channel_id,
                    channel_type,
                });
            }
        }
        ChannelMessage::Data { channel_id, data } => {
            // For shell sessions, data should be forwarded to the PTY
            // The shell_handler_thread will handle this via the transport
            log::debug!("User {} sent {} bytes on channel {}", username, data.len(), channel_id);
            // Note: The shell handler thread is already listening for these messages
            // so we don't need to do anything special here
        }
        ChannelMessage::Close { channel_id } => {
            log::info!("User {} closing channel {}", username, channel_id);
            
            // Remove channel
            let mut conns = connections.lock().await;
            if let Some(conn) = conns.get_mut(username) {
                conn.channels.remove(&channel_id);
            }
        }
        ChannelMessage::PtyRequest { channel_id, term, width_chars, height_chars, .. } => {
            log::info!("User {} requesting PTY on channel {} ({}x{} {})", 
                username, channel_id, width_chars, height_chars, term);
            
            // Store PTY settings for later use (when shell is requested)
            // For now, just acknowledge with success
            let success = Message::Channel(ChannelMessage::Data {
                channel_id,
                data: vec![0], // Success indicator
            });
            transport.send_message(&success).await?;
            
            // Don't send any other data here - wait for shell request
        }
        ChannelMessage::ShellRequest { channel_id } => {
            log::info!("User {} requesting shell on channel {}", username, channel_id);
            
            // Get PTY dimensions from stored channel info (default if not set)
            let (width, height) = (80u16, 24u16); // Default dimensions
            
            // Spawn real shell session
            match ShellSessionThread::new(
                channel_id,
                transport.clone(),
                username.to_string(),
                Some("xterm-256color".to_string()),
                width,
                height,
            ).await {
                Ok(session) => {
                    log::info!("Starting shell session for user {} on channel {}", username, channel_id);
                    log::info!("Shell handler taking over transport - running inline");
                    
                    // Run the shell handler inline - this blocks until shell exits
                    // This ensures the main loop doesn't try to read from transport
                    if let Err(e) = session.run().await {
                        log::error!("Shell session error: {}", e);
                    }
                    log::info!("Shell session ended - returning special error to signal shell completion");
                    
                    // Return a special error to signal that shell has completed
                    // This will break the main loop but won't be treated as an error
                    return Err(QsshError::Protocol("SHELL_SESSION_COMPLETE".into()));
                }
                Err(e) => {
                    log::error!("Failed to spawn shell: {}", e);
                    let error_msg = format!("Failed to spawn shell: {}\n", e).into_bytes();
                    let response = Message::Channel(ChannelMessage::Data {
                        channel_id,
                        data: error_msg,
                    });
                    transport.send_message(&response).await?;
                }
            }
        }
        ChannelMessage::ExecRequest { channel_id, command } => {
            log::info!("User {} exec on channel {}: {}", username, channel_id, command);

            // Execute command
            handle_exec_request(channel_id, command, transport, username).await?;
        }
        ChannelMessage::SubsystemRequest { channel_id, subsystem } => {
            log::info!("User {} requesting subsystem '{}' on channel {}", username, subsystem, channel_id);

            // Handle subsystem request
            handle_subsystem_request(channel_id, subsystem, transport, username).await?;
        }
        _ => {
            log::debug!("Unhandled channel message from {}", username);
        }
    }
    Ok(())
}

/// Handle subsystem request
async fn handle_subsystem_request(
    channel_id: u32,
    subsystem: String,
    transport: &Transport,
    username: &str,
) -> Result<()> {
    match subsystem.as_str() {
        "sftp" => {
            log::info!("Starting SFTP subsystem for user {}", username);

            // Create SFTP subsystem
            let mut sftp = crate::subsystems::sftp::SftpSubsystem::new_for_user(username.to_string());

            // Run SFTP subsystem
            if let Err(e) = sftp.run(channel_id, transport.clone()).await {
                log::error!("SFTP subsystem error: {}", e);
                let error_msg = format!("SFTP subsystem failed: {}\n", e).into_bytes();
                let response = Message::Channel(ChannelMessage::Data {
                    channel_id,
                    data: error_msg,
                });
                transport.send_message(&response).await?;
            }

            // Send EOF when subsystem ends
            let eof = Message::Channel(ChannelMessage::Eof { channel_id });
            transport.send_message(&eof).await?;
        }
        _ => {
            log::warn!("Unknown subsystem requested: {}", subsystem);
            let error_msg = format!("Subsystem '{}' not supported\n", subsystem).into_bytes();
            let response = Message::Channel(ChannelMessage::Data {
                channel_id,
                data: error_msg,
            });
            transport.send_message(&response).await?;
        }
    }

    Ok(())
}

/// Handle exec request
async fn handle_exec_request(
    channel_id: u32,
    command: String,
    transport: &Transport,
    username: &str,
) -> Result<()> {
    log::info!("User {} executing: {}", username, command);
    
    // Execute command (in production, use proper sandboxing)
    match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .await
    {
        Ok(output) => {
            if !output.stdout.is_empty() {
                let response = Message::Channel(ChannelMessage::Data {
                    channel_id,
                    data: output.stdout,
                });
                transport.send_message(&response).await?;
            }
            
            if !output.stderr.is_empty() {
                let error_response = Message::Channel(ChannelMessage::Data {
                    channel_id,
                    data: output.stderr,
                });
                transport.send_message(&error_response).await?;
            }
        }
        Err(e) => {
            let error_msg = format!("Command failed: {}\n", e).into_bytes();
            let response = Message::Channel(ChannelMessage::Data {
                channel_id,
                data: error_msg,
            });
            transport.send_message(&response).await?;
        }
    }
    
    // Send EOF
    let eof = Message::Channel(ChannelMessage::Eof { channel_id });
    transport.send_message(&eof).await?;
    
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_server_config() {
        let config = QsshServerConfig::new("127.0.0.1:22222").expect("Failed to create server config");
        assert_eq!(config.listen_addr, "127.0.0.1:22222");
        assert_eq!(config.max_connections, 100);
    }
}