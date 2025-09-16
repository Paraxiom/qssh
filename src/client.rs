//! QSSH client implementation

use crate::{
    Result, QsshError, QsshConfig, PortForward,
    transport::{Transport, Message, ChannelMessage, ChannelType, ChannelManager},
    handshake::ClientHandshake,
    vault::{QuantumVault, KeyType},
    x11::{X11Forwarder, setup_x11_forwarding},
};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

/// QSSH client
pub struct QsshClient {
    config: QsshConfig,
    transport: Option<Transport>,
    channel_manager: Arc<ChannelManager>,
    vault: Option<Arc<QuantumVault>>,
    x11_forwarder: Option<X11Forwarder>,
}

impl QsshClient {
    /// Create new QSSH client
    pub fn new(config: QsshConfig) -> Self {
        Self {
            config,
            transport: None,
            channel_manager: Arc::new(ChannelManager::new()),
            vault: None,
            x11_forwarder: None,
        }
    }
    
    /// Initialize with quantum vault for enhanced security
    pub async fn with_vault(mut self, master_key: &[u8]) -> Result<Self> {
        let mut vault = QuantumVault::new();
        vault.init(master_key).await?;
        self.vault = Some(Arc::new(vault));
        Ok(self)
    }
    
    /// Connect to QSSH server
    pub async fn connect(&mut self) -> Result<()> {
        // Parse server address
        let addr = self.config.server.clone();
        
        // Connect TCP
        let stream = TcpStream::connect(&addr).await
            .map_err(|e| QsshError::Connection(format!("Failed to connect to {}: {}", addr, e)))?;
        
        log::info!("Connected to {}", addr);
        
        // Perform handshake
        let handshake = ClientHandshake::new(&self.config, stream);
        let transport = handshake.perform().await?;
        
        log::info!("Handshake completed successfully");
        
        self.transport = Some(transport);
        
        // Don't start background transport handler - it conflicts with shell mode
        // The shell session will handle its own transport messages
        // self.start_transport_handler();
        
        // Set up port forwards
        for forward in &self.config.port_forwards {
            self.setup_port_forward(forward.clone()).await?;
        }
        
        Ok(())
    }

    /// Enable X11 forwarding
    pub async fn enable_x11(&mut self, trusted: bool) -> Result<()> {
        if let Some(ref transport) = self.transport {
            let forwarder = setup_x11_forwarding(
                Arc::new(transport.clone()),
                true,
                trusted
            ).await?;

            if let Some(fwd) = forwarder {
                log::info!("X11 forwarding enabled: DISPLAY={}", fwd.get_display());
                self.x11_forwarder = Some(fwd);
            }
        }
        Ok(())
    }

    /// Open an interactive shell session
    pub async fn shell(&self) -> Result<()> {
        let transport = self.transport.as_ref()
            .ok_or_else(|| QsshError::Protocol("Not connected".into()))?;
        
        // Open shell channel
        let channel_id = self.channel_manager.open_channel(ChannelType::Session).await?;
        
        let open_msg = Message::Channel(ChannelMessage::Open {
            channel_id,
            channel_type: ChannelType::Session,
            window_size: 1024 * 1024,
            max_packet_size: 32768,
        });
        
        transport.send_message(&open_msg).await?;
        
        // Wait for channel accept confirmation
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                return Err(QsshError::Protocol("Timeout waiting for channel accept".into()));
            }
            
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Accept { channel_id: ch_id, .. })) if ch_id == channel_id => {
                    log::debug!("Channel {} accepted by server", channel_id);
                    break;
                }
                Ok(msg) => {
                    log::debug!("Received while waiting for accept: {:?}", msg);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        // Handle interactive shell
        self.handle_shell_session(channel_id).await
    }
    
    /// Execute a command
    pub async fn exec(&self, command: &str) -> Result<String> {
        let transport = self.transport.as_ref()
            .ok_or_else(|| QsshError::Protocol("Not connected".into()))?;
        
        // Open exec channel
        let channel_id = self.channel_manager.open_channel(ChannelType::Session).await?;
        
        let open_msg = Message::Channel(ChannelMessage::Open {
            channel_id,
            channel_type: ChannelType::Session,
            window_size: 1024 * 1024,
            max_packet_size: 32768,
        });
        
        transport.send_message(&open_msg).await?;
        
        // Wait for channel accept
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                return Err(QsshError::Protocol("Timeout waiting for channel accept".into()));
            }
            
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Accept { channel_id: ch_id, .. })) if ch_id == channel_id => {
                    break;
                }
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        
        // Send exec request
        let exec_msg = Message::Channel(ChannelMessage::ExecRequest {
            channel_id,
            command: command.to_string(),
        });
        
        transport.send_message(&exec_msg).await?;
        
        // Collect output
        let mut output = Vec::new();
        let timeout = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();
        
        loop {
            if start.elapsed() > timeout {
                break;
            }
            
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data })) if ch_id == channel_id => {
                    output.extend_from_slice(&data);
                }
                Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id })) if ch_id == channel_id => {
                    break;
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id })) if ch_id == channel_id => {
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        
        // Close channel
        let close_msg = Message::Channel(ChannelMessage::Close { channel_id });
        let _ = transport.send_message(&close_msg).await;
        
        Ok(String::from_utf8_lossy(&output).into_owned())
    }
    
    /// Close the connection
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(transport) = &self.transport {
            let disconnect_msg = Message::Disconnect(crate::transport::DisconnectMessage {
                reason_code: crate::transport::protocol::disconnect_reasons::BY_APPLICATION,
                description: "Client disconnecting".into(),
            });
            
            transport.send_message(&disconnect_msg).await?;
            transport.close().await?;
        }
        
        self.transport = None;
        Ok(())
    }
    
    /// Start background transport handler
    fn start_transport_handler(&self) -> Result<()> {
        let transport = self.transport.as_ref()
            .ok_or_else(|| QsshError::Protocol("Transport not available".into()))?
            .clone();
        let channel_manager = self.channel_manager.clone();
        
        tokio::spawn(async move {
            loop {
                match transport.receive_message::<Message>().await {
                    Ok(msg) => {
                        if let Err(e) = handle_message(msg, &channel_manager).await {
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
        });

        Ok(())
    }
    
    /// Set up port forwarding
    async fn setup_port_forward(&self, forward: PortForward) -> Result<()> {
        let channel_manager = self.channel_manager.clone();
        
        tokio::spawn(async move {
            let mut port_forward = crate::transport::channel::PortForward::new(
                forward.local_port,
                forward.remote_host,
                forward.remote_port,
            );
            
            if let Err(e) = port_forward.start(channel_manager).await {
                log::error!("Port forward failed: {}", e);
            }
        });
        
        Ok(())
    }
    
    /// Handle interactive shell session
    async fn handle_shell_session(&self, channel_id: u32) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let transport = self.transport.as_ref()
            .ok_or_else(|| QsshError::Protocol("Transport not available".into()))?
            .clone();
        
        log::info!("Shell session started (channel {})", channel_id);
        
        // Request PTY allocation from server
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
        let pty_req = Message::Channel(ChannelMessage::PtyRequest {
            channel_id,
            term: term.clone(),
            width_chars: 80,
            height_chars: 24,
            width_pixels: 0,
            height_pixels: 0,
            modes: vec![], // Terminal modes
        });
        transport.send_message(&pty_req).await?;
        
        // Request shell
        let shell_req = Message::Channel(ChannelMessage::ShellRequest { channel_id });
        transport.send_message(&shell_req).await?;
        
        // Wait a moment for shell to be ready
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        
        // Set terminal to raw mode
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        
        // Save current terminal settings and set raw mode (only if we have a TTY)
        let is_tty = atty::is(atty::Stream::Stdin);
        log::debug!("Terminal is TTY: {}", is_tty);
        
        let term_settings = if is_tty {
            match termios::Termios::from_fd(0) {
                Ok(settings) => {
                    log::debug!("Setting terminal to raw mode");
                    let mut raw = settings.clone();
                    termios::cfmakeraw(&mut raw);
                    match termios::tcsetattr(0, termios::TCSANOW, &raw) {
                        Ok(_) => {
                            Some(settings)
                        },
                        Err(e) => {
                            log::warn!("Could not set raw mode: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Could not get terminal settings: {}", e);
                    None
                }
            }
        } else {
            log::debug!("Not a TTY, skipping terminal raw mode");
            None
        };
        
        // Don't use BufReader for raw mode - read directly
        let mut stdin = stdin;
        let mut buffer = vec![0u8; 1024];
        
        // Clone transport for reading in separate task
        let transport_read = transport.clone();
        let transport_write = transport.clone();
        
        // Spawn task to handle incoming messages from server
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let read_task = tokio::spawn(async move {
            loop {
                match transport_read.receive_message::<Message>().await {
                    Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data })) if ch_id == channel_id => {
                        // Filter out single null bytes (success indicators)
                        if data.len() == 1 && data[0] == 0 {
                            continue;
                        }
                        let preview = String::from_utf8_lossy(&data[..std::cmp::min(50, data.len())]);
                        log::debug!("Received {} bytes of data from server: {:?}", data.len(), preview);
                        if tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id })) if ch_id == channel_id => {
                        log::info!("Received EOF for channel {}", ch_id);
                        break;
                    }
                    Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id })) if ch_id == channel_id => {
                        log::info!("Server closed channel {}", ch_id);
                        break;
                    }
                    Ok(msg) => {
                        log::debug!("Received other message: {:?}", msg);
                    }
                    Err(e) => {
                        log::error!("Transport receive error: {}", e);
                        break;
                    }
                }
            }
        });
        
        // If not a TTY, use a different approach to avoid immediate EOF
        let result = if is_tty {
            // Interactive mode - read from stdin
            loop {
                tokio::select! {
                    // Read from stdin and send to server
                    result = stdin.read(&mut buffer) => {
                        match result {
                            Ok(0) => {
                                break Ok(())
                            }, // EOF
                            Ok(n) => {
                                log::debug!("Sending {} bytes to server", n);
                                let data_msg = Message::Channel(ChannelMessage::Data {
                                    channel_id,
                                    data: buffer[..n].to_vec(),
                                });
                                match transport_write.send_message(&data_msg).await {
                                    Ok(_) => {
                                    }
                                    Err(e) => {
                                        break Err(e);
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Stdin error: {}", e);
                                break Err(e.into());
                            }
                        }
                    }
                    
                    // Receive data from server and write to stdout
                    Some(data) = rx.recv() => {
                        // Write data immediately to stdout
                        if let Err(e) = stdout.write_all(&data).await {
                            log::error!("Stdout error: {}", e);
                            break Err(e.into());
                        }
                        // Force flush to ensure immediate display
                        if let Err(e) = stdout.flush().await {
                            log::error!("Stdout flush error: {}", e);
                            break Err(e.into());
                        }
                    }
                }
            }
        } else {
            // Non-TTY mode but still interactive - handle both input and output
            log::debug!("Non-TTY mode: handling interactive session");
            
            loop {
                tokio::select! {
                    // Read from stdin and send to server
                    result = stdin.read(&mut buffer) => {
                        match result {
                            Ok(0) => {
                                break Ok(())
                            }, // EOF
                            Ok(n) => {
                                log::debug!("Sending {} bytes to server", n);
                                let data_msg = Message::Channel(ChannelMessage::Data {
                                    channel_id,
                                    data: buffer[..n].to_vec(),
                                });
                                if let Err(e) = transport_write.send_message(&data_msg).await {
                                    break Err(e);
                                }
                            }
                            Err(e) => {
                                log::error!("Stdin error: {}", e);
                                break Err(e.into());
                            }
                        }
                    }
                    
                    // Receive data from server and write to stdout
                    Some(data) = rx.recv() => {
                        if let Err(e) = stdout.write_all(&data).await {
                            log::error!("Stdout error: {}", e);
                            break Err(e.into());
                        }
                        if let Err(e) = stdout.flush().await {
                            log::error!("Stdout flush error: {}", e);
                            break Err(e.into());
                        }
                    }
                }
            }
        };
        
        // Abort the read task
        read_task.abort();
        
        // Restore terminal settings (if we changed them)
        if let Some(settings) = term_settings {
            termios::tcsetattr(0, termios::TCSANOW, &settings)
                .map_err(|e| QsshError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        }
        
        // Close channel
        let close_msg = Message::Channel(ChannelMessage::Close { channel_id });
        let _ = transport.send_message(&close_msg).await;
        
        result
    }
}

/// Handle incoming messages
async fn handle_message(msg: Message, channel_manager: &ChannelManager) -> Result<()> {
    match msg {
        Message::Channel(channel_msg) => {
            channel_manager.handle_message(channel_msg).await?;
        }
        Message::Disconnect(d) => {
            log::info!("Server disconnected: {}", d.description);
            return Err(QsshError::Connection("Server disconnected".into()));
        }
        Message::Ping(nonce) => {
            // Send pong (would need transport reference)
            log::debug!("Received ping: {}", nonce);
        }
        _ => {
            log::debug!("Unhandled message type");
        }
    }
    Ok(())
}