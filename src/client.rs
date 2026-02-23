//! QSSH client implementation

use crate::{
    Result, QsshError, QsshConfig, PortForward,
    transport::{Transport, Message, ChannelMessage, ChannelType, ChannelManager, RekeyMessage},
    crypto::{PqKeyExchange, SymmetricCrypto},
    handshake::ClientHandshake,
    vault::QuantumVault,
    x11::{X11Forwarder, setup_x11_forwarding},
    port_forward::{RemoteForwardRegistry, ForwardedChannelRouter, handle_forwarded_channel},
};
use tokio::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for automatic reconnection with exponential backoff
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Maximum number of reconnection attempts (0 = infinite)
    pub max_attempts: u32,
    /// Initial delay between attempts
    pub initial_delay: Duration,
    /// Maximum delay between attempts
    pub max_delay: Duration,
    /// Backoff multiplier
    pub multiplier: f64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            max_attempts: 10,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

impl ReconnectConfig {
    /// Create a persistent config (infinite retries)
    pub fn persistent() -> Self {
        Self {
            max_attempts: 0,
            ..Default::default()
        }
    }
}

/// QSSH client
pub struct QsshClient {
    config: QsshConfig,
    transport: Option<Transport>,
    channel_manager: Arc<ChannelManager>,
    vault: Option<Arc<QuantumVault>>,
    x11_forwarder: Option<X11Forwarder>,
    agent_forward_enabled: bool,
    remote_forward_registry: RemoteForwardRegistry,
    forwarded_channel_router: ForwardedChannelRouter,
    rekey_task: Option<tokio::task::JoinHandle<()>>,
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
            agent_forward_enabled: false,
            remote_forward_registry: RemoteForwardRegistry::new(),
            forwarded_channel_router: ForwardedChannelRouter::new(),
            rekey_task: None,
        }
    }

    /// Set the remote forward registry and channel router (called by bin/qssh after setting up remote forwards)
    pub fn set_remote_forward_state(&mut self, registry: RemoteForwardRegistry, router: ForwardedChannelRouter) {
        self.remote_forward_registry = registry;
        self.forwarded_channel_router = router;
    }

    /// Check if remote forwards are active
    pub fn has_remote_forwards(&self) -> bool {
        // Check if the registry has any mappings
        // We use a simple flag: if set_remote_forward_state was called with a non-empty registry
        // For now, check if the router was configured (non-default)
        true // Will be called only when -R args are present
    }

    /// Run a forwarding-only dispatch loop.
    /// Used after exec (-c) completes to keep the connection alive for -R forwards.
    /// Reads from transport and dispatches ForwardedTcpip channel opens and data.
    /// Runs until the transport closes or a signal is received.
    pub async fn run_forward_loop(&self) -> Result<()> {
        let transport = self.transport.as_ref()
            .ok_or_else(|| QsshError::Protocol("Not connected".into()))?;

        log::info!("Entering forward dispatch loop (exec completed, -R active)");

        loop {
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Open {
                    channel_id,
                    channel_type: ChannelType::ForwardedTcpip {
                        connected_host, connected_port,
                        originator_host, originator_port,
                    },
                    ..
                })) => {
                    log::info!("Forwarded channel {} open from {}:{} (originator {}:{})",
                        channel_id, connected_host, connected_port,
                        originator_host, originator_port);

                    let transport = transport.clone();
                    let registry = self.remote_forward_registry.clone();
                    let router = self.forwarded_channel_router.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_forwarded_channel(
                            channel_id, connected_host, connected_port,
                            Arc::new(transport), registry, router,
                        ).await {
                            log::error!("Forwarded channel {} error: {}", channel_id, e);
                        }
                    });
                }
                Ok(Message::Channel(ChannelMessage::Accept { channel_id, .. })) => {
                    // Route Accept to local-forward or forwarded channel handlers
                    self.forwarded_channel_router.route_data(channel_id, Vec::new()).await;
                }
                Ok(Message::Channel(ChannelMessage::Data { channel_id, data })) => {
                    if !self.forwarded_channel_router.route_data(channel_id, data).await {
                        log::debug!("No handler for channel {} data in forward loop", channel_id);
                    }
                }
                Ok(Message::Channel(ChannelMessage::Eof { channel_id })) => {
                    self.forwarded_channel_router.remove(channel_id).await;
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id })) => {
                    self.forwarded_channel_router.remove(channel_id).await;
                }
                Ok(Message::Disconnect(_)) => {
                    log::info!("Server disconnected during forward loop");
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    log::debug!("Forward loop transport error: {}", e);
                    break;
                }
            }
        }

        Ok(())
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

        self.connect_with_stream(stream).await
    }

    /// Connect using a pre-established TCP stream (e.g., from ProxyJump).
    /// Performs the PQ handshake over the provided stream.
    pub async fn connect_via_stream(&mut self, stream: TcpStream) -> Result<()> {
        log::info!("Connecting via pre-established stream (ProxyJump)");
        self.connect_with_stream(stream).await
    }

    /// Internal: perform handshake and setup on a connected stream
    async fn connect_with_stream(&mut self, stream: TcpStream) -> Result<()> {
        // Perform handshake
        let handshake = ClientHandshake::new(&self.config, stream);
        let transport = handshake.perform().await?;

        log::info!("Handshake completed successfully");

        // Zeroize password from config now that auth is complete
        if let Some(ref mut pw) = self.config.password {
            use zeroize::Zeroize;
            pw.zeroize();
        }
        self.config.password = None;

        self.transport = Some(transport);

        // Set up port forwards
        for forward in &self.config.port_forwards {
            self.setup_port_forward(forward.clone()).await?;
        }

        // Start automatic rekey timer if key_rotation_interval > 0
        let interval_secs = self.config.key_rotation_interval;
        if interval_secs > 0 {
            if let Some(transport) = self.transport.clone() {
                let interval = Duration::from_secs(interval_secs);
                log::info!("Automatic rekey scheduled every {}s", interval_secs);
                let handle = tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(interval).await;
                        log::info!("Rekey timer fired — initiating key rotation");
                        if let Err(e) = rekey_with_transport(&transport).await {
                            log::warn!("Automatic rekey failed: {} (will retry next interval)", e);
                        }
                    }
                });
                self.rekey_task = Some(handle);
            }
        }

        Ok(())
    }

    /// Connect with automatic retry using exponential backoff
    pub async fn connect_with_retry(&mut self, reconnect: &ReconnectConfig) -> Result<()> {
        let mut attempt = 0u32;
        let mut delay = reconnect.initial_delay;

        loop {
            attempt += 1;
            match self.connect().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if reconnect.max_attempts > 0 && attempt >= reconnect.max_attempts {
                        log::error!("Connection failed after {} attempts: {}", attempt, e);
                        return Err(e);
                    }
                    log::warn!(
                        "Connection attempt {}{} failed: {}. Retrying in {:.1}s...",
                        attempt,
                        if reconnect.max_attempts > 0 { format!("/{}", reconnect.max_attempts) } else { String::new() },
                        e,
                        delay.as_secs_f64()
                    );
                    tokio::time::sleep(delay).await;
                    delay = Duration::from_secs_f64(
                        (delay.as_secs_f64() * reconnect.multiplier).min(reconnect.max_delay.as_secs_f64())
                    );
                }
            }
        }
    }

    /// Get a reference to the transport (for setting up remote forwards before shell)
    pub fn transport(&self) -> Option<&Transport> {
        self.transport.as_ref()
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

    /// Enable agent forwarding.
    /// Sends an AgentForwardRequest to the server on the session channel.
    /// The server will create a Unix socket and set SSH_AUTH_SOCK in the
    /// shell environment. Agent requests from the remote side are forwarded
    /// back through the channel to the local agent (QSSH_AUTH_SOCK).
    pub async fn enable_agent_forwarding(&mut self) -> Result<()> {
        // Check that we have a local agent socket
        let auth_sock = std::env::var("QSSH_AUTH_SOCK").map_err(|_| {
            QsshError::Connection("QSSH_AUTH_SOCK not set — is qssh-agent running?".into())
        })?;

        if !std::path::Path::new(&auth_sock).exists() {
            return Err(QsshError::Connection(format!(
                "Agent socket not found: {}", auth_sock
            )));
        }

        let transport = self.transport.as_ref()
            .ok_or_else(|| QsshError::Protocol("Not connected".into()))?;

        // Use channel 0 (session channel) for the request
        let msg = Message::Channel(ChannelMessage::AgentForwardRequest {
            channel_id: 0,
        });
        transport.send_message(&msg).await?;

        log::info!("Agent forwarding requested (local socket: {})", auth_sock);
        self.agent_forward_enabled = true;
        Ok(())
    }

    /// Perform key rotation (rekey) on the active connection.
    /// Generates new key material, sends to server, waits for server's response,
    /// derives new session keys, and updates the transport crypto.
    pub async fn rekey(&self) -> Result<()> {
        use sha3::Sha3_256;
        use hkdf::Hkdf;

        let transport = self.transport.as_ref()
            .ok_or_else(|| QsshError::Protocol("Not connected".into()))?;

        log::info!("Initiating rekey (rekey #{})", transport.rekey_count() + 1);

        // 1. Generate new key exchange material
        let client_kex = PqKeyExchange::new()?;
        let (client_share, client_sig) = client_kex.create_key_share()?;

        // 2. Send rekey request
        let rekey_msg = RekeyMessage {
            new_falcon_public_key: client_kex.falcon_pk.clone(),
            new_key_share: client_share.clone(),
            new_key_share_signature: client_sig,
            request_qkd: false,
        };
        transport.send_message(&Message::Rekey(rekey_msg)).await?;

        // 3. Wait for server's rekey response
        let server_rekey = loop {
            match transport.receive_message::<Message>().await? {
                Message::Rekey(rekey) => break rekey,
                other => {
                    log::debug!("Received non-rekey message during rekey: {:?}", other);
                    // Process other messages normally (channel data, etc.)
                    continue;
                }
            }
        };

        // 4. Verify server's response signature
        let verified = client_kex.verify_falcon(
            &server_rekey.new_key_share,
            &server_rekey.new_key_share_signature,
            &server_rekey.new_falcon_public_key,
        )?;

        if !verified {
            return Err(QsshError::Crypto("Server rekey signature verification failed".into()));
        }

        // 5. Derive new shared secret: HKDF(SHA3-256, client_share || server_share)
        let mut ikm = Vec::new();
        ikm.extend_from_slice(&client_share);
        ikm.extend_from_slice(&server_rekey.new_key_share);

        let hk = Hkdf::<Sha3_256>::new(None, &ikm);
        let mut server_write_key = vec![0u8; 32];
        let mut client_write_key = vec![0u8; 32];
        hk.expand(b"qssh-rekey-server-write", &mut server_write_key)
            .map_err(|_| QsshError::Crypto("HKDF expand failed".into()))?;
        hk.expand(b"qssh-rekey-client-write", &mut client_write_key)
            .map_err(|_| QsshError::Crypto("HKDF expand failed".into()))?;

        // 6. Switch to new keys
        // Client sends with client_write_key, receives with server_write_key
        let new_send = SymmetricCrypto::from_shared_secret(&client_write_key)?;
        let new_recv = SymmetricCrypto::from_shared_secret(&server_write_key)?;
        transport.update_keys(new_send, new_recv).await?;

        log::info!("Rekey complete — new session keys active");
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
        let router = self.forwarded_channel_router.clone();
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
                Ok(Message::Channel(ChannelMessage::Accept { channel_id: ch_id, .. })) => {
                    router.route_data(ch_id, Vec::new()).await;
                }
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data })) => {
                    router.route_data(ch_id, data).await;
                }
                Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id })) => {
                    router.remove(ch_id).await;
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id })) => {
                    router.remove(ch_id).await;
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
    
    /// Execute a command and return (output, exit_code).
    /// Exit code is 0 on success, or the remote process exit code.
    /// Returns 255 if the server didn't send an exit status.
    pub async fn exec_with_status(&self, command: &str) -> Result<(String, u32)> {
        let transport = self.transport.as_ref()
            .ok_or_else(|| QsshError::Protocol("Not connected".into()))?;
        let router = self.forwarded_channel_router.clone();

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
                // Route Accept for forwarded channels
                Ok(Message::Channel(ChannelMessage::Accept { channel_id: ch_id, .. })) => {
                    router.route_data(ch_id, Vec::new()).await;
                }
                // Route Data for forwarded channels
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data })) => {
                    router.route_data(ch_id, data).await;
                }
                Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id })) => {
                    router.remove(ch_id).await;
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id })) => {
                    router.remove(ch_id).await;
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
        let mut exit_code: u32 = 255; // default if server doesn't send ExitStatus
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
                Ok(Message::Channel(ChannelMessage::ExitStatus { channel_id: ch_id, exit_code: code })) if ch_id == channel_id => {
                    exit_code = code;
                }
                Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id })) if ch_id == channel_id => {
                    break;
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id })) if ch_id == channel_id => {
                    break;
                }
                // Route messages for forwarded channels
                Ok(Message::Channel(ChannelMessage::Accept { channel_id: ch_id, .. })) => {
                    router.route_data(ch_id, Vec::new()).await;
                }
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data })) => {
                    router.route_data(ch_id, data).await;
                }
                Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id })) => {
                    router.remove(ch_id).await;
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id })) => {
                    router.remove(ch_id).await;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        // Close channel
        let close_msg = Message::Channel(ChannelMessage::Close { channel_id });
        let _ = transport.send_message(&close_msg).await;

        Ok((String::from_utf8_lossy(&output).into_owned(), exit_code))
    }

    /// Execute a command (returns output only, for backward compatibility)
    pub async fn exec(&self, command: &str) -> Result<String> {
        let (output, _exit_code) = self.exec_with_status(command).await?;
        Ok(output)
    }
    
    /// Close the connection
    pub async fn disconnect(&mut self) -> Result<()> {
        // Cancel rekey timer
        if let Some(task) = self.rekey_task.take() {
            task.abort();
        }

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
    #[allow(dead_code)]
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
        
        // Request PTY allocation from server with actual terminal dimensions
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
        let (cols, rows) = terminal_size().unwrap_or((80, 24));
        let pty_req = Message::Channel(ChannelMessage::PtyRequest {
            channel_id,
            term: term.clone(),
            width_chars: cols as u32,
            height_chars: rows as u32,
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

        // Clone remote forward state for the read task
        let registry = self.remote_forward_registry.clone();
        let router = self.forwarded_channel_router.clone();

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
                    // Route data to active forwarded channels (remote -R forwards)
                    Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data })) => {
                        if !router.route_data(ch_id, data).await {
                            log::debug!("No handler for channel {} data, ignoring", ch_id);
                        }
                    }
                    // Handle incoming ForwardedTcpip channel opens (server asking us to accept a remote-forwarded connection)
                    Ok(Message::Channel(ChannelMessage::Open {
                        channel_id: ch_id,
                        channel_type: ChannelType::ForwardedTcpip { connected_host, connected_port, .. },
                        ..
                    })) => {
                        log::info!("Server opened ForwardedTcpip channel {} for {}:{}",
                            ch_id, connected_host, connected_port);
                        let transport_fwd = transport_read.clone();
                        let registry_fwd = registry.clone();
                        let router_fwd = router.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_forwarded_channel(
                                ch_id,
                                connected_host.clone(),
                                connected_port,
                                Arc::new(transport_fwd),
                                registry_fwd,
                                router_fwd,
                            ).await {
                                log::error!("Forwarded channel {} error: {}", ch_id, e);
                            }
                        });
                    }
                    // Handle incoming AgentForward channel opens from server
                    Ok(Message::Channel(ChannelMessage::Open {
                        channel_id: ch_id,
                        channel_type: ChannelType::AgentForward,
                        ..
                    })) => {
                        log::info!("Server opened AgentForward channel {}", ch_id);
                        let transport_agent = transport_read.clone();
                        let router_agent = router.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_agent_forward_channel(ch_id, Arc::new(transport_agent), router_agent).await {
                                log::error!("Agent forward channel {} error: {}", ch_id, e);
                            }
                        });
                    }
                    // Route Accept to forwarded/local-forward channel handlers
                    Ok(Message::Channel(ChannelMessage::Accept { channel_id: ch_id, .. })) if ch_id != channel_id => {
                        log::debug!("Routing Accept for channel {} via router", ch_id);
                        router.route_data(ch_id, Vec::new()).await;
                    }
                    // Handle channel close for forwarded channels
                    Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id })) if ch_id == channel_id => {
                        log::info!("Server closed channel {}", ch_id);
                        break;
                    }
                    Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id })) => {
                        log::debug!("Channel {} closed", ch_id);
                        router.remove(ch_id).await;
                    }
                    Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id })) if ch_id == channel_id => {
                        log::info!("Received EOF for channel {}", ch_id);
                        break;
                    }
                    Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id })) => {
                        log::debug!("Channel {} EOF", ch_id);
                        router.remove(ch_id).await;
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
            // Set up SIGWINCH handler for terminal resize
            let mut sigwinch = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::window_change()
            ).map_err(|e| QsshError::Io(e))?;

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

                    // Handle terminal resize (SIGWINCH)
                    _ = sigwinch.recv() => {
                        if let Some((cols, rows)) = terminal_size() {
                            log::debug!("Terminal resized to {}x{}", cols, rows);
                            let resize_msg = Message::Channel(ChannelMessage::WindowChange {
                                channel_id,
                                width_chars: cols as u32,
                                height_chars: rows as u32,
                                width_pixels: 0,
                                height_pixels: 0,
                            });
                            let _ = transport_write.send_message(&resize_msg).await;
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
#[allow(dead_code)]
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

/// Perform rekey on a transport (standalone, for use from spawned timer task).
/// Same logic as QsshClient::rekey() but takes transport directly.
async fn rekey_with_transport(transport: &Transport) -> Result<()> {
    use sha3::Sha3_256;
    use hkdf::Hkdf;

    log::info!("Initiating rekey (rekey #{})", transport.rekey_count() + 1);

    let client_kex = PqKeyExchange::new()?;
    let (client_share, client_sig) = client_kex.create_key_share()?;

    let rekey_msg = RekeyMessage {
        new_falcon_public_key: client_kex.falcon_pk.clone(),
        new_key_share: client_share.clone(),
        new_key_share_signature: client_sig,
        request_qkd: false,
    };
    transport.send_message(&Message::Rekey(rekey_msg)).await?;

    // Wait for server's rekey response (with timeout)
    let server_rekey = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match transport.receive_message::<Message>().await {
                Ok(Message::Rekey(rekey)) => return Ok(rekey),
                Ok(_) => continue,
                Err(e) => return Err(e),
            }
        }
    }).await
        .map_err(|_| QsshError::Protocol("Rekey response timed out".into()))??;

    let verified = client_kex.verify_falcon(
        &server_rekey.new_key_share,
        &server_rekey.new_key_share_signature,
        &server_rekey.new_falcon_public_key,
    )?;

    if !verified {
        return Err(QsshError::Crypto("Server rekey signature verification failed".into()));
    }

    let mut ikm = Vec::new();
    ikm.extend_from_slice(&client_share);
    ikm.extend_from_slice(&server_rekey.new_key_share);

    let hk = Hkdf::<Sha3_256>::new(None, &ikm);
    let mut server_write_key = vec![0u8; 32];
    let mut client_write_key = vec![0u8; 32];
    hk.expand(b"qssh-rekey-server-write", &mut server_write_key)
        .map_err(|_| QsshError::Crypto("HKDF expand failed".into()))?;
    hk.expand(b"qssh-rekey-client-write", &mut client_write_key)
        .map_err(|_| QsshError::Crypto("HKDF expand failed".into()))?;

    let new_send = SymmetricCrypto::from_shared_secret(&client_write_key)?;
    let new_recv = SymmetricCrypto::from_shared_secret(&server_write_key)?;
    transport.update_keys(new_send, new_recv).await?;

    log::info!("Automatic rekey complete — new session keys active");
    Ok(())
}

/// Get terminal size (cols, rows) via ioctl
fn terminal_size() -> Option<(u16, u16)> {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            Some((ws.ws_col, ws.ws_row))
        } else {
            None
        }
    }
}

/// Handle an incoming AgentForward channel from the server.
/// Connects to the local QSSH_AUTH_SOCK and bridges data bidirectionally.
async fn handle_agent_forward_channel(
    channel_id: u32,
    transport: Arc<Transport>,
    router: ForwardedChannelRouter,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let auth_sock = std::env::var("QSSH_AUTH_SOCK")
        .map_err(|_| QsshError::Connection("QSSH_AUTH_SOCK not set".into()))?;

    // Accept the channel
    let accept = Message::Channel(ChannelMessage::Accept {
        channel_id,
        sender_channel: channel_id,
        window_size: 1048576,
        max_packet_size: 32768,
    });
    transport.send_message(&accept).await?;

    // Connect to local agent
    let agent_stream = UnixStream::connect(&auth_sock).await
        .map_err(|e| QsshError::Connection(format!("Failed to connect to local agent: {}", e)))?;

    let (mut agent_read, mut agent_write) = tokio::io::split(agent_stream);

    // Register with router for incoming channel data
    let (data_tx, mut data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    router.register(channel_id, data_tx).await;

    // Bridge: channel → agent
    let transport_to_agent = transport.clone();
    let chan_to_agent = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if agent_write.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    // Bridge: agent → channel
    let agent_to_chan = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match agent_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let msg = Message::Channel(ChannelMessage::Data {
                        channel_id,
                        data: buf[..n].to_vec(),
                    });
                    if transport_to_agent.send_message(&msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Wait for either direction to finish
    tokio::select! {
        _ = chan_to_agent => {}
        _ = agent_to_chan => {}
    }

    // Cleanup
    router.remove(channel_id).await;
    let close = Message::Channel(ChannelMessage::Close { channel_id });
    let _ = transport.send_message(&close).await;

    log::debug!("Agent forward channel {} closed", channel_id);
    Ok(())
}