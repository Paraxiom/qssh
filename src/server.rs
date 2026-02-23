//! QSSH server implementation

use crate::{
    Result, QsshError,
    audit::AuditLogger,
    crypto::{PqKeyExchange, SymmetricCrypto},
    transport::{Transport, Message, ChannelMessage, ChannelType, RekeyMessage,
        GlobalRequestMessage, GlobalRequestType, GlobalRequestSuccessMessage},
    handshake::ServerHandshake,
    shell_handler_thread::ShellSessionThread,
    port_forward::ForwardedChannelRouter,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

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
    /// Path to QKD client certificate
    pub qkd_cert_path: Option<String>,
    /// Path to QKD client private key
    pub qkd_key_path: Option<String>,
    /// Path to QKD CA certificate
    pub qkd_ca_path: Option<String>,
    /// Structured audit logger (hash-chained JSONL)
    pub audit: AuditLogger,
}

impl QsshServerConfig {
    pub fn new(listen_addr: &str) -> Result<Self> {
        let host_key = PqKeyExchange::new()?;
        let audit_path = std::env::var("QSSH_AUDIT_LOG")
            .unwrap_or_else(|_| "/var/log/qssh/audit.jsonl".to_string());

        Ok(Self {
            listen_addr: listen_addr.to_string(),
            host_key: Arc::new(host_key),
            max_connections: 100,
            authorized_keys: HashMap::new(),
            qkd_enabled: false,
            qkd_endpoint: None,
            quantum_native: true,  // Default to quantum-native
            qkd_cert_path: None,
            qkd_key_path: None,
            qkd_ca_path: None,
            audit: AuditLogger::new(std::path::PathBuf::from(audit_path)),
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
            
            let addr_str = addr.to_string();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, config, connections, &addr_str).await {
                    log::error!("Connection error: {}", e);
                }
            });
        }
    }
}

/// Client connection state
struct ClientConnection {
    _username: String,
    _transport: Transport,
    channels: HashMap<u32, Channel>,
}

/// Channel state
struct Channel {
    _id: u32,
    _channel_type: ChannelType,
    /// PTY info stored from PtyRequest, used when ShellRequest arrives
    pty: Option<PtyInfo>,
    /// X11 display string, set when X11Request is received
    x11_display: Option<X11Display>,
}

/// PTY settings received from PtyRequest
#[derive(Clone)]
struct PtyInfo {
    term: String,
    width: u16,
    height: u16,
}

/// X11 display to set in the shell environment
#[derive(Clone)]
#[allow(dead_code)]
struct X11Display {
    display: String,
}

/// X11 forwarding state for a session channel on the server side.
/// The server listens on localhost:6000+display and forwards connections
/// to the client via X11 channels.
#[derive(Clone)]
#[allow(dead_code)]
struct X11ForwardState {
    display_number: u32,
    auth_protocol: String,
    auth_cookie: String,
    single_connection: bool,
}

/// State for remote forwarding listeners on the server side.
/// Tracks active listeners so they can be cancelled and cleaned up.
struct RemoteForwardState {
    listeners: HashMap<(String, u16), tokio::task::JoinHandle<()>>,
}

impl RemoteForwardState {
    fn new() -> Self {
        Self {
            listeners: HashMap::new(),
        }
    }

    /// Abort all active listeners (called on client disconnect)
    fn abort_all(&mut self) {
        for ((host, port), handle) in self.listeners.drain() {
            log::info!("Cancelling remote forward listener on {}:{}", host, port);
            handle.abort();
        }
    }
}

/// Handle a client connection
async fn handle_connection(
    stream: TcpStream,
    config: QsshServerConfig,
    connections: Arc<Mutex<HashMap<String, ClientConnection>>>,
    remote_addr: &str,
) -> Result<()> {
    let audit = &config.audit;
    audit.log("connect", None, Some(remote_addr), None, true).await;

    // Perform handshake
    // For now, recreate the host key since PqKeyExchange doesn't implement Clone
    let host_key = PqKeyExchange::new()?;
    let handshake = ServerHandshake::new(stream, host_key)
        .with_qkd_endpoint(config.qkd_endpoint.clone());
    let (transport, username) = match handshake.perform().await {
        Ok(result) => {
            audit.log("auth", Some(&result.1), Some(remote_addr), Some("handshake success"), true).await;
            result
        }
        Err(e) => {
            audit.log("auth", None, Some(remote_addr), Some(&format!("handshake failed: {}", e)), false).await;
            return Err(e);
        }
    };

    log::info!("User {} authenticated successfully", username);
    
    // Create connection state
    let connection = ClientConnection {
        _username: username.clone(),
        _transport: transport.clone(),
        channels: HashMap::new(),
    };
    
    // Store connection
    {
        let mut conns = connections.lock().await;
        conns.insert(username.clone(), connection);
    }

    // Remote forward state for this connection
    let remote_forward_state = Arc::new(Mutex::new(RemoteForwardState::new()));
    // Channel router: shared between shell handler and remote forward connections
    let channel_router = ForwardedChannelRouter::new();
    // X11 forwarding state: set when client sends X11Request
    let x11_state: Arc<Mutex<Option<X11ForwardState>>> = Arc::new(Mutex::new(None));

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

                if let Err(e) = handle_client_message(
                    msg, &transport, &username, &connections,
                    &remote_forward_state, &channel_router,
                    &x11_state, audit,
                ).await {
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

    // Clean up remote forward listeners
    {
        let mut rfs = remote_forward_state.lock().await;
        rfs.abort_all();
    }

    // Remove connection
    {
        let mut conns = connections.lock().await;
        conns.remove(&username);
    }

    audit.log("disconnect", Some(&username), Some(remote_addr), None, true).await;
    log::info!("User {} disconnected", username);

    Ok(())
}

/// Handle client message
async fn handle_client_message(
    msg: Message,
    transport: &Transport,
    username: &str,
    connections: &Arc<Mutex<HashMap<String, ClientConnection>>>,
    remote_forward_state: &Arc<Mutex<RemoteForwardState>>,
    channel_router: &ForwardedChannelRouter,
    x11_state: &Arc<Mutex<Option<X11ForwardState>>>,
    audit: &AuditLogger,
) -> Result<()> {
    match msg {
        Message::Channel(channel_msg) => {
            handle_channel_message(channel_msg, transport, username, connections, channel_router, x11_state, audit).await?;
        }
        Message::GlobalRequest(req) => {
            handle_global_request(req, transport, username, remote_forward_state, channel_router).await?;
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
            handle_rekey(rekey, transport, username).await?;
        }
        _ => {
            log::debug!("Unhandled message from {}", username);
        }
    }
    Ok(())
}

/// Handle rekey request from client.
/// Server verifies client's new key share, generates its own new key material,
/// derives new session keys, sends response, and updates transport crypto.
async fn handle_rekey(
    client_rekey: RekeyMessage,
    transport: &Transport,
    username: &str,
) -> Result<()> {
    use sha3::Sha3_256;
    use hkdf::Hkdf;

    log::info!("Processing rekey from {} (rekey #{})", username, transport.rekey_count() + 1);

    // 1. Generate server's new key exchange (also used for verification)
    let server_kex = PqKeyExchange::new()?;

    // 2. Verify the client's key share signature using their public key
    let verified = server_kex.verify_falcon(
        &client_rekey.new_key_share,
        &client_rekey.new_key_share_signature,
        &client_rekey.new_falcon_public_key,
    )?;

    if !verified {
        log::warn!("Rekey signature verification failed for {}", username);
        return Err(QsshError::Crypto("Rekey signature verification failed".into()));
    }
    let (server_share, server_sig) = server_kex.create_key_share()?;

    // 3. Derive new shared secret: HKDF(SHA3-256, client_share || server_share)
    let mut ikm = Vec::new();
    ikm.extend_from_slice(&client_rekey.new_key_share);
    ikm.extend_from_slice(&server_share);

    let hk = Hkdf::<Sha3_256>::new(None, &ikm);
    let mut server_write_key = vec![0u8; 32];
    let mut client_write_key = vec![0u8; 32];
    hk.expand(b"qssh-rekey-server-write", &mut server_write_key)
        .map_err(|_| QsshError::Crypto("HKDF expand failed for server write key".into()))?;
    hk.expand(b"qssh-rekey-client-write", &mut client_write_key)
        .map_err(|_| QsshError::Crypto("HKDF expand failed for client write key".into()))?;

    // 4. Send server's rekey response (before switching keys!)
    let server_rekey = RekeyMessage {
        new_falcon_public_key: server_kex.falcon_pk.clone(),
        new_key_share: server_share,
        new_key_share_signature: server_sig,
        request_qkd: false,
    };
    transport.send_message(&Message::Rekey(server_rekey)).await?;

    // 5. Switch to new keys
    // Server sends with server_write_key, receives with client_write_key
    let new_send = SymmetricCrypto::from_shared_secret(&server_write_key)?;
    let new_recv = SymmetricCrypto::from_shared_secret(&client_write_key)?;
    transport.update_keys(new_send, new_recv).await?;

    log::info!("Rekey complete for {} — new session keys active", username);
    Ok(())
}

/// Handle a global request from the client (e.g., TcpipForward for -R)
async fn handle_global_request(
    req: GlobalRequestMessage,
    transport: &Transport,
    username: &str,
    remote_forward_state: &Arc<Mutex<RemoteForwardState>>,
    channel_router: &ForwardedChannelRouter,
) -> Result<()> {
    match req.request_type {
        GlobalRequestType::TcpipForward { bind_host, bind_port } => {
            log::info!("User {} requesting tcpip-forward on {}:{}", username, bind_host, bind_port);

            // Determine the bind address — empty or "0.0.0.0" means all interfaces
            let bind_addr = if bind_host.is_empty() || bind_host == "0.0.0.0" {
                format!("0.0.0.0:{}", bind_port)
            } else if bind_host == "localhost" || bind_host == "127.0.0.1" {
                format!("127.0.0.1:{}", bind_port)
            } else {
                format!("{}:{}", bind_host, bind_port)
            };

            // Try to bind the listener
            match TcpListener::bind(&bind_addr).await {
                Ok(listener) => {
                    let actual_port = listener.local_addr()
                        .map(|a| a.port())
                        .unwrap_or(bind_port);

                    log::info!("Remote forward listener bound on {} (actual port {})", bind_addr, actual_port);

                    // Reply success
                    if req.want_reply {
                        transport.send_message(&Message::GlobalRequestSuccess(
                            GlobalRequestSuccessMessage { bound_port: actual_port }
                        )).await?;
                    }

                    // Spawn the accept loop
                    let transport_clone = transport.clone();
                    let router_clone = channel_router.clone();
                    let bind_host_clone = bind_host.clone();
                    let handle = tokio::spawn(async move {
                        handle_remote_forward_listener(
                            listener, transport_clone, router_clone,
                            bind_host_clone, actual_port,
                        ).await;
                    });

                    // Store the listener handle for cleanup
                    let mut rfs = remote_forward_state.lock().await;
                    rfs.listeners.insert((bind_host, actual_port), handle);
                }
                Err(e) => {
                    log::error!("Failed to bind remote forward on {}: {}", bind_addr, e);
                    if req.want_reply {
                        transport.send_message(&Message::GlobalRequestFailure).await?;
                    }
                }
            }
        }
        GlobalRequestType::CancelTcpipForward { bind_host, bind_port } => {
            log::info!("User {} cancelling tcpip-forward on {}:{}", username, bind_host, bind_port);

            let mut rfs = remote_forward_state.lock().await;
            if let Some(handle) = rfs.listeners.remove(&(bind_host.clone(), bind_port)) {
                handle.abort();
                log::info!("Cancelled remote forward on {}:{}", bind_host, bind_port);
                if req.want_reply {
                    transport.send_message(&Message::GlobalRequestSuccess(
                        GlobalRequestSuccessMessage { bound_port: bind_port }
                    )).await?;
                }
            } else {
                log::warn!("No active remote forward on {}:{}", bind_host, bind_port);
                if req.want_reply {
                    transport.send_message(&Message::GlobalRequestFailure).await?;
                }
            }
        }
    }
    Ok(())
}

/// Accept loop for a remote-forwarded port on the server.
/// For each incoming TCP connection, opens a ForwardedTcpip channel back to the client
/// and bridges data bidirectionally.
async fn handle_remote_forward_listener(
    listener: TcpListener,
    transport: Transport,
    channel_router: ForwardedChannelRouter,
    bind_host: String,
    bind_port: u16,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                log::info!("Remote forward connection from {} on {}:{}", peer_addr, bind_host, bind_port);

                let transport = transport.clone();
                let router = channel_router.clone();
                let bind_host = bind_host.clone();
                let originator_host = peer_addr.ip().to_string();
                let originator_port = peer_addr.port();

                tokio::spawn(async move {
                    if let Err(e) = handle_remote_forward_connection(
                        stream, transport, router, bind_host, bind_port,
                        originator_host, originator_port,
                    ).await {
                        log::error!("Remote forward connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                log::error!("Remote forward accept error on {}:{}: {}", bind_host, bind_port, e);
                break;
            }
        }
    }
}

/// Handle a single connection to a remote-forwarded port.
/// Opens a ForwardedTcpip channel to the client, registers with the channel router
/// to receive data, then bridges TCP stream <-> channel data bidirectionally.
async fn handle_remote_forward_connection(
    tcp_stream: TcpStream,
    transport: Transport,
    channel_router: ForwardedChannelRouter,
    bind_host: String,
    bind_port: u16,
    originator_host: String,
    originator_port: u16,
) -> Result<()> {
    // Generate channel ID
    let channel_id = rand::random::<u32>() % 65536;

    // Register with router BEFORE sending Open, so we can receive the Accept
    let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(256);
    channel_router.register(channel_id, data_tx).await;

    // Open a ForwardedTcpip channel to the client
    let open_msg = Message::Channel(ChannelMessage::Open {
        channel_id,
        channel_type: ChannelType::ForwardedTcpip {
            connected_host: bind_host.clone(),
            connected_port: bind_port,
            originator_host: originator_host.clone(),
            originator_port,
        },
        window_size: 1024 * 1024,
        max_packet_size: 32768,
    });

    transport.send_message(&open_msg).await?;

    // Wait for Accept from client (arrives as empty vec via router)
    let accept_timeout = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        data_rx.recv(),
    ).await;

    match accept_timeout {
        Ok(Some(data)) if data.is_empty() => {
            log::debug!("Client accepted forwarded channel {}", channel_id);
        }
        Ok(Some(_)) => {
            // Got data before accept — unexpected but continue
            log::warn!("Got data before accept on channel {}", channel_id);
        }
        _ => {
            channel_router.remove(channel_id).await;
            return Err(QsshError::Protocol("Timeout waiting for channel accept from client".into()));
        }
    }

    // Bridge: TCP stream <-> channel data (bidirectional)
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // TCP -> channel (read from local TCP, send via transport to client)
    let transport_send = transport.clone();
    let router_clone = channel_router.clone();
    let tcp_to_channel = tokio::spawn(async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            match tcp_read.read(&mut buffer).await {
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
        router_clone.remove(channel_id).await;
    });

    // Channel -> TCP (receive from router, write to local TCP)
    let channel_to_tcp = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if data.is_empty() {
                continue; // control signal
            }
            if tcp_write.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    // Wait for either direction to finish
    tokio::select! {
        _ = tcp_to_channel => {}
        _ = channel_to_tcp => {}
    }

    channel_router.remove(channel_id).await;
    Ok(())
}

/// Handle channel message
async fn handle_channel_message(
    msg: ChannelMessage,
    transport: &Transport,
    username: &str,
    connections: &Arc<Mutex<HashMap<String, ClientConnection>>>,
    channel_router: &ForwardedChannelRouter,
    x11_state: &Arc<Mutex<Option<X11ForwardState>>>,
    audit: &AuditLogger,
) -> Result<()> {
    match msg {
        ChannelMessage::Open { channel_id, channel_type, window_size, max_packet_size } => {
            log::info!("User {} opening channel {} ({:?})", username, channel_id, channel_type);

            // Handle DirectTcpip channel opens (local port forwarding, -L)
            if let ChannelType::DirectTcpip { ref host, port, .. } = channel_type {
                let target_host = host.clone();
                let target_port = port;
                let target_addr = format!("{}:{}", target_host, target_port);
                log::info!("DirectTcpip forward: connecting to {}", target_addr);

                match TcpStream::connect(&target_addr).await {
                    Ok(tcp_stream) => {
                        // Accept the channel
                        let accept = Message::Channel(ChannelMessage::Accept {
                            channel_id,
                            sender_channel: channel_id,
                            window_size,
                            max_packet_size,
                        });
                        transport.send_message(&accept).await?;

                        // Register channel with router for data dispatch
                        let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(256);
                        channel_router.register(channel_id, data_tx).await;

                        // Bridge TCP stream <-> channel data
                        let transport_bridge = transport.clone();
                        let channel_router_bridge = channel_router.clone();
                        tokio::spawn(async move {
                            let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

                            // TCP -> channel (forward data from target to client)
                            let transport_out = transport_bridge.clone();
                            let tcp_to_channel = tokio::spawn(async move {
                                let mut buf = vec![0u8; 8192];
                                loop {
                                    match tcp_read.read(&mut buf).await {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            let msg = Message::Channel(ChannelMessage::Data {
                                                channel_id,
                                                data: buf[..n].to_vec(),
                                            });
                                            if transport_out.send_message(&msg).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });

                            // Channel -> TCP (forward data from client to target)
                            let channel_to_tcp = tokio::spawn(async move {
                                while let Some(data) = data_rx.recv().await {
                                    if data.is_empty() { continue; }
                                    if tcp_write.write_all(&data).await.is_err() {
                                        break;
                                    }
                                }
                            });

                            tokio::select! {
                                _ = tcp_to_channel => {}
                                _ = channel_to_tcp => {}
                            }

                            channel_router_bridge.remove(channel_id).await;
                            let eof = Message::Channel(ChannelMessage::Eof { channel_id });
                            let _ = transport_bridge.send_message(&eof).await;
                            log::debug!("DirectTcpip bridge ended for channel {}", channel_id);
                        });
                    }
                    Err(e) => {
                        log::error!("Failed to connect to {}: {}", target_addr, e);
                        // Reject the channel by sending close
                        let close = Message::Channel(ChannelMessage::Close { channel_id });
                        transport.send_message(&close).await?;
                    }
                }

                // Store channel
                let mut conns = connections.lock().await;
                if let Some(conn) = conns.get_mut(username) {
                    conn.channels.insert(channel_id, Channel {
                        _id: channel_id,
                        _channel_type: channel_type,
                        pty: None,
                        x11_display: None,
                    });
                }
                return Ok(());
            }

            // Accept channel (non-DirectTcpip)
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
                    _id: channel_id,
                    _channel_type: channel_type,
                    pty: None,
                    x11_display: None,
                });
            }
        }
        ChannelMessage::Accept { channel_id, .. } => {
            // Route Accept to forwarded channel handlers (for -R)
            if channel_router.has_channel(channel_id).await {
                log::debug!("Routing Accept for forwarded channel {} via router", channel_id);
                channel_router.route_data(channel_id, Vec::new()).await;
            }
        }
        ChannelMessage::Data { channel_id, data } => {
            // Route to forwarded channel handler if registered
            if channel_router.has_channel(channel_id).await {
                channel_router.route_data(channel_id, data).await;
            } else {
                log::debug!("User {} sent {} bytes on channel {}", username, data.len(), channel_id);
            }
        }
        ChannelMessage::Eof { channel_id } => {
            if channel_router.has_channel(channel_id).await {
                channel_router.remove(channel_id).await;
            }
        }
        ChannelMessage::Close { channel_id } => {
            log::info!("User {} closing channel {}", username, channel_id);

            // Route to forwarded channel handler if registered
            if channel_router.has_channel(channel_id).await {
                channel_router.remove(channel_id).await;
            }

            // Remove channel
            let mut conns = connections.lock().await;
            if let Some(conn) = conns.get_mut(username) {
                conn.channels.remove(&channel_id);
            }
        }
        ChannelMessage::PtyRequest { channel_id, term, width_chars, height_chars, .. } => {
            log::info!("User {} requesting PTY on channel {} ({}x{} {})",
                username, channel_id, width_chars, height_chars, term);

            // Store PTY settings for use when ShellRequest arrives
            {
                let mut conns = connections.lock().await;
                if let Some(conn) = conns.get_mut(username) {
                    if let Some(ch) = conn.channels.get_mut(&channel_id) {
                        ch.pty = Some(PtyInfo {
                            term: term.clone(),
                            width: width_chars as u16,
                            height: height_chars as u16,
                        });
                    }
                }
            }

            // Acknowledge with success
            let success = Message::Channel(ChannelMessage::Data {
                channel_id,
                data: vec![0], // Success indicator
            });
            transport.send_message(&success).await?;
        }
        ChannelMessage::ShellRequest { channel_id } => {
            log::info!("User {} requesting shell on channel {}", username, channel_id);

            // Get PTY dimensions from stored channel info
            let pty_info = {
                let conns = connections.lock().await;
                conns.get(username)
                    .and_then(|conn| conn.channels.get(&channel_id))
                    .and_then(|ch| ch.pty.clone())
            };
            let (term, width, height) = match pty_info {
                Some(info) => (info.term, info.width, info.height),
                None => ("xterm-256color".to_string(), 80, 24),
            };

            // Spawn real shell session
            match ShellSessionThread::new(
                channel_id,
                transport.clone(),
                username.to_string(),
                Some(term),
                width,
                height,
            ).await {
                Ok(mut session) => {
                    log::info!("Starting shell session for user {} on channel {}", username, channel_id);
                    log::info!("Shell handler taking over transport - running inline");

                    // Give the shell handler the channel router so it can dispatch
                    // forwarded channel messages (for -R remote port forwarding)
                    let (_fwd_tx, _fwd_rx) = mpsc::channel(16);
                    session.set_channel_router(channel_router.clone(), _fwd_tx);

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
            audit.log("exec", Some(username), None, Some(&command), true).await;

            // Spawn exec in background so the main message loop keeps running
            // (allows concurrent channel handling, e.g. -L DirectTcpip opens)
            let transport_exec = transport.clone();
            let username_exec = username.to_string();
            let audit_exec = audit.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_exec_request(channel_id, command, &transport_exec, &username_exec, &audit_exec).await {
                    log::error!("Exec error for {}: {}", username_exec, e);
                }
            });
        }
        ChannelMessage::SubsystemRequest { channel_id, subsystem } => {
            log::info!("User {} requesting subsystem '{}' on channel {}", username, subsystem, channel_id);

            // Handle subsystem request
            handle_subsystem_request(channel_id, subsystem, transport, username).await?;
        }
        ChannelMessage::X11Request { channel_id, single_connection, auth_protocol, auth_cookie, screen_number } => {
            log::info!("User {} requesting X11 forwarding on channel {} (screen {})",
                username, channel_id, screen_number);

            // Find an available display number (10..100)
            let mut display_number = 10u32;
            for dn in 10u32..100 {
                let port = 6000 + dn as u16;
                if TcpListener::bind(format!("127.0.0.1:{}", port)).await.is_ok() {
                    display_number = dn;
                    break;
                }
            }

            // Store X11 state globally and on the channel
            {
                let mut state = x11_state.lock().await;
                *state = Some(X11ForwardState {
                    display_number,
                    auth_protocol: auth_protocol.clone(),
                    auth_cookie: auth_cookie.clone(),
                    single_connection,
                });
            }
            {
                let mut conns = connections.lock().await;
                if let Some(conn) = conns.get_mut(username) {
                    if let Some(ch) = conn.channels.get_mut(&channel_id) {
                        ch.x11_display = Some(X11Display {
                            display: format!("localhost:{}.0", display_number),
                        });
                    }
                }
            }

            // Start X11 listener on localhost:6000+display_number
            let x11_port = 6000 + display_number as u16;
            match TcpListener::bind(format!("127.0.0.1:{}", x11_port)).await {
                Ok(listener) => {
                    log::info!("X11 forwarding: listening on 127.0.0.1:{} (DISPLAY=:{}.{})",
                        x11_port, display_number, screen_number);

                    // Spawn X11 accept loop
                    let transport_x11 = transport.clone();
                    let single = single_connection;
                    tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((stream, peer)) => {
                                    log::debug!("X11 connection from {} on display :{}", peer, display_number);

                                    let transport_conn = transport_x11.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_x11_server_connection(
                                            stream, transport_conn,
                                        ).await {
                                            log::debug!("X11 connection ended: {}", e);
                                        }
                                    });

                                    if single {
                                        log::info!("X11 single-connection mode — stopping listener");
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

                    // Acknowledge X11 request
                    let ack = Message::Channel(ChannelMessage::Data {
                        channel_id,
                        data: vec![0], // success
                    });
                    transport.send_message(&ack).await?;
                }
                Err(e) => {
                    log::error!("Failed to bind X11 listener on port {}: {}", x11_port, e);
                }
            }
        }
        ChannelMessage::ForwardRequest { channel_id, remote_host, remote_port } => {
            // Handle ForwardRequest for DirectTcpIp channels (sent after Channel::Open with DirectTcpIp variant)
            let target_addr = format!("{}:{}", remote_host, remote_port);
            log::info!("User {} ForwardRequest on channel {}: {}", username, channel_id, target_addr);

            match TcpStream::connect(&target_addr).await {
                Ok(tcp_stream) => {
                    // Register channel with router for data dispatch
                    let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(256);
                    channel_router.register(channel_id, data_tx).await;

                    // Bridge TCP stream <-> channel data
                    let transport_bridge = transport.clone();
                    let channel_router_bridge = channel_router.clone();
                    tokio::spawn(async move {
                        let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

                        let transport_out = transport_bridge.clone();
                        let tcp_to_channel = tokio::spawn(async move {
                            let mut buf = vec![0u8; 8192];
                            loop {
                                match tcp_read.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        let msg = Message::Channel(ChannelMessage::Data {
                                            channel_id,
                                            data: buf[..n].to_vec(),
                                        });
                                        if transport_out.send_message(&msg).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });

                        let channel_to_tcp = tokio::spawn(async move {
                            while let Some(data) = data_rx.recv().await {
                                if data.is_empty() { continue; }
                                if tcp_write.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                        });

                        tokio::select! {
                            _ = tcp_to_channel => {}
                            _ = channel_to_tcp => {}
                        }

                        channel_router_bridge.remove(channel_id).await;
                        let eof = Message::Channel(ChannelMessage::Eof { channel_id });
                        let _ = transport_bridge.send_message(&eof).await;
                        log::debug!("ForwardRequest bridge ended for channel {}", channel_id);
                    });
                }
                Err(e) => {
                    log::error!("ForwardRequest: failed to connect to {}: {}", target_addr, e);
                    let close = Message::Channel(ChannelMessage::Close { channel_id });
                    transport.send_message(&close).await?;
                }
            }
        }
        _ => {
            log::debug!("Unhandled channel message from {}", username);
        }
    }
    Ok(())
}

/// Handle an X11 connection on the server side.
/// Opens an X11 channel back to the client and bridges TCP <-> channel data.
async fn handle_x11_server_connection(
    stream: TcpStream,
    transport: Transport,
) -> Result<()> {
    let channel_id = rand::random::<u32>() % 65536;

    // Open X11 channel back to the client
    let open_msg = Message::Channel(ChannelMessage::Open {
        channel_id,
        channel_type: ChannelType::X11,
        window_size: 1024 * 1024,
        max_packet_size: 32768,
    });
    transport.send_message(&open_msg).await?;

    // Bridge TCP <-> channel
    let (mut tcp_read, mut tcp_write) = stream.into_split();

    let transport_send = transport.clone();
    let tcp_to_channel = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
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

    let channel_to_tcp = tokio::spawn(async move {
        loop {
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data }))
                    if ch_id == channel_id =>
                {
                    if tcp_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id }))
                | Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id }))
                    if ch_id == channel_id =>
                {
                    break;
                }
                Ok(Message::Disconnect(_)) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    });

    tokio::select! {
        _ = tcp_to_channel => {}
        _ = channel_to_tcp => {}
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
    audit: &AuditLogger,
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

            // Send exit status
            let exit_code = output.status.code().unwrap_or(255) as u32;
            audit.log("exec_exit", Some(username), None,
                Some(&format!("exit_code={}", exit_code)), exit_code == 0).await;
            let exit_msg = Message::Channel(ChannelMessage::ExitStatus {
                channel_id,
                exit_code,
            });
            transport.send_message(&exit_msg).await?;
        }
        Err(e) => {
            let error_msg = format!("Command failed: {}\n", e).into_bytes();
            let response = Message::Channel(ChannelMessage::Data {
                channel_id,
                data: error_msg,
            });
            transport.send_message(&response).await?;

            // Send exit status 255 for spawn failure
            let exit_msg = Message::Channel(ChannelMessage::ExitStatus {
                channel_id,
                exit_code: 255,
            });
            transport.send_message(&exit_msg).await?;
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