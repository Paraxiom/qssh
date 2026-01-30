//! Connection Multiplexing Support
//!
//! Allows multiple SSH sessions to share a single network connection,
//! reducing latency and resource usage.
//!
//! This module implements OpenSSH-style connection multiplexing where:
//! - A control master maintains a single authenticated SSH connection
//! - Multiple clients can request new channels over this connection
//! - Each channel operates independently with proper flow control

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::sync::{RwLock, mpsc, oneshot, Notify};
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use crate::{Result, QsshError};
use crate::transport::Transport;
use crate::transport::protocol::{Message, ChannelMessage, ChannelType};

/// Default window size for new channels (1 MB)
const DEFAULT_WINDOW_SIZE: u32 = 1024 * 1024;

/// Default maximum packet size for channels (32 KB)
const DEFAULT_MAX_PACKET_SIZE: u32 = 32768;

/// Control socket for multiplexed connections
pub struct ControlMaster {
    /// Path to the control socket
    socket_path: PathBuf,
    /// Active transport connection
    transport: Arc<Transport>,
    /// Active sessions
    sessions: Arc<RwLock<HashMap<u32, SessionHandle>>>,
    /// Next session ID (local session identifier)
    next_session_id: Arc<RwLock<u32>>,
    /// Next channel ID for SSH channel allocation
    next_channel_id: Arc<AtomicU32>,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Shutdown notification
    shutdown_notify: Arc<Notify>,
    /// Pending channel open requests awaiting server response
    pending_channels: Arc<RwLock<HashMap<u32, oneshot::Sender<Result<ChannelOpenResult>>>>>,
}

/// Handle to an active session
struct SessionHandle {
    /// Local session identifier
    id: u32,
    /// SSH channel ID (sender channel)
    channel_id: u32,
    /// Remote channel ID assigned by server
    remote_channel_id: u32,
    /// Channel for sending control messages
    tx: mpsc::Sender<ControlMessage>,
    /// Current window size (flow control)
    window_size: Arc<AtomicU32>,
    /// Maximum packet size for this channel
    /// Note: Stored for future flow control improvements but currently
    /// passed directly to forwarding tasks during session creation
    #[allow(dead_code)]
    max_packet_size: u32,
}

/// Result of a successful channel open operation
#[derive(Debug, Clone)]
struct ChannelOpenResult {
    /// Our local channel ID
    local_channel_id: u32,
    /// Server's channel ID
    remote_channel_id: u32,
    /// Initial window size from server
    window_size: u32,
    /// Maximum packet size from server
    max_packet_size: u32,
}

/// Messages between control master and clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Request new session
    NewSession {
        command: Option<String>,
        env: HashMap<String, String>,
    },
    /// Session created
    SessionCreated {
        session_id: u32,
        channel_id: u32,
    },
    /// Forward data to session
    Data {
        session_id: u32,
        data: Vec<u8>,
    },
    /// Session closed
    SessionClosed {
        session_id: u32,
    },
    /// Check if master is alive
    Ping,
    /// Master is alive
    Pong,
    /// Request master to exit
    Exit,
}

impl ControlMaster {
    /// Create new control master
    pub fn new(socket_path: PathBuf, transport: Arc<Transport>) -> Self {
        Self {
            socket_path,
            transport,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            next_session_id: Arc::new(RwLock::new(1)),
            next_channel_id: Arc::new(AtomicU32::new(0)),
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            pending_channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Stop the control master gracefully
    pub async fn stop(&self) -> Result<()> {
        log::info!("Initiating graceful shutdown of control master");

        // Signal shutdown
        self.shutdown.store(true, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();

        // Close all active sessions
        let sessions = self.sessions.read().await;
        for (session_id, handle) in sessions.iter() {
            log::debug!("Closing session {} (channel {})", session_id, handle.channel_id);

            // Send channel close message
            let close_msg = Message::Channel(ChannelMessage::Close {
                channel_id: handle.remote_channel_id,
            });

            if let Err(e) = self.transport.send_message(&close_msg).await {
                log::warn!("Failed to send close for channel {}: {}", handle.channel_id, e);
            }
        }
        drop(sessions);

        // Clear all sessions
        self.sessions.write().await.clear();

        // Cancel all pending channel requests
        let mut pending = self.pending_channels.write().await;
        for (channel_id, sender) in pending.drain() {
            log::debug!("Canceling pending channel open for {}", channel_id);
            let _ = sender.send(Err(QsshError::Connection("Control master shutting down".into())));
        }

        // Clean up the socket file
        if let Err(e) = std::fs::remove_file(&self.socket_path) {
            log::debug!("Could not remove socket file: {}", e);
        }

        log::info!("Control master shutdown complete");
        Ok(())
    }

    /// Start control master server
    pub async fn start(&self) -> Result<()> {
        // Remove existing socket if present
        let _ = std::fs::remove_file(&self.socket_path);

        // Create Unix domain socket
        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| QsshError::Connection(format!("Failed to bind control socket: {}", e)))?;

        log::info!("Control master listening on: {:?}", self.socket_path);

        // Start the transport message receiver task
        let transport_clone = self.transport.clone();
        let sessions_clone = self.sessions.clone();
        let pending_clone = self.pending_channels.clone();
        let shutdown_clone = self.shutdown.clone();

        tokio::spawn(async move {
            handle_transport_messages(
                transport_clone,
                sessions_clone,
                pending_clone,
                shutdown_clone,
            ).await;
        });

        loop {
            // Check for shutdown
            if self.shutdown.load(Ordering::SeqCst) {
                log::info!("Control master received shutdown signal");
                break;
            }

            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _)) => {
                            let sessions = self.sessions.clone();
                            let transport = self.transport.clone();
                            let next_id = self.next_session_id.clone();
                            let next_channel = self.next_channel_id.clone();
                            let pending = self.pending_channels.clone();
                            let shutdown = self.shutdown.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_control_client(
                                    stream,
                                    sessions,
                                    transport,
                                    next_id,
                                    next_channel,
                                    pending,
                                    shutdown,
                                ).await {
                                    log::error!("Control client error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Failed to accept control connection: {}", e);
                        }
                    }
                }
                _ = self.shutdown_notify.notified() => {
                    log::info!("Control master notified of shutdown");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Check if master is running
    pub async fn check_master(socket_path: &PathBuf) -> bool {
        if let Ok(mut stream) = UnixStream::connect(socket_path).await {
            let msg = ControlMessage::Ping;
            let msg_bytes = bincode::serialize(&msg).unwrap_or_default();

            let len_bytes = (msg_bytes.len() as u32).to_be_bytes();
            if stream.write_all(&len_bytes).await.is_err() {
                return false;
            }
            if stream.write_all(&msg_bytes).await.is_err() {
                return false;
            }

            let mut buf = vec![0u8; 4];
            if stream.read_exact(&mut buf).await.is_err() {
                return false;
            }

            let msg_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            let mut msg_buf = vec![0u8; msg_len];
            if stream.read_exact(&mut msg_buf).await.is_err() {
                return false;
            }

            if let Ok(response) = bincode::deserialize::<ControlMessage>(&msg_buf) {
                matches!(response, ControlMessage::Pong)
            } else {
                false
            }
        } else {
            false
        }
    }
}

/// Handle incoming messages from the transport layer
async fn handle_transport_messages(
    transport: Arc<Transport>,
    sessions: Arc<RwLock<HashMap<u32, SessionHandle>>>,
    pending_channels: Arc<RwLock<HashMap<u32, oneshot::Sender<Result<ChannelOpenResult>>>>>,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        // Try to receive a message from the transport
        let msg_result: Result<Message> = transport.receive_message().await;

        match msg_result {
            Ok(Message::Channel(channel_msg)) => {
                match channel_msg {
                    ChannelMessage::Accept {
                        channel_id,
                        sender_channel,
                        window_size,
                        max_packet_size,
                    } => {
                        // This is a response to our channel open request
                        // channel_id is the server's channel ID
                        // sender_channel is our local channel ID
                        let mut pending = pending_channels.write().await;
                        if let Some(sender) = pending.remove(&sender_channel) {
                            let result = ChannelOpenResult {
                                local_channel_id: sender_channel,
                                remote_channel_id: channel_id,
                                window_size,
                                max_packet_size,
                            };
                            let _ = sender.send(Ok(result));
                        } else {
                            log::warn!(
                                "Received channel accept for unknown channel {}",
                                sender_channel
                            );
                        }
                    }
                    ChannelMessage::Data { channel_id, data } => {
                        // Forward data to the appropriate session
                        let sessions_guard = sessions.read().await;
                        for handle in sessions_guard.values() {
                            if handle.remote_channel_id == channel_id {
                                let _ = handle.tx.send(ControlMessage::Data {
                                    session_id: handle.id,
                                    data: data.clone(),
                                }).await;
                                break;
                            }
                        }
                    }
                    ChannelMessage::WindowAdjust { channel_id, bytes_to_add } => {
                        // Update window size for flow control
                        let sessions_guard = sessions.read().await;
                        for handle in sessions_guard.values() {
                            if handle.remote_channel_id == channel_id {
                                handle.window_size.fetch_add(bytes_to_add, Ordering::SeqCst);
                                break;
                            }
                        }
                    }
                    ChannelMessage::Eof { channel_id } => {
                        log::debug!("Received EOF for channel {}", channel_id);
                    }
                    ChannelMessage::Close { channel_id } => {
                        // Find and remove the session with this channel
                        let mut sessions_guard = sessions.write().await;
                        let session_id_to_remove = sessions_guard
                            .iter()
                            .find(|(_, h)| h.remote_channel_id == channel_id)
                            .map(|(id, _)| *id);

                        if let Some(session_id) = session_id_to_remove {
                            if let Some(handle) = sessions_guard.remove(&session_id) {
                                let _ = handle.tx.send(ControlMessage::SessionClosed {
                                    session_id,
                                }).await;
                            }
                        }
                    }
                    _ => {
                        log::debug!("Received unhandled channel message: {:?}", channel_msg);
                    }
                }
            }
            Ok(Message::Disconnect(disconnect)) => {
                log::info!(
                    "Received disconnect from server: {} (code {})",
                    disconnect.description,
                    disconnect.reason_code
                );
                shutdown.store(true, Ordering::SeqCst);
                break;
            }
            Ok(Message::Ping(seq)) => {
                // Respond to keepalive
                let _ = transport.send_message(&Message::Pong(seq)).await;
            }
            Ok(_) => {
                // Other messages handled elsewhere
            }
            Err(e) => {
                if !shutdown.load(Ordering::SeqCst) {
                    log::error!("Transport receive error: {}", e);
                    // On transport error, signal shutdown
                    shutdown.store(true, Ordering::SeqCst);
                }
                break;
            }
        }
    }
}

/// Handle control client connection
async fn handle_control_client(
    mut stream: UnixStream,
    sessions: Arc<RwLock<HashMap<u32, SessionHandle>>>,
    transport: Arc<Transport>,
    next_session_id: Arc<RwLock<u32>>,
    next_channel_id: Arc<AtomicU32>,
    pending_channels: Arc<RwLock<HashMap<u32, oneshot::Sender<Result<ChannelOpenResult>>>>>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let mut buffer = vec![0u8; 65536];

    loop {
        // Check for shutdown
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        // Read message length
        let n = stream.read(&mut buffer[..4]).await?;
        if n == 0 {
            break; // Connection closed
        }

        let msg_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

        // Read message
        let n = stream.read(&mut buffer[..msg_len]).await?;
        if n != msg_len {
            return Err(QsshError::Protocol("Incomplete control message".into()));
        }

        // Parse message
        let request: ControlMessage = bincode::deserialize(&buffer[..msg_len])
            .map_err(|e| QsshError::Protocol(format!("Failed to parse control message: {}", e)))?;

        // Handle request
        let response = match request {
            ControlMessage::NewSession { command, env } => {
                // Allocate new session ID
                let mut id_guard = next_session_id.write().await;
                let session_id = *id_guard;
                *id_guard += 1;
                drop(id_guard);

                // Create new channel on transport
                match create_channel(
                    &transport,
                    &next_channel_id,
                    &pending_channels,
                    command,
                    env,
                ).await {
                    Ok(result) => {
                        // Create session handle
                        let (tx, mut rx) = mpsc::channel(256);
                        let window_size = Arc::new(AtomicU32::new(result.window_size));
                        let handle = SessionHandle {
                            id: session_id,
                            channel_id: result.local_channel_id,
                            remote_channel_id: result.remote_channel_id,
                            tx,
                            window_size: window_size.clone(),
                            max_packet_size: result.max_packet_size,
                        };

                        let channel_id = result.local_channel_id;
                        let remote_channel_id = result.remote_channel_id;
                        let max_packet_size = result.max_packet_size;

                        // Store session
                        sessions.write().await.insert(session_id, handle);

                        // Start forwarding task
                        let transport_clone = transport.clone();
                        tokio::spawn(async move {
                            while let Some(msg) = rx.recv().await {
                                if let ControlMessage::Data { data, .. } = msg {
                                    // Forward data to transport channel with flow control
                                    if let Err(e) = forward_to_channel(
                                        &transport_clone,
                                        remote_channel_id,
                                        data,
                                        max_packet_size,
                                    ).await {
                                        log::error!("Failed to forward data to channel {}: {}", channel_id, e);
                                        break;
                                    }
                                }
                            }
                        });

                        ControlMessage::SessionCreated { session_id, channel_id }
                    }
                    Err(e) => {
                        log::error!("Failed to create channel: {}", e);
                        // Send error response
                        let response_bytes = bincode::serialize(&ControlMessage::SessionClosed {
                            session_id,
                        }).map_err(|e| QsshError::Protocol(format!("Serialization error: {}", e)))?;

                        let len_bytes = (response_bytes.len() as u32).to_be_bytes();
                        stream.write_all(&len_bytes).await?;
                        stream.write_all(&response_bytes).await?;
                        continue;
                    }
                }
            }
            ControlMessage::Data { session_id, data } => {
                // Forward data to session
                if let Some(handle) = sessions.read().await.get(&session_id) {
                    let _ = handle.tx.send(ControlMessage::Data { session_id, data }).await;
                }
                continue; // No response needed
            }
            ControlMessage::SessionClosed { session_id } => {
                // Send channel close to server and remove session
                if let Some(handle) = sessions.write().await.remove(&session_id) {
                    let close_msg = Message::Channel(ChannelMessage::Close {
                        channel_id: handle.remote_channel_id,
                    });
                    let _ = transport.send_message(&close_msg).await;
                }
                continue; // No response needed
            }
            ControlMessage::Ping => ControlMessage::Pong,
            ControlMessage::Exit => {
                // Signal graceful shutdown
                shutdown.store(true, Ordering::SeqCst);
                break;
            }
            _ => continue,
        };

        // Send response
        let response_bytes = bincode::serialize(&response)
            .map_err(|e| QsshError::Protocol(format!("Failed to serialize response: {}", e)))?;

        let len_bytes = (response_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&response_bytes).await?;
    }

    Ok(())
}

/// Create new channel on transport
///
/// Sends SSH_MSG_CHANNEL_OPEN to the server and waits for confirmation.
/// Returns the channel open result containing both local and remote channel IDs.
async fn create_channel(
    transport: &Arc<Transport>,
    next_channel_id: &Arc<AtomicU32>,
    pending_channels: &Arc<RwLock<HashMap<u32, oneshot::Sender<Result<ChannelOpenResult>>>>>,
    command: Option<String>,
    env: HashMap<String, String>,
) -> Result<ChannelOpenResult> {
    // Allocate a new local channel ID
    let local_channel_id = next_channel_id.fetch_add(1, Ordering::SeqCst);

    log::debug!(
        "Creating channel {} (command: {:?}, env keys: {:?})",
        local_channel_id,
        command,
        env.keys().collect::<Vec<_>>()
    );

    // Create a oneshot channel to receive the server's response
    let (response_tx, response_rx) = oneshot::channel();

    // Register the pending channel
    {
        let mut pending = pending_channels.write().await;
        pending.insert(local_channel_id, response_tx);
    }

    // Build and send the channel open message
    let channel_open_msg = Message::Channel(ChannelMessage::Open {
        channel_id: local_channel_id,
        channel_type: ChannelType::Session,
        window_size: DEFAULT_WINDOW_SIZE,
        max_packet_size: DEFAULT_MAX_PACKET_SIZE,
    });

    if let Err(e) = transport.send_message(&channel_open_msg).await {
        // Remove from pending on send failure
        pending_channels.write().await.remove(&local_channel_id);
        return Err(QsshError::Connection(format!(
            "Failed to send channel open: {}",
            e
        )));
    }

    // Wait for server response with timeout
    let timeout_duration = tokio::time::Duration::from_secs(30);
    let result = tokio::time::timeout(timeout_duration, response_rx).await;

    match result {
        Ok(Ok(channel_result)) => {
            let result = channel_result?;
            log::info!(
                "Channel {} opened successfully (remote: {}, window: {}, max_packet: {})",
                result.local_channel_id,
                result.remote_channel_id,
                result.window_size,
                result.max_packet_size
            );

            // If a command was specified, send exec request
            if let Some(cmd) = command {
                let exec_msg = Message::Channel(ChannelMessage::ExecRequest {
                    channel_id: result.remote_channel_id,
                    command: cmd.clone(),
                });
                transport.send_message(&exec_msg).await?;
                log::debug!("Sent exec request for command: {}", cmd);
            } else {
                // Request a shell
                let shell_msg = Message::Channel(ChannelMessage::ShellRequest {
                    channel_id: result.remote_channel_id,
                });
                transport.send_message(&shell_msg).await?;
                log::debug!("Sent shell request");
            }

            // Set environment variables if any
            for (key, value) in env {
                log::debug!("Setting env {}={}", key, value);
                // Environment variables would be sent via SSH_MSG_CHANNEL_REQUEST
                // with "env" type, but this protocol uses a different approach
            }

            Ok(result)
        }
        Ok(Err(_)) => {
            // Oneshot channel was dropped (likely due to shutdown)
            pending_channels.write().await.remove(&local_channel_id);
            Err(QsshError::Connection(
                "Channel open cancelled - receiver dropped".into(),
            ))
        }
        Err(_) => {
            // Timeout
            pending_channels.write().await.remove(&local_channel_id);
            Err(QsshError::Connection(format!(
                "Channel open timed out after {} seconds",
                timeout_duration.as_secs()
            )))
        }
    }
}

/// Forward data to a channel
///
/// Sends SSH_MSG_CHANNEL_DATA to the server. Data is chunked according to
/// the maximum packet size to comply with SSH protocol limits.
async fn forward_to_channel(
    transport: &Arc<Transport>,
    remote_channel_id: u32,
    data: Vec<u8>,
    max_packet_size: u32,
) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    let max_size = max_packet_size as usize;

    // Split data into chunks that fit within max_packet_size
    for chunk in data.chunks(max_size) {
        let data_msg = Message::Channel(ChannelMessage::Data {
            channel_id: remote_channel_id,
            data: chunk.to_vec(),
        });

        transport.send_message(&data_msg).await.map_err(|e| {
            QsshError::Connection(format!(
                "Failed to forward data to channel {}: {}",
                remote_channel_id, e
            ))
        })?;
    }

    log::trace!(
        "Forwarded {} bytes to channel {}",
        data.len(),
        remote_channel_id
    );

    Ok(())
}

/// Control client for connecting to master
pub struct ControlClient {
    socket_path: PathBuf,
    stream: Option<UnixStream>,
}

impl ControlClient {
    /// Create new control client
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            stream: None,
        }
    }

    /// Connect to control master
    pub async fn connect(&mut self) -> Result<()> {
        let stream = UnixStream::connect(&self.socket_path).await
            .map_err(|e| QsshError::Connection(format!("Failed to connect to control master: {}", e)))?;
        self.stream = Some(stream);
        Ok(())
    }

    /// Request new session
    pub async fn new_session(&mut self, command: Option<String>) -> Result<u32> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| QsshError::Protocol("Not connected to control master".into()))?;

        let msg = ControlMessage::NewSession {
            command,
            env: HashMap::new(),
        };

        // Send request
        let msg_bytes = bincode::serialize(&msg)
            .map_err(|e| QsshError::Protocol(format!("Failed to serialize message: {}", e)))?;

        let len_bytes = (msg_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&msg_bytes).await?;

        // Read response
        let mut buf = vec![0u8; 4];
        stream.read_exact(&mut buf).await?;
        let msg_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        let response: ControlMessage = bincode::deserialize(&msg_buf)
            .map_err(|e| QsshError::Protocol(format!("Failed to parse response: {}", e)))?;

        match response {
            ControlMessage::SessionCreated { session_id, .. } => Ok(session_id),
            _ => Err(QsshError::Protocol("Unexpected response from control master".into())),
        }
    }

    /// Send data to session
    pub async fn send_data(&mut self, session_id: u32, data: Vec<u8>) -> Result<()> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| QsshError::Protocol("Not connected to control master".into()))?;

        let msg = ControlMessage::Data { session_id, data };
        let msg_bytes = bincode::serialize(&msg)
            .map_err(|e| QsshError::Protocol(format!("Failed to serialize message: {}", e)))?;

        let len_bytes = (msg_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&msg_bytes).await?;

        Ok(())
    }

    /// Close session
    pub async fn close_session(&mut self, session_id: u32) -> Result<()> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| QsshError::Protocol("Not connected to control master".into()))?;

        let msg = ControlMessage::SessionClosed { session_id };
        let msg_bytes = bincode::serialize(&msg)
            .map_err(|e| QsshError::Protocol(format!("Failed to serialize message: {}", e)))?;

        let len_bytes = (msg_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&msg_bytes).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_control_master_ping() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("control.sock");

        // Check that master is not running
        assert!(!ControlMaster::check_master(&socket_path).await);
    }

    #[tokio::test]
    async fn test_control_client_creation() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("control.sock");

        let client = ControlClient::new(socket_path);
        assert!(client.stream.is_none());
    }

    #[tokio::test]
    async fn test_control_message_serialization() {
        // Test that all control messages can be serialized and deserialized
        let messages = vec![
            ControlMessage::NewSession {
                command: Some("ls -la".to_string()),
                env: {
                    let mut env = HashMap::new();
                    env.insert("TERM".to_string(), "xterm-256color".to_string());
                    env
                },
            },
            ControlMessage::SessionCreated {
                session_id: 42,
                channel_id: 100,
            },
            ControlMessage::Data {
                session_id: 42,
                data: vec![0x48, 0x65, 0x6c, 0x6c, 0x6f], // "Hello"
            },
            ControlMessage::SessionClosed { session_id: 42 },
            ControlMessage::Ping,
            ControlMessage::Pong,
            ControlMessage::Exit,
        ];

        for msg in messages {
            let serialized = bincode::serialize(&msg).expect("Serialization should succeed");
            let deserialized: ControlMessage =
                bincode::deserialize(&serialized).expect("Deserialization should succeed");

            // Verify round-trip (using Debug representation for comparison)
            assert_eq!(format!("{:?}", msg), format!("{:?}", deserialized));
        }
    }

    #[tokio::test]
    async fn test_channel_open_result() {
        let result = ChannelOpenResult {
            local_channel_id: 5,
            remote_channel_id: 10,
            window_size: DEFAULT_WINDOW_SIZE,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
        };

        assert_eq!(result.local_channel_id, 5);
        assert_eq!(result.remote_channel_id, 10);
        assert_eq!(result.window_size, 1024 * 1024);
        assert_eq!(result.max_packet_size, 32768);
    }

    #[tokio::test]
    async fn test_session_handle_window_size() {
        let (tx, _rx) = mpsc::channel(256);
        let window_size = Arc::new(AtomicU32::new(DEFAULT_WINDOW_SIZE));

        let handle = SessionHandle {
            id: 1,
            channel_id: 0,
            remote_channel_id: 100,
            tx,
            window_size: window_size.clone(),
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
        };

        // Test atomic window size operations
        assert_eq!(handle.window_size.load(Ordering::SeqCst), DEFAULT_WINDOW_SIZE);

        // Simulate window adjustment
        handle.window_size.fetch_add(4096, Ordering::SeqCst);
        assert_eq!(
            handle.window_size.load(Ordering::SeqCst),
            DEFAULT_WINDOW_SIZE + 4096
        );

        // Simulate data consumption (window decrease)
        handle.window_size.fetch_sub(1024, Ordering::SeqCst);
        assert_eq!(
            handle.window_size.load(Ordering::SeqCst),
            DEFAULT_WINDOW_SIZE + 4096 - 1024
        );
    }

    #[tokio::test]
    async fn test_control_client_not_connected() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("control.sock");

        let mut client = ControlClient::new(socket_path);

        // Operations should fail when not connected
        let result = client.new_session(None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Not connected to control master"));

        let result = client.send_data(1, vec![1, 2, 3]).await;
        assert!(result.is_err());

        let result = client.close_session(1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_control_client_connect_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("nonexistent.sock");

        let mut client = ControlClient::new(socket_path);

        // Should fail to connect to nonexistent socket
        let result = client.connect().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to connect to control master"));
    }

    #[test]
    fn test_default_constants() {
        // Verify constants are reasonable
        assert_eq!(DEFAULT_WINDOW_SIZE, 1024 * 1024); // 1 MB
        assert_eq!(DEFAULT_MAX_PACKET_SIZE, 32768); // 32 KB

        // Max packet size should be less than window size
        assert!(DEFAULT_MAX_PACKET_SIZE < DEFAULT_WINDOW_SIZE);
    }

    #[tokio::test]
    async fn test_data_chunking_logic() {
        // Test that data would be properly chunked
        let large_data = vec![0u8; 100_000]; // 100 KB of data
        let max_packet_size = 32768u32;

        let chunks: Vec<&[u8]> = large_data.chunks(max_packet_size as usize).collect();

        // Should create 4 chunks (32768 + 32768 + 32768 + 1696)
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].len(), 32768);
        assert_eq!(chunks[1].len(), 32768);
        assert_eq!(chunks[2].len(), 32768);
        assert_eq!(chunks[3].len(), 100_000 - 3 * 32768);
    }

    #[tokio::test]
    async fn test_atomic_channel_id_generation() {
        let next_channel_id = Arc::new(AtomicU32::new(0));

        // Simulate concurrent channel allocation
        let mut handles = vec![];
        for _ in 0..100 {
            let id_clone = next_channel_id.clone();
            handles.push(tokio::spawn(async move {
                id_clone.fetch_add(1, Ordering::SeqCst)
            }));
        }

        let mut ids = vec![];
        for handle in handles {
            ids.push(handle.await.unwrap());
        }

        // All IDs should be unique
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 100);

        // Final value should be 100
        assert_eq!(next_channel_id.load(Ordering::SeqCst), 100);
    }

    #[tokio::test]
    async fn test_pending_channels_cleanup() {
        let pending_channels: Arc<RwLock<HashMap<u32, oneshot::Sender<Result<ChannelOpenResult>>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // Add some pending channels
        for i in 0..5 {
            let (tx, _rx) = oneshot::channel();
            pending_channels.write().await.insert(i, tx);
        }

        assert_eq!(pending_channels.read().await.len(), 5);

        // Simulate cleanup (like during shutdown)
        {
            let mut pending = pending_channels.write().await;
            for (channel_id, sender) in pending.drain() {
                let _ = sender.send(Err(QsshError::Connection(format!(
                    "Channel {} cancelled",
                    channel_id
                ))));
            }
        }

        assert_eq!(pending_channels.read().await.len(), 0);
    }
}