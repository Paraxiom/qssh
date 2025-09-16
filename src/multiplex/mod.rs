//! Connection Multiplexing Support
//!
//! Allows multiple SSH sessions to share a single network connection,
//! reducing latency and resource usage.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use crate::{Result, QsshError};
use crate::transport::Transport;

/// Control socket for multiplexed connections
pub struct ControlMaster {
    /// Path to the control socket
    socket_path: PathBuf,
    /// Active transport connection
    transport: Arc<Transport>,
    /// Active sessions
    sessions: Arc<RwLock<HashMap<u32, SessionHandle>>>,
    /// Next session ID
    next_session_id: Arc<RwLock<u32>>,
}

/// Handle to an active session
struct SessionHandle {
    id: u32,
    channel_id: u32,
    tx: mpsc::Sender<ControlMessage>,
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
        }
    }

    /// Start control master server
    pub async fn start(&self) -> Result<()> {
        // Remove existing socket if present
        let _ = std::fs::remove_file(&self.socket_path);

        // Create Unix domain socket
        let listener = UnixListener::bind(&self.socket_path)
            .map_err(|e| QsshError::Connection(format!("Failed to bind control socket: {}", e)))?;

        println!("Control master listening on: {:?}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let sessions = self.sessions.clone();
                    let transport = self.transport.clone();
                    let next_id = self.next_session_id.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_control_client(stream, sessions, transport, next_id).await {
                            eprintln!("Control client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept control connection: {}", e);
                }
            }
        }
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

/// Handle control client connection
async fn handle_control_client(
    mut stream: UnixStream,
    sessions: Arc<RwLock<HashMap<u32, SessionHandle>>>,
    transport: Arc<Transport>,
    next_session_id: Arc<RwLock<u32>>,
) -> Result<()> {
    let mut buffer = vec![0u8; 65536];

    loop {
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

                // Create new channel on transport
                let channel_id = create_channel(&transport, command, env).await?;

                // Create session handle
                let (tx, mut rx) = mpsc::channel(256);
                let handle = SessionHandle {
                    id: session_id,
                    channel_id,
                    tx,
                };

                // Store session
                sessions.write().await.insert(session_id, handle);

                // Start forwarding task
                let transport_clone = transport.clone();
                tokio::spawn(async move {
                    while let Some(msg) = rx.recv().await {
                        if let ControlMessage::Data { data, .. } = msg {
                            // Forward data to transport channel
                            let _ = forward_to_channel(&transport_clone, channel_id, data).await;
                        }
                    }
                });

                ControlMessage::SessionCreated { session_id, channel_id }
            }
            ControlMessage::Data { session_id, data } => {
                // Forward data to session
                if let Some(handle) = sessions.read().await.get(&session_id) {
                    let _ = handle.tx.send(ControlMessage::Data { session_id, data }).await;
                }
                continue; // No response needed
            }
            ControlMessage::SessionClosed { session_id } => {
                // Remove session
                sessions.write().await.remove(&session_id);
                continue; // No response needed
            }
            ControlMessage::Ping => ControlMessage::Pong,
            ControlMessage::Exit => {
                // TODO: Graceful shutdown
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
async fn create_channel(
    transport: &Arc<Transport>,
    command: Option<String>,
    _env: HashMap<String, String>,
) -> Result<u32> {
    // TODO: Implement actual channel creation on transport
    // This would send SSH_MSG_CHANNEL_OPEN to the server

    // For now, return a dummy channel ID
    static mut NEXT_CHANNEL: u32 = 1;
    unsafe {
        let channel_id = NEXT_CHANNEL;
        NEXT_CHANNEL += 1;
        Ok(channel_id)
    }
}

/// Forward data to a channel
async fn forward_to_channel(
    _transport: &Arc<Transport>,
    _channel_id: u32,
    _data: Vec<u8>,
) -> Result<()> {
    // TODO: Implement actual data forwarding
    // This would send SSH_MSG_CHANNEL_DATA to the server
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
}