// SFTP Subsystem Implementation
// Implements SSH File Transfer Protocol version 3

pub mod protocol;
pub mod handler;
pub mod session;

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::Subsystem;

use protocol::*;
use handler::FileHandle;
use session::SftpSession;

/// SFTP Subsystem
pub struct SftpSubsystem {
    sftp_session: SftpSession,
    root_dir: PathBuf,
    handles: HashMap<String, FileHandle>,
    next_handle_id: u32,
}

impl SftpSubsystem {
    pub fn new() -> Self {
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

        SftpSubsystem {
            sftp_session: SftpSession::new(),
            root_dir: PathBuf::from(home_dir),
            handles: HashMap::new(),
            next_handle_id: 1,
        }
    }

    pub fn new_for_user(username: String) -> Self {
        // Try to get user's home directory, fallback to /tmp
        let home_dir = format!("/home/{}", username);
        let root_dir = if std::path::Path::new(&home_dir).exists() {
            PathBuf::from(home_dir)
        } else {
            PathBuf::from("/tmp")
        };

        SftpSubsystem {
            sftp_session: SftpSession::for_user(username, root_dir.clone()),
            root_dir,
            handles: HashMap::new(),
            next_handle_id: 1,
        }
    }

    pub fn with_root(root_dir: PathBuf) -> Self {
        SftpSubsystem {
            sftp_session: SftpSession::new(),
            root_dir,
            handles: HashMap::new(),
            next_handle_id: 1,
        }
    }

    fn generate_handle(&mut self) -> String {
        let handle = format!("handle_{}", self.next_handle_id);
        self.next_handle_id += 1;
        handle
    }

    fn resolve_path(&self, path: &str) -> PathBuf {
        if path.starts_with('/') {
            // Absolute path
            self.root_dir.join(&path[1..])
        } else {
            // Relative path
            self.sftp_session.current_dir().join(path)
        }
    }

    async fn handle_init(&mut self, version: u32) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        log::debug!("[SFTP] Client requested version {}", version);

        // We support version 3
        let supported_version = 3;
        let response = SftpMessage::Version {
            version: supported_version,
            extensions: vec![],
        };

        Ok(response.to_bytes()?)
    }

    async fn handle_open(&mut self, msg: OpenMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let path = self.resolve_path(&msg.filename);
        log::debug!("[SFTP] Opening file: {:?} with flags {:?}", path, msg.flags);

        // Create file handle
        let handle = FileHandle::open(path.clone(), msg.flags).await?;
        let handle_id = self.generate_handle();
        self.handles.insert(handle_id.clone(), handle);

        let response = SftpMessage::Handle {
            id: msg.id,
            handle: handle_id,
        };

        Ok(response.to_bytes()?)
    }

    async fn handle_close(&mut self, id: u32, handle: String) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        log::debug!("[SFTP] Closing handle: {}", handle);

        if let Some(mut file_handle) = self.handles.remove(&handle) {
            file_handle.close().await?;

            let response = SftpMessage::Status {
                id,
                code: StatusCode::Ok,
                message: "File closed".to_string(),
                language: "en".to_string(),
            };

            Ok(response.to_bytes()?)
        } else {
            let response = SftpMessage::Status {
                id,
                code: StatusCode::NoSuchFile,
                message: "Invalid handle".to_string(),
                language: "en".to_string(),
            };

            Ok(response.to_bytes()?)
        }
    }

    async fn handle_read(&mut self, msg: ReadMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        log::debug!("[SFTP] Reading {} bytes from handle {} at offset {}",
                 msg.length, msg.handle, msg.offset);

        if let Some(handle) = self.handles.get_mut(&msg.handle) {
            let data = handle.read(msg.offset, msg.length as usize).await?;

            if data.is_empty() {
                // EOF
                let response = SftpMessage::Status {
                    id: msg.id,
                    code: StatusCode::Eof,
                    message: "End of file".to_string(),
                    language: "en".to_string(),
                };
                Ok(response.to_bytes()?)
            } else {
                let response = SftpMessage::Data {
                    id: msg.id,
                    data,
                };
                Ok(response.to_bytes()?)
            }
        } else {
            let response = SftpMessage::Status {
                id: msg.id,
                code: StatusCode::NoSuchFile,
                message: "Invalid handle".to_string(),
                language: "en".to_string(),
            };
            Ok(response.to_bytes()?)
        }
    }

    async fn handle_write(&mut self, msg: WriteMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        log::debug!("[SFTP] Writing {} bytes to handle {} at offset {}",
                 msg.data.len(), msg.handle, msg.offset);

        if let Some(handle) = self.handles.get_mut(&msg.handle) {
            handle.write(msg.offset, &msg.data).await?;

            let response = SftpMessage::Status {
                id: msg.id,
                code: StatusCode::Ok,
                message: "Write successful".to_string(),
                language: "en".to_string(),
            };
            Ok(response.to_bytes()?)
        } else {
            let response = SftpMessage::Status {
                id: msg.id,
                code: StatusCode::NoSuchFile,
                message: "Invalid handle".to_string(),
                language: "en".to_string(),
            };
            Ok(response.to_bytes()?)
        }
    }

    async fn handle_opendir(&mut self, msg: OpenDirMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let path = self.resolve_path(&msg.path);
        log::debug!("[SFTP] Opening directory: {:?}", path);

        // Verify it's a directory
        let metadata = fs::metadata(&path).await?;
        if !metadata.is_dir() {
            let response = SftpMessage::Status {
                id: msg.id,
                code: StatusCode::NoSuchFile,
                message: "Not a directory".to_string(),
                language: "en".to_string(),
            };
            return Ok(response.to_bytes()?);
        }

        // Create directory handle
        let handle = FileHandle::opendir(path).await?;
        let handle_id = self.generate_handle();
        self.handles.insert(handle_id.clone(), handle);

        let response = SftpMessage::Handle {
            id: msg.id,
            handle: handle_id,
        };

        Ok(response.to_bytes()?)
    }

    async fn handle_readdir(&mut self, msg: ReadDirMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        log::debug!("[SFTP] Reading directory from handle: {}", msg.handle);

        if let Some(handle) = self.handles.get_mut(&msg.handle) {
            let entries = handle.readdir().await?;

            if entries.is_empty() {
                // End of directory
                let response = SftpMessage::Status {
                    id: msg.id,
                    code: StatusCode::Eof,
                    message: "End of directory".to_string(),
                    language: "en".to_string(),
                };
                Ok(response.to_bytes()?)
            } else {
                let response = SftpMessage::Name {
                    id: msg.id,
                    files: entries,
                };
                Ok(response.to_bytes()?)
            }
        } else {
            let response = SftpMessage::Status {
                id: msg.id,
                code: StatusCode::NoSuchFile,
                message: "Invalid handle".to_string(),
                language: "en".to_string(),
            };
            Ok(response.to_bytes()?)
        }
    }

    async fn handle_stat(&mut self, msg: StatMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let path = self.resolve_path(&msg.path);
        log::debug!("[SFTP] Stat on path: {:?}", path);

        match fs::metadata(&path).await {
            Ok(metadata) => {
                let attrs = FileAttributes::from_metadata(&metadata);
                let response = SftpMessage::Attrs {
                    id: msg.id,
                    attrs,
                };
                Ok(response.to_bytes()?)
            }
            Err(_) => {
                let response = SftpMessage::Status {
                    id: msg.id,
                    code: StatusCode::NoSuchFile,
                    message: "File not found".to_string(),
                    language: "en".to_string(),
                };
                Ok(response.to_bytes()?)
            }
        }
    }

    async fn handle_realpath(&mut self, msg: RealPathMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let path = self.resolve_path(&msg.path);
        log::debug!("[SFTP] Realpath for: {} -> {:?}", msg.path, path);

        // Get canonical path
        let canonical = match fs::canonicalize(&path).await {
            Ok(p) => p,
            Err(_) => path, // If file doesn't exist, return resolved path
        };

        // Get file info if it exists
        let attrs = match fs::metadata(&canonical).await {
            Ok(metadata) => FileAttributes::from_metadata(&metadata),
            Err(_) => FileAttributes::default(),
        };

        let response = SftpMessage::Name {
            id: msg.id,
            files: vec![FileInfo {
                filename: canonical.to_string_lossy().to_string(),
                longname: format!("{}", canonical.display()),
                attrs,
            }],
        };

        Ok(response.to_bytes()?)
    }

    pub async fn run(&mut self, channel_id: u32, transport: crate::transport::Transport) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::transport::{Message, ChannelMessage};

        log::info!("Starting SFTP subsystem on channel {}", channel_id);

        // Send success response
        let success = Message::Channel(ChannelMessage::Data {
            channel_id,
            data: vec![0], // Success indicator
        });
        transport.send_message(&success).await?;

        // Main SFTP loop
        loop {
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data })) if ch_id == channel_id => {
                    log::debug!("SFTP received {} bytes", data.len());

                    // Process SFTP message
                    match self.handle_data(&data).await {
                        Ok(response) => {
                            if !response.is_empty() {
                                let msg = Message::Channel(ChannelMessage::Data {
                                    channel_id,
                                    data: response,
                                });
                                transport.send_message(&msg).await?;
                            }
                        }
                        Err(e) => {
                            log::error!("SFTP error: {}", e);
                            // Send error response
                            let error_msg = format!("SFTP error: {}", e).into_bytes();
                            let msg = Message::Channel(ChannelMessage::Data {
                                channel_id,
                                data: error_msg,
                            });
                            transport.send_message(&msg).await?;
                        }
                    }
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id })) if ch_id == channel_id => {
                    log::info!("SFTP channel {} closed", channel_id);
                    break;
                }
                Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id })) if ch_id == channel_id => {
                    log::info!("SFTP channel {} EOF", channel_id);
                    break;
                }
                Ok(_) => {
                    // Ignore other messages
                }
                Err(e) => {
                    log::error!("Transport error in SFTP: {}", e);
                    break;
                }
            }
        }

        // Shutdown
        self.shutdown().await?;

        Ok(())
    }
}

#[async_trait]
impl Subsystem for SftpSubsystem {
    fn name(&self) -> &str {
        "sftp"
    }

    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::debug!("[SFTP] Starting SFTP subsystem");
        Ok(())
    }

    async fn handle_data(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Parse SFTP message
        let msg = SftpMessage::from_bytes(data)?;

        // Handle message based on type
        match msg {
            SftpMessage::Init { version } => self.handle_init(version).await,
            SftpMessage::Open(msg) => self.handle_open(msg).await,
            SftpMessage::Close { id, handle } => self.handle_close(id, handle).await,
            SftpMessage::Read(msg) => self.handle_read(msg).await,
            SftpMessage::Write(msg) => self.handle_write(msg).await,
            SftpMessage::OpenDir(msg) => self.handle_opendir(msg).await,
            SftpMessage::ReadDir(msg) => self.handle_readdir(msg).await,
            SftpMessage::Stat(msg) => self.handle_stat(msg).await,
            SftpMessage::RealPath(msg) => self.handle_realpath(msg).await,
            _ => {
                // Unsupported operation
                let response = SftpMessage::Status {
                    id: 0,
                    code: StatusCode::OpUnsupported,
                    message: "Operation not supported".to_string(),
                    language: "en".to_string(),
                };
                Ok(response.to_bytes()?)
            }
        }
    }

    async fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::debug!("[SFTP] Shutting down SFTP subsystem");

        // Close all open handles
        for (_, mut handle) in self.handles.drain() {
            let _ = handle.close().await;
        }

        Ok(())
    }
}