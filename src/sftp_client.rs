//! SFTP Client - speaks SFTP protocol over a qssh channel
//!
//! Used by qscp for proper file transfers instead of the base64 exec hack.

use crate::transport::{Transport, Message, ChannelMessage, ChannelType};
use crate::subsystems::sftp::protocol::*;
use crate::{Result, QsshError};

/// SFTP client that operates over a qssh channel
pub struct SftpClient {
    transport: Transport,
    channel_id: u32,
    next_id: u32,
}

impl SftpClient {
    /// Open an SFTP session on the given transport.
    /// Opens a session channel, requests the "sftp" subsystem, and performs the Init/Version handshake.
    pub async fn connect(transport: Transport) -> Result<Self> {
        // Open session channel
        let channel_id = rand::random::<u32>() % 65536;

        let open_msg = Message::Channel(ChannelMessage::Open {
            channel_id,
            channel_type: ChannelType::Session,
            window_size: 1024 * 1024,
            max_packet_size: 32768,
        });
        transport.send_message(&open_msg).await?;

        // Wait for Accept
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                return Err(QsshError::Protocol("Timeout waiting for SFTP channel accept".into()));
            }
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Accept { channel_id: ch_id, .. })) if ch_id == channel_id => break,
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }

        // Request SFTP subsystem
        let subsystem_msg = Message::Channel(ChannelMessage::SubsystemRequest {
            channel_id,
            subsystem: "sftp".to_string(),
        });
        transport.send_message(&subsystem_msg).await?;

        // Wait for success indicator (single null byte)
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                return Err(QsshError::Protocol("Timeout waiting for SFTP subsystem start".into()));
            }
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data })) if ch_id == channel_id => {
                    if data == vec![0] {
                        break; // Success indicator
                    }
                    // Might be an error message
                    let msg = String::from_utf8_lossy(&data);
                    return Err(QsshError::Protocol(format!("SFTP subsystem error: {}", msg)));
                }
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }

        let mut client = Self {
            transport,
            channel_id,
            next_id: 1,
        };

        // SFTP Init/Version handshake
        client.sftp_init().await?;

        Ok(client)
    }

    fn next_request_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Send an SFTP message over the channel
    async fn send_sftp(&self, msg: &SftpMessage) -> Result<()> {
        let data = msg.to_bytes()
            .map_err(|e| QsshError::Protocol(format!("SFTP serialize: {}", e)))?;

        let channel_msg = Message::Channel(ChannelMessage::Data {
            channel_id: self.channel_id,
            data,
        });
        self.transport.send_message(&channel_msg).await
    }

    /// Receive an SFTP message from the channel
    async fn recv_sftp(&self) -> Result<SftpMessage> {
        loop {
            match self.transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch_id, data })) if ch_id == self.channel_id => {
                    let msg = SftpMessage::from_bytes(&data)
                        .map_err(|e| QsshError::Protocol(format!("SFTP parse: {}", e)))?;
                    return Ok(msg);
                }
                Ok(Message::Channel(ChannelMessage::Eof { channel_id: ch_id })) if ch_id == self.channel_id => {
                    return Err(QsshError::Protocol("SFTP channel EOF".into()));
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id: ch_id })) if ch_id == self.channel_id => {
                    return Err(QsshError::Protocol("SFTP channel closed".into()));
                }
                Ok(_) => {} // Ignore other messages
                Err(e) => return Err(e),
            }
        }
    }

    /// Perform SFTP Init/Version handshake
    async fn sftp_init(&mut self) -> Result<()> {
        let init = SftpMessage::Init { version: 3 };
        self.send_sftp(&init).await?;

        match self.recv_sftp().await? {
            SftpMessage::Version { version, .. } => {
                log::info!("SFTP server version: {}", version);
                Ok(())
            }
            other => Err(QsshError::Protocol(format!("Expected Version, got: {:?}", other))),
        }
    }

    /// Upload a file to the remote server
    pub async fn upload(&mut self, local_data: &[u8], remote_path: &str) -> Result<()> {
        let id = self.next_request_id();

        // Open file for writing (create + truncate)
        let open_msg = SftpMessage::Open(OpenMessage {
            id,
            filename: remote_path.to_string(),
            flags: OpenFlags {
                read: false,
                write: true,
                append: false,
                create: true,
                truncate: true,
                exclusive: false,
            },
            attrs: FileAttributes::default(),
        });
        self.send_sftp(&open_msg).await?;

        let handle = match self.recv_sftp().await? {
            SftpMessage::Handle { handle, .. } => handle,
            SftpMessage::Status { code, message, .. } => {
                return Err(QsshError::Protocol(format!("SFTP open failed: {:?} - {}", code, message)));
            }
            other => return Err(QsshError::Protocol(format!("Expected Handle, got: {:?}", other))),
        };

        // Write data in chunks
        let chunk_size = 32768; // 32KB chunks
        let mut offset = 0u64;

        for chunk in local_data.chunks(chunk_size) {
            let id = self.next_request_id();
            let write_msg = SftpMessage::Write(WriteMessage {
                id,
                handle: handle.clone(),
                offset,
                data: chunk.to_vec(),
            });
            self.send_sftp(&write_msg).await?;

            // Wait for Status OK
            match self.recv_sftp().await? {
                SftpMessage::Status { code: StatusCode::Ok, .. } => {}
                SftpMessage::Status { code, message, .. } => {
                    return Err(QsshError::Protocol(format!("SFTP write failed: {:?} - {}", code, message)));
                }
                other => return Err(QsshError::Protocol(format!("Expected Status, got: {:?}", other))),
            }

            offset += chunk.len() as u64;
        }

        // Close handle
        let id = self.next_request_id();
        let close_msg = SftpMessage::Close { id, handle };
        self.send_sftp(&close_msg).await?;

        match self.recv_sftp().await? {
            SftpMessage::Status { code: StatusCode::Ok, .. } => Ok(()),
            SftpMessage::Status { code, message, .. } => {
                Err(QsshError::Protocol(format!("SFTP close failed: {:?} - {}", code, message)))
            }
            other => Err(QsshError::Protocol(format!("Expected Status, got: {:?}", other))),
        }
    }

    /// Download a file from the remote server
    pub async fn download(&mut self, remote_path: &str) -> Result<Vec<u8>> {
        let id = self.next_request_id();

        // Open file for reading
        let open_msg = SftpMessage::Open(OpenMessage {
            id,
            filename: remote_path.to_string(),
            flags: OpenFlags {
                read: true,
                write: false,
                append: false,
                create: false,
                truncate: false,
                exclusive: false,
            },
            attrs: FileAttributes::default(),
        });
        self.send_sftp(&open_msg).await?;

        let handle = match self.recv_sftp().await? {
            SftpMessage::Handle { handle, .. } => handle,
            SftpMessage::Status { code, message, .. } => {
                return Err(QsshError::Protocol(format!("SFTP open failed: {:?} - {}", code, message)));
            }
            other => return Err(QsshError::Protocol(format!("Expected Handle, got: {:?}", other))),
        };

        // Read data in chunks
        let mut data = Vec::new();
        let chunk_size = 32768u32;
        let mut offset = 0u64;

        loop {
            let id = self.next_request_id();
            let read_msg = SftpMessage::Read(ReadMessage {
                id,
                handle: handle.clone(),
                offset,
                length: chunk_size,
            });
            self.send_sftp(&read_msg).await?;

            match self.recv_sftp().await? {
                SftpMessage::Data { data: chunk, .. } => {
                    offset += chunk.len() as u64;
                    data.extend(chunk);
                }
                SftpMessage::Status { code: StatusCode::Eof, .. } => break,
                SftpMessage::Status { code, message, .. } => {
                    return Err(QsshError::Protocol(format!("SFTP read failed: {:?} - {}", code, message)));
                }
                other => return Err(QsshError::Protocol(format!("Expected Data/Eof, got: {:?}", other))),
            }
        }

        // Close handle
        let id = self.next_request_id();
        let close_msg = SftpMessage::Close { id, handle };
        self.send_sftp(&close_msg).await?;

        // Ignore close errors on download
        let _ = self.recv_sftp().await?;

        Ok(data)
    }

    /// Create a remote directory
    pub async fn mkdir(&mut self, path: &str) -> Result<()> {
        // Use exec-like approach since SFTP mkdir requires the full message
        // For now, stat to check if it exists, otherwise create
        let id = self.next_request_id();
        let stat_msg = SftpMessage::Stat(StatMessage {
            id,
            path: path.to_string(),
        });
        self.send_sftp(&stat_msg).await?;

        match self.recv_sftp().await? {
            SftpMessage::Attrs { .. } => {
                // Directory already exists
                Ok(())
            }
            SftpMessage::Status { code: StatusCode::NoSuchFile, .. } => {
                // Need to create — SFTP Mkdir not yet parsed by from_bytes,
                // so use a workaround: send raw mkdir message
                // For now, return error indicating mkdir is not supported via SFTP
                Err(QsshError::Protocol("Remote directory does not exist".into()))
            }
            other => Err(QsshError::Protocol(format!("Unexpected stat response: {:?}", other))),
        }
    }

    /// Close the SFTP session
    pub async fn close(self) -> Result<()> {
        let close_msg = Message::Channel(ChannelMessage::Close {
            channel_id: self.channel_id,
        });
        let _ = self.transport.send_message(&close_msg).await;
        Ok(())
    }
}
