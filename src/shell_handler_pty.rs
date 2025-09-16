//! PTY-based shell process handler for QSSH server

use crate::{Result, QsshError, transport::{Transport, Message, ChannelMessage}, pty::{Pty, TerminalSize}};
use tokio::process::{Command, Child};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::process::Stdio;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use tokio::fs::File;

/// Shell session handler with PTY support
pub struct ShellSessionPty {
    channel_id: u32,
    process: Child,
    pty: Pty,
    transport: Transport,
    username: String,
}

impl ShellSessionPty {
    /// Create a new shell session with PTY
    pub async fn new(
        channel_id: u32,
        transport: Transport,
        username: String,
        term: Option<String>,
        width: u16,
        height: u16,
    ) -> Result<Self> {
        log::info!("Spawning PTY shell for user {} on channel {}", username, channel_id);
        
        // Create PTY
        let pty = Pty::new()?;
        
        // Set terminal size
        let term_size = TerminalSize {
            rows: height,
            cols: width,
            pixel_width: 0,
            pixel_height: 0,
        };
        pty.set_size(term_size)?;
        
        // Get slave FD for the shell process
        let slave_fd = pty.slave_fd();
        
        // Spawn shell process with PTY slave
        let mut cmd = Command::new("/bin/bash");
        cmd.arg("-i")  // Interactive shell
           .arg("-l")  // Login shell to load profile
           .stdin(unsafe { Stdio::from_raw_fd(slave_fd) })
           .stdout(unsafe { Stdio::from_raw_fd(slave_fd) })
           .stderr(unsafe { Stdio::from_raw_fd(slave_fd) })
           .kill_on_drop(true);
        
        // Set environment variables
        cmd.env("USER", &username);
        cmd.env("HOME", format!("/home/{}", &username));
        cmd.env("SHELL", "/bin/bash");
        cmd.env("TERM", term.unwrap_or_else(|| "xterm-256color".to_string()));
        
        let process = cmd.spawn()
            .map_err(|e| QsshError::Io(e))?;
        
        Ok(Self {
            channel_id,
            process,
            pty,
            transport,
            username,
        })
    }
    
    /// Run the shell session
    pub async fn run(mut self) -> Result<()> {
        let transport = self.transport.clone();
        let channel_id = self.channel_id;
        
        // Get async reader/writer for PTY master
        let (mut master_read, mut master_write) = self.pty.master_async();
        
        // Send initial welcome message
        let welcome = format!("QSSH Shell ready for user {}\r\n", self.username);
        let welcome_msg = Message::Channel(ChannelMessage::Data {
            channel_id,
            data: welcome.into_bytes(),
        });
        if let Err(e) = transport.send_message(&welcome_msg).await {
            log::error!("Failed to send welcome message: {}", e);
        }
        
        // Spawn task to read from PTY master and send to client
        let transport_out = transport.clone();
        let output_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            loop {
                match master_read.read(&mut buffer).await {
                    Ok(0) => {
                        log::debug!("PTY EOF");
                        break;
                    }
                    Ok(n) => {
                        log::debug!("Read {} bytes from PTY", n);
                        let msg = Message::Channel(ChannelMessage::Data {
                            channel_id,
                            data: buffer[..n].to_vec(),
                        });
                        if let Err(e) = transport_out.send_message(&msg).await {
                            log::error!("Failed to send PTY data: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("Error reading PTY: {}", e);
                        break;
                    }
                }
            }
        });
        
        // Handle input from client and write to PTY
        loop {
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch, data })) if ch == channel_id => {
                    log::debug!("Writing {} bytes to PTY", data.len());
                    // Write data to PTY master
                    if let Err(e) = master_write.write_all(&data).await {
                        log::error!("Failed to write to PTY: {}", e);
                        break;
                    }
                    if let Err(e) = master_write.flush().await {
                        log::error!("Failed to flush PTY: {}", e);
                        break;
                    }
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id: ch })) if ch == channel_id => {
                    log::info!("Channel {} closed by client", channel_id);
                    break;
                }
                Ok(_) => {
                    // Other message, ignore for now
                }
                Err(e) => {
                    log::error!("Error receiving message: {}", e);
                    break;
                }
            }
        }
        
        // Kill the shell process
        if let Err(e) = self.process.kill().await {
            log::warn!("Failed to kill shell process: {}", e);
        }
        
        // Wait for output task to complete
        let _ = output_task.await;
        
        // PTY will be closed when dropped
        
        // Send EOF to client
        let eof = Message::Channel(ChannelMessage::Eof { channel_id });
        let _ = transport.send_message(&eof).await;
        
        log::info!("PTY shell session ended for user {} on channel {}", self.username, channel_id);
        
        Ok(())
    }
}