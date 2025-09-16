//! Async PTY-based shell handler

use crate::{Result, QsshError, transport::{Transport, Message, ChannelMessage}};
use crate::pty_async::{AsyncPty, PtyReader, PtyWriter};
use tokio::process::{Command, Child};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::process::Stdio;
use std::os::unix::io::{FromRawFd};

pub struct ShellSessionAsync {
    channel_id: u32,
    process: Child,
    transport: Transport,
    username: String,
    pty_reader: PtyReader,
    pty_writer: PtyWriter,
}

impl ShellSessionAsync {
    pub async fn new(
        channel_id: u32,
        transport: Transport,
        username: String,
        term: Option<String>,
        width: u16,
        height: u16,
    ) -> Result<Self> {
        log::info!("Spawning async PTY shell for user {} on channel {}", username, channel_id);
        
        // Create async PTY
        let pty = AsyncPty::new().await?;
        
        // Set terminal size
        pty.set_size(height, width)?;
        
        // Get slave FD for shell
        let slave_fd = pty.slave_fd();
        
        // Spawn shell with PTY slave
        let mut cmd = Command::new("/bin/bash");
        cmd.arg("-i")
           .arg("-l")
           .stdin(unsafe { Stdio::from_raw_fd(slave_fd) })
           .stdout(unsafe { Stdio::from_raw_fd(slave_fd) })
           .stderr(unsafe { Stdio::from_raw_fd(slave_fd) })
           .kill_on_drop(true);
        
        // Set environment
        cmd.env("USER", &username);
        cmd.env("HOME", format!("/root")); // Use root home for now
        cmd.env("SHELL", "/bin/bash");
        cmd.env("TERM", term.unwrap_or_else(|| "xterm-256color".to_string()));
        
        let process = cmd.spawn()
            .map_err(|e| QsshError::Io(e))?;
        
        // Split PTY into reader/writer
        let (pty_reader, pty_writer) = pty.split();
        
        Ok(Self {
            channel_id,
            process,
            transport,
            username,
            pty_reader,
            pty_writer,
        })
    }
    
    pub async fn run(mut self) -> Result<()> {
        let channel_id = self.channel_id;
        let transport = self.transport.clone();
        
        // Send welcome message
        let welcome = format!("Welcome to QSSH, {}!\r\n", self.username);
        log::info!("Sending welcome message: {} bytes", welcome.len());
        let msg = Message::Channel(ChannelMessage::Data {
            channel_id,
            data: welcome.into_bytes(),
        });
        if let Err(e) = transport.send_message(&msg).await {
            log::error!("Failed to send welcome: {}", e);
        }
        
        // Try an immediate read to see if shell prompt is available
        let mut test_buffer = vec![0u8; 1024];
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        match self.pty_reader.read(&mut test_buffer).await {
            Ok(0) => log::warn!("Immediate read got EOF from PTY"),
            Ok(n) => {
                log::info!("Immediate read got {} bytes from PTY", n);
                let msg = Message::Channel(ChannelMessage::Data {
                    channel_id,
                    data: test_buffer[..n].to_vec(),
                });
                match transport.send_message(&msg).await {
                    Ok(_) => log::info!("Successfully sent {} bytes to client", n),
                    Err(e) => log::error!("Failed to send {} bytes: {}", n, e),
                }
            }
            Err(e) => log::warn!("Immediate read error: {}", e),
        }
        
        // Spawn task to read from PTY and send to client
        let transport_out = transport.clone();
        let mut pty_reader = self.pty_reader;
        let output_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            loop {
                match pty_reader.read(&mut buffer).await {
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
                        log::error!("PTY read error: {}", e);
                        break;
                    }
                }
            }
        });
        
        // Handle input from client
        let mut pty_writer = self.pty_writer;
        loop {
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch, data })) if ch == channel_id => {
                    log::debug!("Writing {} bytes to PTY", data.len());
                    if let Err(e) = pty_writer.write_all(&data).await {
                        log::error!("Failed to write to PTY: {}", e);
                        break;
                    }
                    if let Err(e) = pty_writer.flush().await {
                        log::error!("Failed to flush PTY: {}", e);
                        break;
                    }
                }
                Ok(Message::Channel(ChannelMessage::Close { channel_id: ch })) if ch == channel_id => {
                    log::info!("Channel {} closed by client", channel_id);
                    break;
                }
                Ok(_) => {
                    // Ignore other messages
                }
                Err(e) => {
                    log::error!("Transport error: {}", e);
                    break;
                }
            }
        }
        
        // Kill shell process
        let _ = self.process.kill().await;
        
        // Wait for output task
        output_task.abort();
        
        // Send EOF
        let eof = Message::Channel(ChannelMessage::Eof { channel_id });
        let _ = transport.send_message(&eof).await;
        
        log::info!("Shell session ended for user {} on channel {}", self.username, channel_id);
        
        Ok(())
    }
}