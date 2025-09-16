//! Shell process handler for QSSH server

use crate::{Result, QsshError, transport::{Transport, Message, ChannelMessage}, pty::{Pty, TerminalSize}};
use tokio::process::{Command, Child};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::process::Stdio;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::os::unix::io::{AsRawFd, FromRawFd};

/// Shell session handler
pub struct ShellSession {
    channel_id: u32,
    process: Child,
    transport: Transport,
    username: String,
}

impl ShellSession {
    /// Create a new shell session
    pub async fn new(
        channel_id: u32,
        transport: Transport,
        username: String,
        term: Option<String>,
        width: u16,
        height: u16,
    ) -> Result<Self> {
        log::info!("Spawning shell for user {} on channel {}", username, channel_id);
        
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
        
        // Create stdio from slave FD for the shell process
        let slave_fd = pty.slave_fd();
        let slave_stdio = unsafe { Stdio::from_raw_fd(slave_fd) };
        
        // Spawn shell process with PTY
        let mut cmd = Command::new("/bin/bash");
        cmd.arg("-i")  // Interactive shell
           .arg("-l")  // Login shell to load profile
           .stdin(unsafe { Stdio::from_raw_fd(slave_fd) })
           .stdout(unsafe { Stdio::from_raw_fd(slave_fd) })
           .stderr(unsafe { Stdio::from_raw_fd(slave_fd) })
           .kill_on_drop(true);
        
        // Set environment variables
        cmd.env("USER", &username);
        cmd.env("SHELL", "/bin/bash");
        cmd.env("TERM", term.unwrap_or_else(|| "xterm-256color".to_string()));
        cmd.env("LINES", height.to_string());
        cmd.env("COLUMNS", width.to_string());
        
        let mut process = cmd.spawn()
            .map_err(|e| QsshError::Io(e))?;
        
        // Close slave FD in parent process
        unsafe {
            libc::close(slave_fd);
        }
        
        // Store the PTY master FD in the process structure for later use
        // We'll need to modify the Child structure or create a wrapper
        
        Ok(Self {
            channel_id,
            process,
            transport,
            username,
        })
    }
    
    /// Run the shell session
    pub async fn run(mut self) -> Result<()> {
        let mut stdin = self.process.stdin.take()
            .ok_or_else(|| QsshError::Protocol("Failed to get stdin".into()))?;
        let mut stdout = self.process.stdout.take()
            .ok_or_else(|| QsshError::Protocol("Failed to get stdout".into()))?;
        let mut stderr = self.process.stderr.take()
            .ok_or_else(|| QsshError::Protocol("Failed to get stderr".into()))?;
        
        let transport = self.transport.clone();
        let channel_id = self.channel_id;
        
        // Send initial prompt to indicate shell is ready
        let welcome = format!("QSSH Shell ready for user {}\n", self.username);
        let welcome_msg = Message::Channel(ChannelMessage::Data {
            channel_id,
            data: welcome.into_bytes(),
        });
        if let Err(e) = transport.send_message(&welcome_msg).await {
            log::error!("Failed to send welcome message: {}", e);
        }
        
        // Spawn task to read from stdout
        let transport_stdout = transport.clone();
        let stdout_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            loop {
                match stdout.read(&mut buffer).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        log::debug!("Read {} bytes from shell stdout", n);
                        let msg = Message::Channel(ChannelMessage::Data {
                            channel_id,
                            data: buffer[..n].to_vec(),
                        });
                        if let Err(e) = transport_stdout.send_message(&msg).await {
                            log::error!("Failed to send stdout data: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("Error reading stdout: {}", e);
                        break;
                    }
                }
            }
        });
        
        // Spawn task to read from stderr
        let transport_stderr = transport.clone();
        let stderr_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            loop {
                match stderr.read(&mut buffer).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        let msg = Message::Channel(ChannelMessage::Data {
                            channel_id,
                            data: buffer[..n].to_vec(),
                        });
                        if let Err(e) = transport_stderr.send_message(&msg).await {
                            log::error!("Failed to send stderr data: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("Error reading stderr: {}", e);
                        break;
                    }
                }
            }
        });
        
        // Handle input from client
        loop {
            match transport.receive_message::<Message>().await {
                Ok(Message::Channel(ChannelMessage::Data { channel_id: ch, data })) if ch == channel_id => {
                    // Write data to shell stdin
                    if let Err(e) = stdin.write_all(&data).await {
                        log::error!("Failed to write to shell stdin: {}", e);
                        break;
                    }
                    if let Err(e) = stdin.flush().await {
                        log::error!("Failed to flush stdin: {}", e);
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
        
        // Wait for tasks to complete
        let _ = stdout_task.await;
        let _ = stderr_task.await;
        
        // Send EOF to client
        let eof = Message::Channel(ChannelMessage::Eof { channel_id });
        let _ = transport.send_message(&eof).await;
        
        log::info!("Shell session ended for user {} on channel {}", self.username, channel_id);
        
        Ok(())
    }
}