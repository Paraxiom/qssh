//! Shell handler using blocking threads for PTY I/O

use crate::{Result, QsshError, transport::{Transport, Message, ChannelMessage}};
use crate::pty_thread::PtyThread;
use tokio::process::{Command, Child};
use tokio::sync::mpsc;
use std::process::Stdio;
use std::os::unix::io::FromRawFd;

pub struct ShellSessionThread {
    channel_id: u32,
    process: Command,  // Changed from Child to Command
    transport: Transport,
    username: String,
    pty: PtyThread,
}

impl ShellSessionThread {
    pub async fn new(
        channel_id: u32,
        transport: Transport,
        username: String,
        term: Option<String>,
        width: u16,
        height: u16,
    ) -> Result<Self> {
        log::info!("Spawning thread-based PTY shell for user {} on channel {}", username, channel_id);
        
        // Create PTY
        let pty = PtyThread::new()?;
        pty.set_size(height, width)?;
        
        let slave_fd = pty.slave_fd();
        
        // Duplicate slave FD for each stdio stream
        let slave_stdin = unsafe { libc::dup(slave_fd) };
        let slave_stdout = unsafe { libc::dup(slave_fd) };
        let slave_stderr = unsafe { libc::dup(slave_fd) };
        
        // Detect the user's shell
        let shell = std::env::var("SHELL").unwrap_or_else(|_| {
            // Try to get from passwd file
            if std::path::Path::new("/bin/zsh").exists() {
                "/bin/zsh".to_string()
            } else {
                "/bin/bash".to_string()
            }
        });
        
        // Get actual home directory
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| {
            #[cfg(target_os = "macos")]
            { format!("/Users/{}", username) }
            #[cfg(not(target_os = "macos"))]
            { format!("/home/{}", username) }
        });
        
        log::info!("Starting shell {} for user {} with home {}", shell, username, home_dir);
        
        // Spawn shell with PTY slave
        let mut cmd = Command::new(&shell);
        cmd.arg("-il")  // -i for interactive, -l for login shell
           .stdin(unsafe { Stdio::from_raw_fd(slave_stdin) })
           .stdout(unsafe { Stdio::from_raw_fd(slave_stdout) })
           .stderr(unsafe { Stdio::from_raw_fd(slave_stderr) })
           .kill_on_drop(true);
        
        // Set environment
        cmd.env("USER", &username);
        cmd.env("HOME", &home_dir);
        cmd.env("SHELL", &shell);
        cmd.env("TERM", term.unwrap_or_else(|| "xterm-256color".to_string()));
        cmd.env("PATH", std::env::var("PATH").unwrap_or_else(|_| 
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()));
        
        // Set up process session
        unsafe {
            cmd.pre_exec(move || {
                // Create a new session
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                
                // Make the slave PTY our controlling terminal
                if libc::ioctl(slave_fd, libc::TIOCSCTTY.into(), 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                
                Ok(())
            });
        }
        
        // Don't spawn yet - save the command for run()
        // This ensures the shell starts AFTER the PTY threads are ready
        
        Ok(Self {
            channel_id,
            process: cmd, // Store Command instead of Child
            transport,
            username,
            pty,
        })
    }
    
    pub async fn run(mut self) -> Result<()> {
        log::info!("Starting shell session run() for channel {}", self.channel_id);
        let channel_id = self.channel_id;
        let transport = self.transport.clone();
        log::debug!("Shell handler has transport, starting operations");
        
        // Start the PTY I/O threads FIRST
        log::debug!("Starting PTY threads");
        let (tx_to_pty, mut rx_from_pty, original_slave_fd) = self.pty.start_threads();
        
        // NOW spawn the shell process - after PTY threads are ready
        log::debug!("Spawning shell process");
        let mut process = self.process.spawn()
            .map_err(|e| QsshError::Io(e))?;
        
        // Close the original slave FD since we duplicated it for the shell process
        unsafe { libc::close(original_slave_fd); }
        
        // Send welcome message
        let welcome = b"Welcome to QSSH!\r\n";
        log::debug!("Sending welcome message: {} bytes", welcome.len());
        let msg = Message::Channel(ChannelMessage::Data {
            channel_id,
            data: welcome.to_vec(),
        });
        transport.send_message(&msg).await?;
        
        // Give shell a moment to fully start
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        
        // Spawn task to forward PTY output to client
        let transport_out = transport.clone();
        let output_task = tokio::spawn(async move {
            log::debug!("Starting PTY output forwarding task");
            while let Some(data) = rx_from_pty.recv().await {
                log::debug!("Forwarding {} bytes from PTY to client: {:?}", data.len(), 
                    String::from_utf8_lossy(&data[..std::cmp::min(50, data.len())]));
                let msg = Message::Channel(ChannelMessage::Data {
                    channel_id,
                    data,
                });
                match transport_out.send_message(&msg).await {
                    Ok(_) => log::debug!("Successfully sent PTY data to client"),
                    Err(e) => {
                        log::error!("Failed to send PTY data: {}", e);
                        break;
                    }
                }
            }
            log::debug!("PTY output forwarding task ended");
        });
        
        // Force the spawned task to start immediately
        tokio::task::yield_now().await;
        // Small delay to ensure PTY data starts flowing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Handle input from client
        log::info!("Shell handler entering main receive loop");
        loop {
            log::info!("Shell handler waiting for message from client...");
            tokio::select! {
                result = transport.receive_message::<Message>() => {
                    log::info!("Shell handler received result from transport");
                    match result {
                        Ok(Message::Channel(ChannelMessage::Data { channel_id: ch, data })) if ch == channel_id => {
                            log::info!("Shell handler received {} bytes from client for PTY: {:?}", 
                                data.len(), String::from_utf8_lossy(&data));
                            if tx_to_pty.send(data.clone()).await.is_err() {
                                log::error!("Failed to send data to PTY");
                                break;
                            }
                            log::info!("Shell handler successfully forwarded {} bytes to PTY", data.len());
                            log::info!("Shell handler continuing loop, waiting for next message");
                        }
                        Ok(Message::Channel(ChannelMessage::Close { channel_id: ch })) if ch == channel_id => {
                            log::info!("Channel {} closed by client", ch);
                            break;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            log::error!("Shell handler transport receive error: {}", e);
                            break;
                        }
                    }
                }
                _ = process.wait() => {
                    log::info!("Shell process exited");
                    break;
                }
            }
        }
        
        // Clean up
        let _ = process.kill().await;
        output_task.abort();
        
        log::info!("Shell session ended for user {} on channel {}", self.username, self.channel_id);
        
        // Send EOF
        let eof = Message::Channel(ChannelMessage::Eof { channel_id: self.channel_id });
        let _ = self.transport.send_message(&eof).await;
        
        Ok(())
    }
}