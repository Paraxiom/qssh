//! Async PTY implementation using tokio
use crate::{Result, QsshError};
use std::os::unix::io::{AsRawFd, RawFd, FromRawFd};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use std::process::Stdio;

/// PTY with async support
pub struct AsyncPty {
    master: tokio::fs::File,
    slave_fd: RawFd,
}

impl AsyncPty {
    /// Create a new async PTY
    pub async fn new() -> Result<Self> {
        let mut master_fd: libc::c_int = 0;
        let mut slave_fd: libc::c_int = 0;
        
        unsafe {
            #[cfg(target_os = "linux")]
            let result = libc::openpty(&mut master_fd, &mut slave_fd, 
                           std::ptr::null_mut(), 
                           std::ptr::null(), 
                           std::ptr::null());
            
            #[cfg(target_os = "macos")]
            let result = libc::openpty(&mut master_fd, &mut slave_fd, 
                           std::ptr::null_mut(), 
                           std::ptr::null_mut(), 
                           std::ptr::null_mut());
            
            if result != 0 {
                return Err(QsshError::Io(std::io::Error::last_os_error()));
            }
            
            // Set master to non-blocking
            let flags = libc::fcntl(master_fd, libc::F_GETFL, 0);
            if flags == -1 {
                libc::close(master_fd);
                libc::close(slave_fd);
                return Err(QsshError::Io(std::io::Error::last_os_error()));
            }
            
            if libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                libc::close(master_fd);
                libc::close(slave_fd);
                return Err(QsshError::Io(std::io::Error::last_os_error()));
            }
            
            // Create async File from master FD
            let master = tokio::fs::File::from_raw_fd(master_fd);
            
            Ok(Self {
                master,
                slave_fd,
            })
        }
    }
    
    /// Get slave FD for spawning shell
    pub fn slave_fd(&self) -> RawFd {
        self.slave_fd
    }
    
    /// Set terminal size
    pub fn set_size(&self, rows: u16, cols: u16) -> Result<()> {
        let winsize = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        
        unsafe {
            if libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &winsize) != 0 {
                return Err(QsshError::Io(std::io::Error::last_os_error()));
            }
        }
        
        Ok(())
    }
    
    /// Split into reader and writer
    pub fn split(self) -> (PtyReader, PtyWriter) {
        let (read_half, write_half) = tokio::io::split(self.master);
        (
            PtyReader { 
                inner: read_half,
                slave_fd: Some(self.slave_fd),
            },
            PtyWriter { 
                inner: write_half 
            },
        )
    }
}

pub struct PtyReader {
    inner: tokio::io::ReadHalf<tokio::fs::File>,
    slave_fd: Option<RawFd>,
}

impl PtyReader {
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf).await
    }
}

impl Drop for PtyReader {
    fn drop(&mut self) {
        // Close slave FD when reader is dropped
        if let Some(fd) = self.slave_fd {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

pub struct PtyWriter {
    inner: tokio::io::WriteHalf<tokio::fs::File>,
}

impl PtyWriter {
    pub async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(buf).await
    }
    
    pub async fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush().await
    }
}