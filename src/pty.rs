//! PTY (Pseudo-Terminal) handling for QSSH
//!
//! This module provides platform-specific PTY allocation and management
//! for interactive shell sessions.

use crate::{Result, QsshError};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(unix)]
use libc::{winsize, TIOCGWINSZ, TIOCSWINSZ};

/// Terminal size information
#[derive(Debug, Clone, Copy)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

/// PTY handle for both master and slave sides
pub struct Pty {
    master: RawFd,
    slave: RawFd,
}

impl Pty {
    /// Allocate a new PTY
    #[cfg(unix)]
    pub fn new() -> Result<Self> {
        use libc::{openpty, grantpt, unlockpt};
        use std::ptr;
        
        let mut master: RawFd = 0;
        let mut slave: RawFd = 0;
        
        unsafe {
            if openpty(&mut master, &mut slave, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) != 0 {
                return Err(QsshError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    "Failed to allocate PTY"
                )));
            }
            
            // Grant access to slave PTY
            if grantpt(master) != 0 {
                libc::close(master);
                libc::close(slave);
                return Err(QsshError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    "Failed to grant PTY access"
                )));
            }
            
            // Unlock slave PTY
            if unlockpt(master) != 0 {
                libc::close(master);
                libc::close(slave);
                return Err(QsshError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    "Failed to unlock PTY"
                )));
            }
        }
        
        Ok(Self { master, slave })
    }
    
    /// Get the master file descriptor
    pub fn master_fd(&self) -> RawFd {
        self.master
    }
    
    /// Get the slave file descriptor
    pub fn slave_fd(&self) -> RawFd {
        self.slave
    }
    
    /// Set terminal size
    #[cfg(unix)]
    pub fn set_size(&self, size: TerminalSize) -> Result<()> {
        let ws = winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        };
        
        unsafe {
            if libc::ioctl(self.master, TIOCSWINSZ, &ws) != 0 {
                return Err(QsshError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    "Failed to set terminal size"
                )));
            }
        }
        
        Ok(())
    }
    
    /// Get terminal size
    #[cfg(unix)]
    pub fn get_size(&self) -> Result<TerminalSize> {
        let mut ws: winsize = unsafe { std::mem::zeroed() };
        
        unsafe {
            if libc::ioctl(self.master, TIOCGWINSZ, &mut ws) != 0 {
                return Err(QsshError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other, 
                    "Failed to get terminal size"
                )));
            }
        }
        
        Ok(TerminalSize {
            rows: ws.ws_row,
            cols: ws.ws_col,
            pixel_width: ws.ws_xpixel,
            pixel_height: ws.ws_ypixel,
        })
    }
    
    /// Create async reader/writer for the master side
    pub fn master_async(&self) -> (PtyReader, PtyWriter) {
        let master_fd = self.master;
        
        // Create duplicated file descriptors for reader and writer
        let reader_fd = unsafe { libc::dup(master_fd) };
        let writer_fd = unsafe { libc::dup(master_fd) };
        
        (
            PtyReader { fd: reader_fd },
            PtyWriter { fd: writer_fd },
        )
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.master);
            libc::close(self.slave);
        }
    }
}

/// Async reader for PTY master
pub struct PtyReader {
    fd: RawFd,
}

impl AsyncRead for PtyReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Use tokio's AsyncFd for async operations
        let mut async_fd = match tokio::io::unix::AsyncFd::new(self.fd) {
            Ok(fd) => fd,
            Err(e) => return std::task::Poll::Ready(Err(e)),
        };
        
        match async_fd.poll_read_ready(cx) {
            std::task::Poll::Ready(Ok(mut guard)) => {
                let unfilled = buf.initialize_unfilled();
                match unsafe {
                    libc::read(
                        self.fd,
                        unfilled.as_mut_ptr() as *mut libc::c_void,
                        unfilled.len(),
                    )
                } {
                    -1 => {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            guard.clear_ready();
                            std::task::Poll::Pending
                        } else {
                            std::task::Poll::Ready(Err(err))
                        }
                    }
                    n => {
                        buf.advance(n as usize);
                        std::task::Poll::Ready(Ok(()))
                    }
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Async writer for PTY master
pub struct PtyWriter {
    fd: RawFd,
}

impl AsyncWrite for PtyWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut async_fd = match tokio::io::unix::AsyncFd::new(self.fd) {
            Ok(fd) => fd,
            Err(e) => return std::task::Poll::Ready(Err(e)),
        };
        
        match async_fd.poll_write_ready(cx) {
            std::task::Poll::Ready(Ok(mut guard)) => {
                match unsafe {
                    libc::write(
                        self.fd,
                        buf.as_ptr() as *const libc::c_void,
                        buf.len(),
                    )
                } {
                    -1 => {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            guard.clear_ready();
                            std::task::Poll::Pending
                        } else {
                            std::task::Poll::Ready(Err(err))
                        }
                    }
                    n => std::task::Poll::Ready(Ok(n as usize)),
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
    
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // PTYs don't need explicit flushing
        std::task::Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Close the file descriptor
        unsafe {
            libc::close(self.fd);
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for PtyReader {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl Drop for PtyWriter {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}