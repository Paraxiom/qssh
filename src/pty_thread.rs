//! PTY handler using blocking thread (the reliable approach)

use crate::{Result, QsshError};
use std::os::unix::io::{AsRawFd, RawFd, FromRawFd};
use tokio::sync::mpsc;
use std::io::{Read, Write};

pub struct PtyThread {
    master_fd: RawFd,
    slave_fd: RawFd,
}

impl PtyThread {
    pub fn new() -> Result<Self> {
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
        }
        
        Ok(Self { master_fd, slave_fd })
    }
    
    pub fn slave_fd(&self) -> RawFd {
        self.slave_fd
    }
    
    pub fn set_size(&self, rows: u16, cols: u16) -> Result<()> {
        let winsize = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        
        unsafe {
            if libc::ioctl(self.master_fd, libc::TIOCSWINSZ, &winsize) != 0 {
                return Err(QsshError::Io(std::io::Error::last_os_error()));
            }
        }
        
        Ok(())
    }
    
    /// Start blocking I/O threads for PTY
    /// Takes ownership and consumes self to prevent Drop from being called
    /// Returns (tx_to_pty, rx_from_pty, slave_fd) - caller owns slave_fd
    pub fn start_threads(mut self) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>, RawFd) {
        let (tx_to_pty, mut rx_to_pty) = mpsc::channel::<Vec<u8>>(256);
        let (tx_from_pty, rx_from_pty) = mpsc::channel::<Vec<u8>>(256);
        
        let master_fd = self.master_fd;
        let slave_fd = self.slave_fd;
        
        // Mark FDs as consumed so Drop doesn't close them
        self.master_fd = -1;
        self.slave_fd = -1;
        
        // Thread to write to PTY
        let master_fd_write = unsafe { libc::dup(master_fd) };
        std::thread::spawn(move || {
            log::debug!("PTY write thread started");
            let mut master = unsafe { std::fs::File::from_raw_fd(master_fd_write) };
            while let Some(data) = rx_to_pty.blocking_recv() {
                log::debug!("PTY write thread received {} bytes to write: {:?}", 
                    data.len(), String::from_utf8_lossy(&data));
                if let Err(e) = master.write_all(&data) {
                    log::error!("PTY write error: {}", e);
                    break;
                }
                if let Err(e) = master.flush() {
                    log::error!("PTY flush error: {}", e);
                    break;
                }
                log::debug!("PTY write thread successfully wrote {} bytes", data.len());
            }
            log::debug!("PTY write thread exiting");
        });
        
        // Thread to read from PTY
        let master_fd_read = unsafe { libc::dup(master_fd) };
        std::thread::spawn(move || {
            log::debug!("PTY read thread started");
            let mut master = unsafe { std::fs::File::from_raw_fd(master_fd_read) };
            let mut buffer = vec![0u8; 4096];
            loop {
                match master.read(&mut buffer) {
                    Ok(0) => {
                        log::debug!("PTY read thread got EOF");
                        break;
                    }
                    Ok(n) => {
                        log::debug!("PTY read thread got {} bytes", n);
                        if tx_from_pty.blocking_send(buffer[..n].to_vec()).is_err() {
                            log::debug!("PTY read thread channel closed");
                            break;
                        }
                    }
                    Err(e) => {
                        log::debug!("PTY read thread error: {}", e);
                        break;
                    }
                }
            }
            log::debug!("PTY read thread exiting");
        });
        
        // Close the original master FD since we duplicated it
        unsafe { libc::close(master_fd); }
        
        // Return slave_fd to be closed by the shell when it exits
        // We don't close it here as the shell process is using it
        
        (tx_to_pty, rx_from_pty, slave_fd)
    }
}

impl Drop for PtyThread {
    fn drop(&mut self) {
        unsafe {
            if self.master_fd != -1 {
                libc::close(self.master_fd);
            }
            if self.slave_fd != -1 {
                libc::close(self.slave_fd);
            }
        }
    }
}