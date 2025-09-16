// SFTP Session Management
// Manages SFTP session state and working directory

use std::path::PathBuf;

/// SFTP Session state
pub struct SftpSession {
    current_dir: PathBuf,
    home_dir: PathBuf,
    username: String,
}

impl SftpSession {
    /// Create a new SFTP session
    pub fn new() -> Self {
        let home_dir = std::env::var("HOME")
            .unwrap_or_else(|_| "/tmp".to_string());

        let username = std::env::var("USER")
            .unwrap_or_else(|_| "unknown".to_string());

        SftpSession {
            current_dir: PathBuf::from(&home_dir),
            home_dir: PathBuf::from(home_dir),
            username,
        }
    }

    /// Create a new SFTP session for a specific user
    pub fn for_user(username: String, home_dir: PathBuf) -> Self {
        SftpSession {
            current_dir: home_dir.clone(),
            home_dir,
            username,
        }
    }

    /// Get current working directory
    pub fn current_dir(&self) -> &PathBuf {
        &self.current_dir
    }

    /// Change current directory
    pub fn change_dir(&mut self, path: PathBuf) {
        self.current_dir = path;
    }

    /// Get home directory
    pub fn home_dir(&self) -> &PathBuf {
        &self.home_dir
    }

    /// Get username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Resolve a path relative to current directory
    pub fn resolve_path(&self, path: &str) -> PathBuf {
        if path.starts_with('/') {
            // Absolute path
            PathBuf::from(path)
        } else if path == "~" || path.starts_with("~/") {
            // Home directory reference
            if path == "~" {
                self.home_dir.clone()
            } else {
                self.home_dir.join(&path[2..])
            }
        } else if path == "." {
            // Current directory
            self.current_dir.clone()
        } else if path == ".." {
            // Parent directory
            self.current_dir.parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| self.current_dir.clone())
        } else {
            // Relative path
            self.current_dir.join(path)
        }
    }
}