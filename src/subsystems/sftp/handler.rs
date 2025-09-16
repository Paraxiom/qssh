// SFTP File Handler
// Manages file operations for SFTP subsystem

use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use std::io::SeekFrom;

use super::protocol::{FileInfo, FileAttributes, OpenFlags};

/// Represents an open file or directory handle
pub enum FileHandle {
    File {
        path: PathBuf,
        file: File,
        flags: OpenFlags,
    },
    Directory {
        path: PathBuf,
        entries: Vec<FileInfo>,
        position: usize,
    },
}

impl FileHandle {
    /// Open a file with specified flags
    pub async fn open(path: PathBuf, flags: OpenFlags) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut options = OpenOptions::new();

        if flags.read {
            options.read(true);
        }
        if flags.write {
            options.write(true);
        }
        if flags.append {
            options.append(true);
        }
        if flags.create {
            options.create(true);
        }
        if flags.truncate {
            options.truncate(true);
        }
        if flags.exclusive {
            options.create_new(true);
        }

        let file = options.open(&path).await?;

        Ok(FileHandle::File {
            path,
            file,
            flags,
        })
    }

    /// Open a directory for reading
    pub async fn opendir(path: PathBuf) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut entries = Vec::new();
        let mut dir_entries = tokio::fs::read_dir(&path).await?;

        while let Some(entry) = dir_entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            let filename = entry.file_name().to_string_lossy().to_string();

            // Create long name (ls -l style)
            let longname = format_longname(&filename, &metadata);

            entries.push(FileInfo {
                filename,
                longname,
                attrs: FileAttributes::from_metadata(&metadata),
            });
        }

        Ok(FileHandle::Directory {
            path,
            entries,
            position: 0,
        })
    }

    /// Read data from file
    pub async fn read(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            FileHandle::File { file, .. } => {
                file.seek(SeekFrom::Start(offset)).await?;
                let mut buffer = vec![0u8; length];
                let bytes_read = file.read(&mut buffer).await?;
                buffer.truncate(bytes_read);
                Ok(buffer)
            }
            _ => Err("Not a file handle".into()),
        }
    }

    /// Write data to file
    pub async fn write(&mut self, offset: u64, data: &[u8]) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            FileHandle::File { file, flags, .. } => {
                if !flags.write && !flags.append {
                    return Err("File not opened for writing".into());
                }

                if flags.append {
                    file.seek(SeekFrom::End(0)).await?;
                } else {
                    file.seek(SeekFrom::Start(offset)).await?;
                }

                Ok(file.write(data).await?)
            }
            _ => Err("Not a file handle".into()),
        }
    }

    /// Read directory entries
    pub async fn readdir(&mut self) -> Result<Vec<FileInfo>, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            FileHandle::Directory { entries, position, .. } => {
                // Return batch of entries (max 100 at a time)
                let batch_size = 100;
                let start = *position;
                let end = std::cmp::min(start + batch_size, entries.len());

                if start >= entries.len() {
                    return Ok(Vec::new()); // EOF
                }

                *position = end;
                Ok(entries[start..end].to_vec())
            }
            _ => Err("Not a directory handle".into()),
        }
    }

    /// Close the handle
    pub async fn close(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            FileHandle::File { file, .. } => {
                file.sync_all().await?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Format a long name string (like ls -l output)
fn format_longname(filename: &str, metadata: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;

    let file_type = if metadata.is_dir() {
        'd'
    } else if metadata.is_symlink() {
        'l'
    } else {
        '-'
    };

    let mode = metadata.mode();
    let perms = format!(
        "{}{}{}{}{}{}{}{}{}",
        if mode & 0o400 != 0 { 'r' } else { '-' },
        if mode & 0o200 != 0 { 'w' } else { '-' },
        if mode & 0o100 != 0 { 'x' } else { '-' },
        if mode & 0o040 != 0 { 'r' } else { '-' },
        if mode & 0o020 != 0 { 'w' } else { '-' },
        if mode & 0o010 != 0 { 'x' } else { '-' },
        if mode & 0o004 != 0 { 'r' } else { '-' },
        if mode & 0o002 != 0 { 'w' } else { '-' },
        if mode & 0o001 != 0 { 'x' } else { '-' },
    );

    let nlinks = metadata.nlink();
    let uid = metadata.uid();
    let gid = metadata.gid();
    let size = metadata.len();

    // Format modification time
    let mtime = metadata.mtime();
    let datetime = chrono::DateTime::<chrono::Local>::from(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(mtime as u64)
    );
    let time_str = datetime.format("%b %e %H:%M").to_string();

    format!(
        "{}{} {:3} {:8} {:8} {:8} {} {}",
        file_type,
        perms,
        nlinks,
        uid,
        gid,
        size,
        time_str,
        filename
    )
}