// SFTP Protocol Messages (Version 3)
// Based on draft-ietf-secsh-filexfer-02.txt

use std::io::{Read, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

// SFTP message types
#[derive(Debug, Clone)]
pub enum SftpMessage {
    // Client -> Server
    Init { version: u32 },
    Open(OpenMessage),
    Close { id: u32, handle: String },
    Read(ReadMessage),
    Write(WriteMessage),
    Remove { id: u32, filename: String },
    Rename { id: u32, oldpath: String, newpath: String },
    Mkdir { id: u32, path: String, attrs: FileAttributes },
    Rmdir { id: u32, path: String },
    OpenDir(OpenDirMessage),
    ReadDir(ReadDirMessage),
    Stat(StatMessage),
    LStat { id: u32, path: String },
    FStat { id: u32, handle: String },
    SetStat { id: u32, path: String, attrs: FileAttributes },
    SetFStat { id: u32, handle: String, attrs: FileAttributes },
    RealPath(RealPathMessage),
    Symlink { id: u32, linkpath: String, targetpath: String },
    ReadLink { id: u32, path: String },

    // Server -> Client
    Version { version: u32, extensions: Vec<(String, String)> },
    Status { id: u32, code: StatusCode, message: String, language: String },
    Handle { id: u32, handle: String },
    Data { id: u32, data: Vec<u8> },
    Name { id: u32, files: Vec<FileInfo> },
    Attrs { id: u32, attrs: FileAttributes },
}

// Message type constants
const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_FSTAT: u8 = 8;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_FSETSTAT: u8 = 10;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_READLINK: u8 = 19;
const SSH_FXP_SYMLINK: u8 = 20;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;

// Open flags
#[derive(Debug, Clone)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub create: bool,
    pub truncate: bool,
    pub exclusive: bool,
}

impl OpenFlags {
    pub fn from_u32(flags: u32) -> Self {
        OpenFlags {
            read: (flags & 0x00000001) != 0,
            write: (flags & 0x00000002) != 0,
            append: (flags & 0x00000004) != 0,
            create: (flags & 0x00000008) != 0,
            truncate: (flags & 0x00000010) != 0,
            exclusive: (flags & 0x00000020) != 0,
        }
    }
}

// Status codes
#[derive(Debug, Clone, Copy)]
pub enum StatusCode {
    Ok = 0,
    Eof = 1,
    NoSuchFile = 2,
    PermissionDenied = 3,
    Failure = 4,
    BadMessage = 5,
    NoConnection = 6,
    ConnectionLost = 7,
    OpUnsupported = 8,
}

// File attributes
#[derive(Debug, Clone, Default)]
pub struct FileAttributes {
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
}

impl FileAttributes {
    pub fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        FileAttributes {
            size: Some(metadata.len()),
            uid: Some(metadata.uid()),
            gid: Some(metadata.gid()),
            permissions: Some(metadata.mode()),
            atime: Some(metadata.atime() as u32),
            mtime: Some(metadata.mtime() as u32),
        }
    }

    fn from_bytes(data: &[u8]) -> Result<(Self, usize), Box<dyn std::error::Error + Send + Sync>> {
        let mut cursor = std::io::Cursor::new(data);
        let flags = cursor.read_u32::<BigEndian>()?;
        let mut attrs = FileAttributes::default();
        let mut bytes_read = 4;

        if (flags & 0x00000001) != 0 {
            attrs.size = Some(cursor.read_u64::<BigEndian>()?);
            bytes_read += 8;
        }
        if (flags & 0x00000002) != 0 {
            attrs.uid = Some(cursor.read_u32::<BigEndian>()?);
            attrs.gid = Some(cursor.read_u32::<BigEndian>()?);
            bytes_read += 8;
        }
        if (flags & 0x00000004) != 0 {
            attrs.permissions = Some(cursor.read_u32::<BigEndian>()?);
            bytes_read += 4;
        }
        if (flags & 0x00000008) != 0 {
            attrs.atime = Some(cursor.read_u32::<BigEndian>()?);
            attrs.mtime = Some(cursor.read_u32::<BigEndian>()?);
            bytes_read += 8;
        }

        Ok((attrs, bytes_read))
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut flags = 0u32;

        if self.size.is_some() { flags |= 0x00000001; }
        if self.uid.is_some() { flags |= 0x00000002; }
        if self.permissions.is_some() { flags |= 0x00000004; }
        if self.atime.is_some() { flags |= 0x00000008; }

        buf.write_u32::<BigEndian>(flags).unwrap();

        if let Some(size) = self.size {
            buf.write_u64::<BigEndian>(size).unwrap();
        }
        if let Some(uid) = self.uid {
            buf.write_u32::<BigEndian>(uid).unwrap();
            buf.write_u32::<BigEndian>(self.gid.unwrap_or(0)).unwrap();
        }
        if let Some(perms) = self.permissions {
            buf.write_u32::<BigEndian>(perms).unwrap();
        }
        if let Some(atime) = self.atime {
            buf.write_u32::<BigEndian>(atime).unwrap();
            buf.write_u32::<BigEndian>(self.mtime.unwrap_or(atime)).unwrap();
        }

        buf
    }
}

// File information
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub filename: String,
    pub longname: String,
    pub attrs: FileAttributes,
}

// Message structures
#[derive(Debug, Clone)]
pub struct OpenMessage {
    pub id: u32,
    pub filename: String,
    pub flags: OpenFlags,
    pub attrs: FileAttributes,
}

#[derive(Debug, Clone)]
pub struct ReadMessage {
    pub id: u32,
    pub handle: String,
    pub offset: u64,
    pub length: u32,
}

#[derive(Debug, Clone)]
pub struct WriteMessage {
    pub id: u32,
    pub handle: String,
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OpenDirMessage {
    pub id: u32,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct ReadDirMessage {
    pub id: u32,
    pub handle: String,
}

#[derive(Debug, Clone)]
pub struct StatMessage {
    pub id: u32,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct RealPathMessage {
    pub id: u32,
    pub path: String,
}

impl SftpMessage {
    pub fn from_bytes(data: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if data.len() < 5 {
            return Err("Message too short".into());
        }

        let mut cursor = std::io::Cursor::new(data);
        let length = cursor.read_u32::<BigEndian>()? as usize;
        let msg_type = cursor.read_u8()?;

        match msg_type {
            SSH_FXP_INIT => {
                let version = cursor.read_u32::<BigEndian>()?;
                Ok(SftpMessage::Init { version })
            }
            SSH_FXP_OPEN => {
                let id = cursor.read_u32::<BigEndian>()?;
                let filename = read_string(&mut cursor)?;
                let flags = cursor.read_u32::<BigEndian>()?;
                let attrs_data = &data[cursor.position() as usize..];
                let (attrs, _) = FileAttributes::from_bytes(attrs_data)?;

                Ok(SftpMessage::Open(OpenMessage {
                    id,
                    filename,
                    flags: OpenFlags::from_u32(flags),
                    attrs,
                }))
            }
            SSH_FXP_CLOSE => {
                let id = cursor.read_u32::<BigEndian>()?;
                let handle = read_string(&mut cursor)?;
                Ok(SftpMessage::Close { id, handle })
            }
            SSH_FXP_READ => {
                let id = cursor.read_u32::<BigEndian>()?;
                let handle = read_string(&mut cursor)?;
                let offset = cursor.read_u64::<BigEndian>()?;
                let length = cursor.read_u32::<BigEndian>()?;
                Ok(SftpMessage::Read(ReadMessage {
                    id,
                    handle,
                    offset,
                    length,
                }))
            }
            SSH_FXP_WRITE => {
                let id = cursor.read_u32::<BigEndian>()?;
                let handle = read_string(&mut cursor)?;
                let offset = cursor.read_u64::<BigEndian>()?;
                let data = read_data(&mut cursor)?;
                Ok(SftpMessage::Write(WriteMessage {
                    id,
                    handle,
                    offset,
                    data,
                }))
            }
            SSH_FXP_OPENDIR => {
                let id = cursor.read_u32::<BigEndian>()?;
                let path = read_string(&mut cursor)?;
                Ok(SftpMessage::OpenDir(OpenDirMessage { id, path }))
            }
            SSH_FXP_READDIR => {
                let id = cursor.read_u32::<BigEndian>()?;
                let handle = read_string(&mut cursor)?;
                Ok(SftpMessage::ReadDir(ReadDirMessage { id, handle }))
            }
            SSH_FXP_STAT => {
                let id = cursor.read_u32::<BigEndian>()?;
                let path = read_string(&mut cursor)?;
                Ok(SftpMessage::Stat(StatMessage { id, path }))
            }
            SSH_FXP_REALPATH => {
                let id = cursor.read_u32::<BigEndian>()?;
                let path = read_string(&mut cursor)?;
                Ok(SftpMessage::RealPath(RealPathMessage { id, path }))
            }
            _ => Err(format!("Unknown message type: {}", msg_type).into()),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(0)?; // Placeholder for length

        match self {
            SftpMessage::Version { version, extensions } => {
                buf.write_u8(SSH_FXP_VERSION)?;
                buf.write_u32::<BigEndian>(*version)?;
                // Extensions not implemented yet
            }
            SftpMessage::Status { id, code, message, language } => {
                buf.write_u8(SSH_FXP_STATUS)?;
                buf.write_u32::<BigEndian>(*id)?;
                buf.write_u32::<BigEndian>(*code as u32)?;
                write_string(&mut buf, message)?;
                write_string(&mut buf, language)?;
            }
            SftpMessage::Handle { id, handle } => {
                buf.write_u8(SSH_FXP_HANDLE)?;
                buf.write_u32::<BigEndian>(*id)?;
                write_string(&mut buf, handle)?;
            }
            SftpMessage::Data { id, data } => {
                buf.write_u8(SSH_FXP_DATA)?;
                buf.write_u32::<BigEndian>(*id)?;
                write_data(&mut buf, data)?;
            }
            SftpMessage::Name { id, files } => {
                buf.write_u8(SSH_FXP_NAME)?;
                buf.write_u32::<BigEndian>(*id)?;
                buf.write_u32::<BigEndian>(files.len() as u32)?;
                for file in files {
                    write_string(&mut buf, &file.filename)?;
                    write_string(&mut buf, &file.longname)?;
                    buf.extend(file.attrs.to_bytes());
                }
            }
            SftpMessage::Attrs { id, attrs } => {
                buf.write_u8(SSH_FXP_ATTRS)?;
                buf.write_u32::<BigEndian>(*id)?;
                buf.extend(attrs.to_bytes());
            }
            _ => return Err("Message serialization not implemented".into()),
        }

        // Update length
        let len = (buf.len() - 4) as u32;
        buf[0..4].copy_from_slice(&len.to_be_bytes());

        Ok(buf)
    }
}

// Helper functions
fn read_string(cursor: &mut std::io::Cursor<&[u8]>) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let len = cursor.read_u32::<BigEndian>()? as usize;
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf)?;
    Ok(String::from_utf8(buf)?)
}

fn write_string(buf: &mut Vec<u8>, s: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    buf.write_u32::<BigEndian>(s.len() as u32)?;
    buf.write_all(s.as_bytes())?;
    Ok(())
}

fn read_data(cursor: &mut std::io::Cursor<&[u8]>) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let len = cursor.read_u32::<BigEndian>()? as usize;
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_data(buf: &mut Vec<u8>, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    buf.write_u32::<BigEndian>(data.len() as u32)?;
    buf.write_all(data)?;
    Ok(())
}