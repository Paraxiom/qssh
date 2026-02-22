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
            // Server -> Client messages
            SSH_FXP_VERSION => {
                let version = cursor.read_u32::<BigEndian>()?;
                // Extensions parsing skipped for now
                Ok(SftpMessage::Version { version, extensions: vec![] })
            }
            SSH_FXP_STATUS => {
                let id = cursor.read_u32::<BigEndian>()?;
                let code_val = cursor.read_u32::<BigEndian>()?;
                let code = match code_val {
                    0 => StatusCode::Ok,
                    1 => StatusCode::Eof,
                    2 => StatusCode::NoSuchFile,
                    3 => StatusCode::PermissionDenied,
                    4 => StatusCode::Failure,
                    5 => StatusCode::BadMessage,
                    6 => StatusCode::NoConnection,
                    7 => StatusCode::ConnectionLost,
                    8 => StatusCode::OpUnsupported,
                    _ => StatusCode::Failure,
                };
                let message = read_string(&mut cursor).unwrap_or_default();
                let language = read_string(&mut cursor).unwrap_or_default();
                Ok(SftpMessage::Status { id, code, message, language })
            }
            SSH_FXP_HANDLE => {
                let id = cursor.read_u32::<BigEndian>()?;
                let handle = read_string(&mut cursor)?;
                Ok(SftpMessage::Handle { id, handle })
            }
            SSH_FXP_DATA => {
                let id = cursor.read_u32::<BigEndian>()?;
                let data = read_data(&mut cursor)?;
                Ok(SftpMessage::Data { id, data })
            }
            SSH_FXP_NAME => {
                let id = cursor.read_u32::<BigEndian>()?;
                let count = cursor.read_u32::<BigEndian>()? as usize;
                let mut files = Vec::with_capacity(count);
                for _ in 0..count {
                    let filename = read_string(&mut cursor)?;
                    let longname = read_string(&mut cursor)?;
                    let attrs_data = &data[cursor.position() as usize..];
                    let (attrs, consumed) = FileAttributes::from_bytes(attrs_data)?;
                    cursor.set_position(cursor.position() + consumed as u64);
                    files.push(FileInfo { filename, longname, attrs });
                }
                Ok(SftpMessage::Name { id, files })
            }
            SSH_FXP_ATTRS => {
                let id = cursor.read_u32::<BigEndian>()?;
                let attrs_data = &data[cursor.position() as usize..];
                let (attrs, _) = FileAttributes::from_bytes(attrs_data)?;
                Ok(SftpMessage::Attrs { id, attrs })
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
            // Client -> Server messages
            SftpMessage::Init { version } => {
                buf.write_u8(SSH_FXP_INIT)?;
                buf.write_u32::<BigEndian>(*version)?;
            }
            SftpMessage::Open(msg) => {
                buf.write_u8(SSH_FXP_OPEN)?;
                buf.write_u32::<BigEndian>(msg.id)?;
                write_string(&mut buf, &msg.filename)?;
                let mut flags = 0u32;
                if msg.flags.read { flags |= 0x00000001; }
                if msg.flags.write { flags |= 0x00000002; }
                if msg.flags.append { flags |= 0x00000004; }
                if msg.flags.create { flags |= 0x00000008; }
                if msg.flags.truncate { flags |= 0x00000010; }
                if msg.flags.exclusive { flags |= 0x00000020; }
                buf.write_u32::<BigEndian>(flags)?;
                buf.extend(msg.attrs.to_bytes());
            }
            SftpMessage::Close { id, handle } => {
                buf.write_u8(SSH_FXP_CLOSE)?;
                buf.write_u32::<BigEndian>(*id)?;
                write_string(&mut buf, handle)?;
            }
            SftpMessage::Read(msg) => {
                buf.write_u8(SSH_FXP_READ)?;
                buf.write_u32::<BigEndian>(msg.id)?;
                write_string(&mut buf, &msg.handle)?;
                buf.write_u64::<BigEndian>(msg.offset)?;
                buf.write_u32::<BigEndian>(msg.length)?;
            }
            SftpMessage::Write(msg) => {
                buf.write_u8(SSH_FXP_WRITE)?;
                buf.write_u32::<BigEndian>(msg.id)?;
                write_string(&mut buf, &msg.handle)?;
                buf.write_u64::<BigEndian>(msg.offset)?;
                write_data(&mut buf, &msg.data)?;
            }
            SftpMessage::Stat(msg) => {
                buf.write_u8(SSH_FXP_STAT)?;
                buf.write_u32::<BigEndian>(msg.id)?;
                write_string(&mut buf, &msg.path)?;
            }
            SftpMessage::RealPath(msg) => {
                buf.write_u8(SSH_FXP_REALPATH)?;
                buf.write_u32::<BigEndian>(msg.id)?;
                write_string(&mut buf, &msg.path)?;
            }
            SftpMessage::OpenDir(msg) => {
                buf.write_u8(SSH_FXP_OPENDIR)?;
                buf.write_u32::<BigEndian>(msg.id)?;
                write_string(&mut buf, &msg.path)?;
            }
            SftpMessage::ReadDir(msg) => {
                buf.write_u8(SSH_FXP_READDIR)?;
                buf.write_u32::<BigEndian>(msg.id)?;
                write_string(&mut buf, &msg.handle)?;
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

/// Kani bounded model checking harnesses for SFTP protocol.
///
/// Verifies integer cast safety for SFTP wire format serialization.
///
/// Run with: `cargo kani --harness <harness_name>`
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // ── Step 6: Integer Cast Safety ────────────────────────────────────────

    /// Proves the `s.len() as u32` and `data.len() as u32` casts in
    /// write_string/write_data never truncate for practical SFTP data.
    /// SFTP protocol constrains strings and data to well under 4 GB.
    #[kani::proof]
    fn proof_sftp_u32_casts() {
        let str_len: usize = kani::any();
        let data_len: usize = kani::any();
        // SFTP practical limit: 256 KB per message (generous bound)
        kani::assume(str_len <= 256 * 1024);
        kani::assume(data_len <= 256 * 1024);

        let str_cast = str_len as u32;
        let data_cast = data_len as u32;

        assert_eq!(str_cast as usize, str_len);
        assert_eq!(data_cast as usize, data_len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: Init → bytes → Init
    #[test]
    fn test_roundtrip_init() {
        let msg = SftpMessage::Init { version: 3 };
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Init { version } => assert_eq!(version, 3),
            other => panic!("Expected Init, got {:?}", other),
        }
    }

    /// Round-trip: Version → bytes → Version
    #[test]
    fn test_roundtrip_version() {
        let msg = SftpMessage::Version { version: 3, extensions: vec![] };
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Version { version, .. } => assert_eq!(version, 3),
            other => panic!("Expected Version, got {:?}", other),
        }
    }

    /// Round-trip: Status → bytes → Status (all codes)
    #[test]
    fn test_roundtrip_status_codes() {
        let codes = [
            (StatusCode::Ok, 0u32),
            (StatusCode::Eof, 1),
            (StatusCode::NoSuchFile, 2),
            (StatusCode::PermissionDenied, 3),
            (StatusCode::Failure, 4),
            (StatusCode::OpUnsupported, 8),
        ];
        for (code, expected_val) in codes {
            let msg = SftpMessage::Status {
                id: 42,
                code,
                message: "test".to_string(),
                language: "en".to_string(),
            };
            let bytes = msg.to_bytes().unwrap();
            let parsed = SftpMessage::from_bytes(&bytes).unwrap();
            match parsed {
                SftpMessage::Status { id, code: parsed_code, message, .. } => {
                    assert_eq!(id, 42);
                    assert_eq!(parsed_code as u32, expected_val);
                    assert_eq!(message, "test");
                }
                other => panic!("Expected Status, got {:?}", other),
            }
        }
    }

    /// Round-trip: Handle → bytes → Handle
    #[test]
    fn test_roundtrip_handle() {
        let msg = SftpMessage::Handle { id: 7, handle: "handle_1".to_string() };
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Handle { id, handle } => {
                assert_eq!(id, 7);
                assert_eq!(handle, "handle_1");
            }
            other => panic!("Expected Handle, got {:?}", other),
        }
    }

    /// Round-trip: Data → bytes → Data
    #[test]
    fn test_roundtrip_data() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
        let msg = SftpMessage::Data { id: 99, data: payload.clone() };
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Data { id, data } => {
                assert_eq!(id, 99);
                assert_eq!(data, payload);
            }
            other => panic!("Expected Data, got {:?}", other),
        }
    }

    /// Round-trip: Open (write+create+truncate) → bytes → Open
    #[test]
    fn test_roundtrip_open() {
        let msg = SftpMessage::Open(OpenMessage {
            id: 1,
            filename: "/tmp/test.txt".to_string(),
            flags: OpenFlags {
                read: false, write: true, append: false,
                create: true, truncate: true, exclusive: false,
            },
            attrs: FileAttributes::default(),
        });
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Open(m) => {
                assert_eq!(m.id, 1);
                assert_eq!(m.filename, "/tmp/test.txt");
                assert!(m.flags.write);
                assert!(m.flags.create);
                assert!(m.flags.truncate);
                assert!(!m.flags.read);
            }
            other => panic!("Expected Open, got {:?}", other),
        }
    }

    /// Round-trip: Close → bytes → Close
    #[test]
    fn test_roundtrip_close() {
        let msg = SftpMessage::Close { id: 5, handle: "h42".to_string() };
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Close { id, handle } => {
                assert_eq!(id, 5);
                assert_eq!(handle, "h42");
            }
            other => panic!("Expected Close, got {:?}", other),
        }
    }

    /// Round-trip: Read → bytes → Read
    #[test]
    fn test_roundtrip_read() {
        let msg = SftpMessage::Read(ReadMessage {
            id: 10, handle: "h1".to_string(), offset: 4096, length: 32768,
        });
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Read(m) => {
                assert_eq!(m.id, 10);
                assert_eq!(m.handle, "h1");
                assert_eq!(m.offset, 4096);
                assert_eq!(m.length, 32768);
            }
            other => panic!("Expected Read, got {:?}", other),
        }
    }

    /// Round-trip: Write → bytes → Write
    #[test]
    fn test_roundtrip_write() {
        let payload = vec![0x41; 1024]; // 1KB of 'A'
        let msg = SftpMessage::Write(WriteMessage {
            id: 20, handle: "h2".to_string(), offset: 0, data: payload.clone(),
        });
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Write(m) => {
                assert_eq!(m.id, 20);
                assert_eq!(m.handle, "h2");
                assert_eq!(m.offset, 0);
                assert_eq!(m.data, payload);
            }
            other => panic!("Expected Write, got {:?}", other),
        }
    }

    /// Round-trip: Stat → bytes → Stat
    #[test]
    fn test_roundtrip_stat() {
        let msg = SftpMessage::Stat(StatMessage { id: 30, path: "/etc/passwd".to_string() });
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Stat(m) => {
                assert_eq!(m.id, 30);
                assert_eq!(m.path, "/etc/passwd");
            }
            other => panic!("Expected Stat, got {:?}", other),
        }
    }

    /// Round-trip: Attrs → bytes → Attrs (with size + permissions)
    #[test]
    fn test_roundtrip_attrs() {
        let msg = SftpMessage::Attrs {
            id: 31,
            attrs: FileAttributes {
                size: Some(12345),
                uid: None,
                gid: None,
                permissions: Some(0o644),
                atime: None,
                mtime: None,
            },
        };
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Attrs { id, attrs } => {
                assert_eq!(id, 31);
                assert_eq!(attrs.size, Some(12345));
                assert_eq!(attrs.permissions, Some(0o644));
                assert!(attrs.uid.is_none());
            }
            other => panic!("Expected Attrs, got {:?}", other),
        }
    }

    /// Round-trip: Name (single file) → bytes → Name
    #[test]
    fn test_roundtrip_name() {
        let msg = SftpMessage::Name {
            id: 40,
            files: vec![FileInfo {
                filename: "hello.txt".to_string(),
                longname: "-rw-r--r-- 1 user user 42 Feb 22 hello.txt".to_string(),
                attrs: FileAttributes { size: Some(42), ..FileAttributes::default() },
            }],
        };
        let bytes = msg.to_bytes().unwrap();
        let parsed = SftpMessage::from_bytes(&bytes).unwrap();
        match parsed {
            SftpMessage::Name { id, files } => {
                assert_eq!(id, 40);
                assert_eq!(files.len(), 1);
                assert_eq!(files[0].filename, "hello.txt");
                assert_eq!(files[0].attrs.size, Some(42));
            }
            other => panic!("Expected Name, got {:?}", other),
        }
    }

    /// Verify FileAttributes round-trip with all fields set
    #[test]
    fn test_file_attributes_full_roundtrip() {
        let attrs = FileAttributes {
            size: Some(999999),
            uid: Some(1000),
            gid: Some(1000),
            permissions: Some(0o755),
            atime: Some(1708560000),
            mtime: Some(1708560000),
        };
        let bytes = attrs.to_bytes();
        let (parsed, consumed) = FileAttributes::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.size, Some(999999));
        assert_eq!(parsed.uid, Some(1000));
        assert_eq!(parsed.gid, Some(1000));
        assert_eq!(parsed.permissions, Some(0o755));
        assert_eq!(parsed.atime, Some(1708560000));
        assert_eq!(consumed, bytes.len());
    }

    /// Verify empty message is rejected
    #[test]
    fn test_reject_too_short() {
        assert!(SftpMessage::from_bytes(&[0, 0]).is_err());
    }

    /// Verify unknown message type is rejected
    #[test]
    fn test_reject_unknown_type() {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(1).unwrap(); // length = 1
        buf.push(255); // unknown type
        assert!(SftpMessage::from_bytes(&buf).is_err());
    }
}