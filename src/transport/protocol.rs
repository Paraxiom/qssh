//! QSSH protocol messages

use serde::{Serialize, Deserialize};
use crate::{PqAlgorithm, KexAlgorithm};

/// QSSH protocol version
pub const PROTOCOL_VERSION: (u8, u8) = (0, 1);

/// Protocol messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Version exchange
    Version(VersionMessage),
    
    /// Client hello
    ClientHello(ClientHelloMessage),
    
    /// Server hello
    ServerHello(ServerHelloMessage),
    
    /// Key exchange
    KeyExchange(KeyExchangeMessage),
    
    /// Authentication
    Auth(AuthMessage),
    
    /// Channel operations
    Channel(ChannelMessage),
    
    /// Disconnect
    Disconnect(DisconnectMessage),
    
    /// Keepalive
    Ping(u64),
    Pong(u64),
    
    /// Key rotation
    Rekey(RekeyMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMessage {
    pub version: (u8, u8),
    pub software: String,
    pub comments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHelloMessage {
    pub version: (u8, u8),
    pub random: [u8; 32],
    /// Supported key exchange algorithms (ordered by preference)
    pub kex_algorithms: Vec<KexAlgorithm>,
    pub sig_algorithms: Vec<PqAlgorithm>,
    pub ciphers: Vec<String>,
    pub qkd_capable: bool,
    pub extensions: Vec<Extension>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHelloMessage {
    pub version: (u8, u8),
    pub random: [u8; 32],
    /// Selected key exchange algorithm
    pub selected_kex: KexAlgorithm,
    pub selected_sig: PqAlgorithm,
    pub selected_cipher: String,
    /// Falcon public key (used for FalconSignedShares KEX)
    pub falcon_public_key: Vec<u8>,
    /// Key share for FalconSignedShares KEX
    pub key_share: Vec<u8>,
    /// Signature over key_share (for FalconSignedShares)
    pub key_share_signature: Vec<u8>,
    /// ML-KEM encapsulation key (used for MlKem768/MlKem1024 KEX)
    #[serde(default)]
    pub mlkem_encapsulation_key: Option<Vec<u8>>,
    /// X25519 public key (used for Hybrid KEX)
    #[serde(default)]
    pub x25519_public_key: Option<Vec<u8>>,
    pub qkd_endpoint: Option<String>,
    pub extensions: Vec<Extension>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeMessage {
    /// Falcon public key (for FalconSignedShares KEX)
    pub falcon_public_key: Vec<u8>,
    /// Key share for FalconSignedShares KEX
    pub key_share: Vec<u8>,
    /// Signature over key_share (for FalconSignedShares)
    pub key_share_signature: Vec<u8>,
    pub sphincs_public_key: Vec<u8>,
    /// ML-KEM ciphertext (used for MlKem768/MlKem1024 KEX)
    #[serde(default)]
    pub mlkem_ciphertext: Option<Vec<u8>>,
    /// X25519 public key from client (used for Hybrid KEX)
    #[serde(default)]
    pub x25519_public_key: Option<Vec<u8>>,
    pub qkd_proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMessage {
    pub username: String,
    pub auth_method: AuthMethod,
    pub signature: Vec<u8>,
    pub session_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    PublicKey {
        algorithm: PqAlgorithm,
        public_key: Vec<u8>,
    },
    Password {
        password_hash: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelMessage {
    Open {
        channel_id: u32,
        channel_type: ChannelType,
        window_size: u32,
        max_packet_size: u32,
    },
    Accept {
        channel_id: u32,
        sender_channel: u32,
        window_size: u32,
        max_packet_size: u32,
    },
    Data {
        channel_id: u32,
        data: Vec<u8>,
    },
    WindowAdjust {
        channel_id: u32,
        bytes_to_add: u32,
    },
    Close {
        channel_id: u32,
    },
    Eof {
        channel_id: u32,
    },
    PtyRequest {
        channel_id: u32,
        term: String,
        width_chars: u32,
        height_chars: u32,
        width_pixels: u32,
        height_pixels: u32,
        modes: Vec<u8>,
    },
    ShellRequest {
        channel_id: u32,
    },
    ForwardRequest {
        channel_id: u32,
        remote_host: String,
        remote_port: u16,
    },
    ExecRequest {
        channel_id: u32,
        command: String,
    },
    X11Request {
        channel_id: u32,
        single_connection: bool,
        auth_protocol: String,
        auth_cookie: String,
        screen_number: u32,
    },
    SubsystemRequest {
        channel_id: u32,
        subsystem: String,
    },
    WindowChange {
        channel_id: u32,
        width_chars: u32,
        height_chars: u32,
        width_pixels: u32,
        height_pixels: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelType {
    Session,
    DirectTcpIp,
    ForwardedTcpIp,
    X11,
    DirectTcpip {
        host: String,
        port: u16,
        originator_host: String,
        originator_port: u16,
    },
    ForwardedTcpip {
        connected_host: String,
        connected_port: u16,
        originator_host: String,
        originator_port: u16,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectMessage {
    pub reason_code: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyMessage {
    pub new_falcon_public_key: Vec<u8>,
    pub new_key_share: Vec<u8>,
    pub new_key_share_signature: Vec<u8>,
    pub request_qkd: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Extension {
    MaxPacketSize(u32),
    NoDelay(bool),
    QkdRequired(bool),
    Custom(String, Vec<u8>),
}

/// Disconnect reason codes
pub mod disconnect_reasons {
    pub const PROTOCOL_ERROR: u32 = 1;
    pub const KEY_EXCHANGE_FAILED: u32 = 2;
    pub const AUTHENTICATION_FAILED: u32 = 3;
    pub const CONNECTION_LOST: u32 = 4;
    pub const BY_APPLICATION: u32 = 5;
    pub const TOO_MANY_CONNECTIONS: u32 = 6;
    pub const REKEY_REQUIRED: u32 = 7;
}