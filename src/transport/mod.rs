//! Quantum-secure transport layer

use crate::{QsshError, Result, crypto::SymmetricCrypto};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use serde::{Serialize, Deserialize};
use bincode;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod protocol;
pub mod channel;
pub mod quantum_resistant;

pub use protocol::*;
pub use channel::*;
pub use quantum_resistant::*;

/// Unified transport trait for both classical and quantum-resistant transports
#[async_trait::async_trait]
pub trait QsshTransport: Send + Sync {
    /// Send a message
    async fn send_message<T: serde::Serialize + Send + Sync>(&self, message: &T) -> Result<()>;

    /// Receive a message
    async fn receive_message<T: for<'de> serde::Deserialize<'de>>(&self) -> Result<T>;

    /// Close the transport
    async fn close(&self) -> Result<()>;
}

/// Maximum message size (1MB)
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Transport layer for encrypted communication
#[derive(Clone)]
pub struct Transport {
    reader: Arc<Mutex<OwnedReadHalf>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    send_crypto: Arc<SymmetricCrypto>,
    recv_crypto: Arc<SymmetricCrypto>,
    send_sequence: Arc<Mutex<u64>>,
    recv_sequence: Arc<Mutex<u64>>,
}

impl Transport {
    /// Create new transport from established TCP connection (unidirectional - for backwards compatibility)
    pub fn new(stream: TcpStream, crypto: SymmetricCrypto) -> Self {
        let (reader, writer) = stream.into_split();
        let crypto_arc = Arc::new(crypto);
        Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            send_crypto: crypto_arc.clone(),
            recv_crypto: crypto_arc,
            send_sequence: Arc::new(Mutex::new(0)),
            recv_sequence: Arc::new(Mutex::new(0)),
        }
    }
    
    /// Create new transport with separate send and receive crypto
    pub fn new_bidirectional(stream: TcpStream, send_crypto: SymmetricCrypto, recv_crypto: SymmetricCrypto) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            send_crypto: Arc::new(send_crypto),
            recv_crypto: Arc::new(recv_crypto),
            send_sequence: Arc::new(Mutex::new(0)),
            recv_sequence: Arc::new(Mutex::new(0)),
        }
    }
    
    /// Send an encrypted message
    pub async fn send_message<T: Serialize>(&self, message: &T) -> Result<()> {
        log::trace!("Transport: sending message");
        // Serialize message
        let plaintext = bincode::serialize(message)
            .map_err(|e| QsshError::Protocol(format!("Serialization failed: {}", e)))?;
        
        if plaintext.len() > MAX_MESSAGE_SIZE {
            return Err(QsshError::Protocol("Message too large".into()));
        }
        
        // Get sequence number
        let seq = {
            let mut seq_lock = self.send_sequence.lock().await;
            let current = *seq_lock;
            *seq_lock += 1;
            current
        };
        
        // Add sequence number to prevent replay attacks
        let mut authenticated_data = Vec::new();
        authenticated_data.extend_from_slice(&seq.to_be_bytes());
        authenticated_data.extend_from_slice(&plaintext);
        
        // Encrypt
        let (ciphertext, nonce) = self.send_crypto.encrypt(&authenticated_data)?;
        
        // Frame format: [4 bytes length][12 bytes nonce][ciphertext]
        let frame_length = (nonce.len() + ciphertext.len()) as u32;
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_length.to_be_bytes());
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&ciphertext);
        
        // Send
        let mut writer = self.writer.lock().await;
        log::trace!("Transport: writing {} bytes to stream", frame.len());
        writer.write_all(&frame).await
            .map_err(|e| {
                log::error!("Transport: failed to write to stream: {}", e);
                QsshError::Io(e)
            })?;
        writer.flush().await
            .map_err(|e| {
                log::error!("Transport: failed to flush stream: {}", e);
                QsshError::Io(e)
            })?;
        log::trace!("Transport: message sent successfully");
        
        Ok(())
    }
    
    /// Receive and decrypt a message
    pub async fn receive_message<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        let mut reader = self.reader.lock().await;
        
        // Read frame length
        let mut length_bytes = [0u8; 4];
        log::trace!("Transport: attempting to read 4 bytes for frame length");
        reader.read_exact(&mut length_bytes).await
            .map_err(|e| {
                log::error!("Transport: failed to read frame length: {}", e);
                QsshError::Io(e)
            })?;
        let frame_length = u32::from_be_bytes(length_bytes) as usize;
        
        if frame_length > MAX_MESSAGE_SIZE {
            return Err(QsshError::Protocol("Frame too large".into()));
        }
        
        // Read nonce and ciphertext
        let mut frame = vec![0u8; frame_length];
        reader.read_exact(&mut frame).await
            .map_err(|e| QsshError::Io(e))?;
        
        let (nonce, ciphertext) = frame.split_at(12);
        
        // Decrypt
        let authenticated_data = self.recv_crypto.decrypt(ciphertext, nonce)?;
        
        // Verify sequence number
        if authenticated_data.len() < 8 {
            return Err(QsshError::Protocol("Invalid message format".into()));
        }
        
        let (seq_bytes, plaintext) = authenticated_data.split_at(8);
        let received_seq = u64::from_be_bytes(
            seq_bytes.try_into()
                .map_err(|_| QsshError::Protocol("Invalid sequence number format".into()))?
        );
        
        // Check and update sequence number
        let expected_seq = {
            let mut seq_lock = self.recv_sequence.lock().await;
            let current = *seq_lock;
            *seq_lock += 1;
            current
        };
        
        if received_seq != expected_seq {
            return Err(QsshError::Protocol(format!("Invalid sequence number: expected {}, got {}", expected_seq, received_seq)));
        }
        
        // Deserialize
        let message = bincode::deserialize(plaintext)
            .map_err(|e| QsshError::Protocol(format!("Deserialization failed: {}", e)))?;
        
        Ok(message)
    }
    
    /// Close the transport
    pub async fn close(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.shutdown().await
            .map_err(|e| QsshError::Io(e))?;
        Ok(())
    }
}

/// Implement unified transport trait for classical transport
#[async_trait::async_trait]
impl QsshTransport for Transport {
    async fn send_message<T: serde::Serialize + Send + Sync>(&self, message: &T) -> Result<()> {
        self.send_message(message).await
    }

    async fn receive_message<T: for<'de> serde::Deserialize<'de>>(&self) -> Result<T> {
        self.receive_message().await
    }

    async fn close(&self) -> Result<()> {
        self.close().await
    }
}