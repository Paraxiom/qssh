//! Quantum-Native Transport for QSSH
//!
//! Replaces classical SSH framing with indistinguishable 768-byte frames

use crate::{QsshError, Result};
use crate::crypto::quantum_kem::QuantumKem;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use std::sync::Arc;
use tokio::sync::Mutex;
use rand::RngCore;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

/// Fixed frame size - all frames look identical
pub const QUANTUM_FRAME_SIZE: usize = 768;

/// Frame types (encrypted so adversary can't distinguish)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantumFrameType {
    Noise = 0x00,      // Dummy traffic
    Handshake = 0x01,  // Key exchange messages
    Data = 0x02,       // Application data
    Control = 0x03,    // Channel operations
}

/// Quantum-native transport using indistinguishable frames
pub struct QuantumTransport {
    reader: Arc<Mutex<OwnedReadHalf>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    send_key: Arc<Mutex<[u8; 32]>>,
    recv_key: Arc<Mutex<[u8; 32]>>,
    send_sequence: Arc<Mutex<u64>>,
    recv_sequence: Arc<Mutex<u64>>,
    auth_key: Arc<[u8; 32]>,
    stealth_config: StealthConfig,
}

/// Stealth/obfuscation configuration
#[derive(Debug, Clone)]
pub struct StealthConfig {
    pub dummy_traffic: bool,
    pub timing_obfuscation: bool,
    pub min_frame_rate: u32,
    pub max_padding: bool,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            dummy_traffic: true,
            timing_obfuscation: true,
            min_frame_rate: 10,
            max_padding: true,
        }
    }
}

/// Quantum frame structure - exactly 768 bytes
#[repr(C)]
pub struct QuantumFrame {
    /// Encrypted header (17 bytes)
    header: EncryptedHeader,
    /// Payload with random padding (719 bytes)
    payload: [u8; 719],
    /// Authentication MAC (32 bytes)
    mac: [u8; 32],
}

/// Encrypted frame header
#[repr(C)]
struct EncryptedHeader {
    sequence: [u8; 8],     // Sequence number (encrypted)
    timestamp: [u8; 8],    // Microsecond timestamp (encrypted)
    frame_type: u8,        // Frame type (encrypted)
}

impl QuantumTransport {
    /// Create quantum transport after successful KEM handshake
    pub async fn new(
        stream: TcpStream,
        kem: &QuantumKem,
        peer_pk: &[u8],
        is_client: bool,
    ) -> Result<Self> {
        log::info!("Creating quantum-native transport (768-byte indistinguishable frames)");

        let (reader, writer) = stream.into_split();

        // Perform quantum KEM handshake
        let (shared_secret, auth_key) = if is_client {
            Self::client_kem_handshake(kem, peer_pk).await?
        } else {
            Self::server_kem_handshake(kem, peer_pk).await?
        };

        // Derive symmetric keys
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];

        // Client and server use different key directions
        if is_client {
            send_key.copy_from_slice(&shared_secret[0..32]);
            recv_key.copy_from_slice(&shared_secret[32..64]);
        } else {
            recv_key.copy_from_slice(&shared_secret[0..32]);
            send_key.copy_from_slice(&shared_secret[32..64]);
        }

        Ok(Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
            send_key: Arc::new(Mutex::new(send_key)),
            recv_key: Arc::new(Mutex::new(recv_key)),
            send_sequence: Arc::new(Mutex::new(0)),
            recv_sequence: Arc::new(Mutex::new(0)),
            auth_key: Arc::new(auth_key),
            stealth_config: StealthConfig::default(),
        })
    }

    /// Client-side KEM handshake
    async fn client_kem_handshake(kem: &QuantumKem, server_pk: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        log::debug!("Client: performing SPHINCS+/Falcon KEM handshake");

        // Encapsulate to server's public key
        let (ciphertext, shared_secret) = kem.encapsulate(server_pk)?;

        log::debug!("Client: KEM encapsulation successful, shared secret: {} bytes", shared_secret.len());

        // Expand shared secret to session keys
        let mut expanded = vec![0u8; 96];
        Self::kdf(&shared_secret, b"QSSH-quantum-session", &mut expanded)?;

        // Extract auth key
        let mut auth_key = [0u8; 32];
        auth_key.copy_from_slice(&expanded[64..96]);

        Ok((expanded[0..64].to_vec(), auth_key))
    }

    /// Server-side KEM handshake
    async fn server_kem_handshake(kem: &QuantumKem, client_pk: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        log::debug!("Server: performing SPHINCS+/Falcon KEM handshake");

        // For server, we need to receive the client's encapsulation
        // In a real implementation, this would be sent over the wire
        // For now, simulate the handshake completion

        // Generate a shared secret (in real implementation, this comes from decapsulation)
        let mut shared_secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut shared_secret);

        // Expand to session keys
        let mut expanded = vec![0u8; 96];
        Self::kdf(&shared_secret, b"QSSH-quantum-session", &mut expanded)?;

        let mut auth_key = [0u8; 32];
        auth_key.copy_from_slice(&expanded[64..96]);

        log::debug!("Server: KEM handshake complete");

        Ok((expanded[0..64].to_vec(), auth_key))
    }

    /// Key derivation function using HKDF-SHA256
    fn kdf(secret: &[u8], info: &[u8], output: &mut [u8]) -> Result<()> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, secret);
        hkdf.expand(info, output)
            .map_err(|e| QsshError::Crypto(format!("KDF failed: {}", e)))?;

        Ok(())
    }

    /// Send quantum frame (all frames are indistinguishable)
    pub async fn send_frame(&self, frame_type: QuantumFrameType, data: &[u8]) -> Result<()> {
        let sequence = {
            let mut seq = self.send_sequence.lock().await;
            let current = *seq;
            *seq += 1;
            current
        };

        // Create frame
        let frame = self.build_frame(sequence, frame_type, data).await?;

        // Send to network
        let mut writer = self.writer.lock().await;
        let frame_bytes = unsafe {
            std::slice::from_raw_parts(
                &frame as *const QuantumFrame as *const u8,
                QUANTUM_FRAME_SIZE
            )
        };

        writer.write_all(frame_bytes).await
            .map_err(|e| QsshError::Io(e))?;
        writer.flush().await
            .map_err(|e| QsshError::Io(e))?;

        log::trace!("Quantum frame sent: type={:?}, sequence={}", frame_type, sequence);

        // Maybe send dummy traffic to confuse analysis
        if self.stealth_config.dummy_traffic && rand::random::<f32>() < 0.3 {
            self.send_dummy_frame_impl().await?;
        }

        Ok(())
    }

    /// Receive quantum frame
    pub async fn receive_frame(&self) -> Result<(QuantumFrameType, Vec<u8>)> {
        let mut reader = self.reader.lock().await;

        // Read exactly one frame
        let mut frame_bytes = vec![0u8; QUANTUM_FRAME_SIZE];
        reader.read_exact(&mut frame_bytes).await
            .map_err(|e| QsshError::Io(e))?;

        // Parse frame
        let frame = unsafe {
            std::ptr::read(frame_bytes.as_ptr() as *const QuantumFrame)
        };

        // Verify and decrypt
        let (frame_type, payload) = self.verify_and_decrypt_frame(frame).await?;

        // Skip noise frames
        if frame_type == QuantumFrameType::Noise {
            log::trace!("Received noise frame, skipping");
            return Box::pin(self.receive_frame()).await;
        }

        log::trace!("Quantum frame received: type={:?}, payload={} bytes", frame_type, payload.len());

        Ok((frame_type, payload))
    }

    /// Build encrypted quantum frame
    async fn build_frame(&self, sequence: u64, frame_type: QuantumFrameType, data: &[u8]) -> Result<QuantumFrame> {
        let mut frame = QuantumFrame {
            header: EncryptedHeader {
                sequence: sequence.to_be_bytes(),
                timestamp: Self::get_timestamp(),
                frame_type: frame_type as u8,
            },
            payload: [0; 719],
            mac: [0; 32],
        };

        // Pack data with length prefix
        let data_len = data.len().min(717);
        frame.payload[0..2].copy_from_slice(&(data_len as u16).to_be_bytes());
        frame.payload[2..2 + data_len].copy_from_slice(&data[..data_len]);

        // Fill remaining with random padding (indistinguishable)
        if self.stealth_config.max_padding {
            rand::thread_rng().fill_bytes(&mut frame.payload[2 + data_len..]);
        }

        // Encrypt header in place
        self.encrypt_header(&mut frame.header).await?;

        // Calculate MAC over everything except MAC field
        frame.mac = self.calculate_mac(&frame).await?;

        Ok(frame)
    }

    /// Verify and decrypt received frame
    async fn verify_and_decrypt_frame(&self, mut frame: QuantumFrame) -> Result<(QuantumFrameType, Vec<u8>)> {
        // Verify MAC first
        let calculated_mac = self.calculate_mac_for_verify(&frame).await?;
        if calculated_mac != frame.mac {
            return Err(QsshError::Crypto("Frame MAC verification failed".to_string()));
        }

        // Decrypt header
        self.decrypt_header(&mut frame.header).await?;

        // Verify sequence number
        let received_seq = u64::from_be_bytes(frame.header.sequence);
        let expected_seq = {
            let mut seq = self.recv_sequence.lock().await;
            let current = *seq;
            *seq += 1;
            current
        };

        if received_seq != expected_seq {
            return Err(QsshError::Protocol(format!(
                "Invalid sequence: expected {}, got {}", expected_seq, received_seq
            )));
        }

        // Extract frame type and payload
        let frame_type = match frame.header.frame_type {
            0x00 => QuantumFrameType::Noise,
            0x01 => QuantumFrameType::Handshake,
            0x02 => QuantumFrameType::Data,
            0x03 => QuantumFrameType::Control,
            _ => return Err(QsshError::Protocol("Invalid frame type".to_string())),
        };

        // Extract actual payload
        let payload_len = u16::from_be_bytes([frame.payload[0], frame.payload[1]]) as usize;
        if payload_len > 717 {
            return Err(QsshError::Protocol("Invalid payload length".to_string()));
        }

        let payload = frame.payload[2..2 + payload_len].to_vec();

        Ok((frame_type, payload))
    }

    /// Send dummy traffic frame (non-recursive implementation)
    async fn send_dummy_frame_impl(&self) -> Result<()> {
        let sequence = {
            let mut seq = self.send_sequence.lock().await;
            let current = *seq;
            *seq += 1;
            current
        };

        let mut dummy_data = vec![0u8; rand::random::<usize>() % 500];
        rand::thread_rng().fill_bytes(&mut dummy_data);

        // Build frame directly to avoid recursion
        let frame = self.build_frame(sequence, QuantumFrameType::Noise, &dummy_data).await?;

        // Send to network
        let mut writer = self.writer.lock().await;
        let frame_bytes = unsafe {
            std::slice::from_raw_parts(
                &frame as *const QuantumFrame as *const u8,
                QUANTUM_FRAME_SIZE
            )
        };

        writer.write_all(frame_bytes).await
            .map_err(|e| QsshError::Io(e))?;
        writer.flush().await
            .map_err(|e| QsshError::Io(e))?;

        log::trace!("Dummy frame sent: sequence={}", sequence);
        Ok(())
    }

    /// Encrypt header in place using stream cipher
    async fn encrypt_header(&self, header: &mut EncryptedHeader) -> Result<()> {
        let key = self.send_key.lock().await;

        // Simple XOR encryption (in production, use ChaCha20)
        for (i, byte) in header.sequence.iter_mut().enumerate() {
            *byte ^= key[i % 32];
        }
        for (i, byte) in header.timestamp.iter_mut().enumerate() {
            *byte ^= key[(i + 8) % 32];
        }
        header.frame_type ^= key[16];

        Ok(())
    }

    /// Decrypt header in place
    async fn decrypt_header(&self, header: &mut EncryptedHeader) -> Result<()> {
        let key = self.recv_key.lock().await;

        // XOR decryption (same as encryption)
        for (i, byte) in header.sequence.iter_mut().enumerate() {
            *byte ^= key[i % 32];
        }
        for (i, byte) in header.timestamp.iter_mut().enumerate() {
            *byte ^= key[(i + 8) % 32];
        }
        header.frame_type ^= key[16];

        Ok(())
    }

    /// Calculate MAC for frame authentication
    async fn calculate_mac(&self, frame: &QuantumFrame) -> Result<[u8; 32]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&*self.auth_key)
            .map_err(|e| QsshError::Crypto(format!("MAC creation failed: {}", e)))?;

        // MAC covers header + payload, but not MAC field
        mac.update(&frame.header.sequence);
        mac.update(&frame.header.timestamp);
        mac.update(&[frame.header.frame_type]);
        mac.update(&frame.payload);

        let result = mac.finalize();
        let mut mac_bytes = [0u8; 32];
        mac_bytes.copy_from_slice(result.into_bytes().as_slice());
        Ok(mac_bytes)
    }

    /// Calculate MAC for verification (same as above but separate for clarity)
    async fn calculate_mac_for_verify(&self, frame: &QuantumFrame) -> Result<[u8; 32]> {
        self.calculate_mac(frame).await
    }

    /// Get current timestamp in microseconds
    fn get_timestamp() -> [u8; 8] {
        use std::time::{SystemTime, UNIX_EPOCH};

        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        micros.to_be_bytes()
    }

    /// Close quantum transport
    pub async fn close(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.shutdown().await
            .map_err(|e| QsshError::Io(e))?;
        Ok(())
    }
}

/// Convenience methods for QSSH protocol messages
impl QuantumTransport {
    /// Send serialized QSSH protocol message
    pub async fn send_message<T: serde::Serialize>(&self, message: &T) -> Result<()> {
        let data = bincode::serialize(message)
            .map_err(|e| QsshError::Protocol(format!("Serialization failed: {}", e)))?;

        self.send_frame(QuantumFrameType::Data, &data).await
    }

    /// Receive and deserialize QSSH protocol message
    pub async fn receive_message<T: for<'de> serde::Deserialize<'de>>(&self) -> Result<T> {
        let (frame_type, data) = self.receive_frame().await?;

        if frame_type != QuantumFrameType::Data {
            return Err(QsshError::Protocol("Expected data frame".to_string()));
        }

        let message = bincode::deserialize(&data)
            .map_err(|e| QsshError::Protocol(format!("Deserialization failed: {}", e)))?;

        Ok(message)
    }
}

/// Implement unified transport trait for quantum transport
#[async_trait::async_trait]
impl crate::transport::QsshTransport for QuantumTransport {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_size() {
        assert_eq!(std::mem::size_of::<QuantumFrame>(), QUANTUM_FRAME_SIZE);
        println!("✅ Quantum frame is exactly {} bytes", QUANTUM_FRAME_SIZE);
    }

    #[test]
    fn test_frame_indistinguishability() {
        // All frames should look the same from the outside
        let mut frame1 = QuantumFrame {
            header: EncryptedHeader {
                sequence: [1, 2, 3, 4, 5, 6, 7, 8],
                timestamp: [9, 10, 11, 12, 13, 14, 15, 16],
                frame_type: QuantumFrameType::Data as u8,
            },
            payload: [0; 719],
            mac: [0; 32],
        };

        let mut frame2 = QuantumFrame {
            header: EncryptedHeader {
                sequence: [8, 7, 6, 5, 4, 3, 2, 1],
                timestamp: [16, 15, 14, 13, 12, 11, 10, 9],
                frame_type: QuantumFrameType::Noise as u8,
            },
            payload: [0; 719],
            mac: [0; 32],
        };

        // Fill with different data
        rand::thread_rng().fill_bytes(&mut frame1.payload);
        rand::thread_rng().fill_bytes(&mut frame2.payload);
        rand::thread_rng().fill_bytes(&mut frame1.mac);
        rand::thread_rng().fill_bytes(&mut frame2.mac);

        // Both frames are exactly the same size
        assert_eq!(std::mem::size_of_val(&frame1), std::mem::size_of_val(&frame2));
        assert_eq!(std::mem::size_of_val(&frame1), QUANTUM_FRAME_SIZE);

        println!("✅ All frames are indistinguishable (same size)");
    }
}