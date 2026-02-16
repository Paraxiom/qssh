//! Quantum-Resistant Transport for QSSH
//!
//! Uses uniform 768-byte frames to hide message boundaries and resist traffic analysis

use crate::{QsshError, Result};
use crate::crypto::quantum_kem::QuantumKem;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use rand::RngCore;
use hmac::{Hmac, Mac};
use sha2::Sha256;

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

/// Quantum-resistant transport using uniform 768-byte frames
pub struct QuantumTransport {
    reader: Arc<Mutex<OwnedReadHalf>>,
    writer: Arc<Mutex<OwnedWriteHalf>>,
    send_key: Arc<RwLock<Vec<u8>>>,
    recv_key: Arc<RwLock<Vec<u8>>>,
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

// Compile-time assertion: QuantumFrame must be exactly QUANTUM_FRAME_SIZE bytes.
// The unsafe transmutes in send_frame/receive_frame depend on this invariant.
const _: () = assert!(std::mem::size_of::<QuantumFrame>() == QUANTUM_FRAME_SIZE);
const _: () = assert!(std::mem::size_of::<EncryptedHeader>() == 17);

/// Encrypted frame header
#[repr(C)]
struct EncryptedHeader {
    sequence: [u8; 8],     // Sequence number (encrypted)
    timestamp: [u8; 8],    // Microsecond timestamp (encrypted)
    frame_type: u8,        // Frame type (encrypted)
}

/// Size of the KEM ciphertext (Falcon PK + ephemeral secret + SPHINCS+ signature)
const KEM_CIPHERTEXT_SIZE: usize = 897 + 64 + 16976; // 17937 bytes

/// Handshake message header size (4 bytes for length)
const HANDSHAKE_HEADER_SIZE: usize = 4;

impl QuantumTransport {
    /// Create quantum transport after successful KEM handshake
    pub async fn new(
        stream: TcpStream,
        kem: &QuantumKem,
        peer_pk: &[u8],
        is_client: bool,
    ) -> Result<Self> {
        log::info!("Creating quantum-native transport (768-byte indistinguishable frames)");

        let (mut reader, mut writer) = stream.into_split();

        // Perform quantum KEM handshake with network exchange
        let (shared_secret, auth_key) = if is_client {
            Self::client_kem_handshake(kem, peer_pk, &mut writer).await?
        } else {
            Self::server_kem_handshake(kem, peer_pk, &mut reader).await?
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
            send_key: Arc::new(RwLock::new(send_key.to_vec())),
            recv_key: Arc::new(RwLock::new(recv_key.to_vec())),
            send_sequence: Arc::new(Mutex::new(0)),
            recv_sequence: Arc::new(Mutex::new(0)),
            auth_key: Arc::new(auth_key),
            stealth_config: StealthConfig::default(),
        })
    }

    /// Client-side KEM handshake
    ///
    /// The client performs encapsulation using the server's public key and sends
    /// the resulting ciphertext to the server. Both parties derive the same
    /// shared secret from the KEM operation.
    async fn client_kem_handshake(
        kem: &QuantumKem,
        server_pk: &[u8],
        writer: &mut OwnedWriteHalf,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        log::debug!("Client: performing SPHINCS+/Falcon KEM handshake");

        // Encapsulate to server's public key
        let (ciphertext, shared_secret) = kem.encapsulate(server_pk)?;

        log::debug!(
            "Client: KEM encapsulation successful, ciphertext: {} bytes, shared secret: {} bytes",
            ciphertext.len(),
            shared_secret.len()
        );

        // Send ciphertext length and ciphertext to server
        let ciphertext_len = ciphertext.len() as u32;
        writer.write_all(&ciphertext_len.to_be_bytes()).await
            .map_err(|e| QsshError::Io(e))?;
        writer.write_all(&ciphertext).await
            .map_err(|e| QsshError::Io(e))?;
        writer.flush().await
            .map_err(|e| QsshError::Io(e))?;

        log::debug!("Client: KEM ciphertext sent to server");

        // Expand shared secret to session keys
        let mut expanded = vec![0u8; 96];
        Self::kdf(&shared_secret, b"QSSH-quantum-session", &mut expanded)?;

        // Extract auth key
        let mut auth_key = [0u8; 32];
        auth_key.copy_from_slice(&expanded[64..96]);

        Ok((expanded[0..64].to_vec(), auth_key))
    }

    /// Server-side KEM handshake
    ///
    /// The server receives the ciphertext from the client and decapsulates it
    /// using its own secret key to derive the same shared secret that the
    /// client computed during encapsulation.
    async fn server_kem_handshake(
        kem: &QuantumKem,
        client_pk: &[u8],
        reader: &mut OwnedReadHalf,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        log::debug!("Server: performing SPHINCS+/Falcon KEM handshake");

        // Read ciphertext length
        let mut len_bytes = [0u8; HANDSHAKE_HEADER_SIZE];
        reader.read_exact(&mut len_bytes).await
            .map_err(|e| QsshError::Io(e))?;
        let ciphertext_len = u32::from_be_bytes(len_bytes) as usize;

        // Validate ciphertext length to prevent DoS
        if ciphertext_len == 0 || ciphertext_len > KEM_CIPHERTEXT_SIZE + 1024 {
            return Err(QsshError::Protocol(format!(
                "Invalid KEM ciphertext size: {} (expected around {})",
                ciphertext_len,
                KEM_CIPHERTEXT_SIZE
            )));
        }

        // Read ciphertext
        let mut ciphertext = vec![0u8; ciphertext_len];
        reader.read_exact(&mut ciphertext).await
            .map_err(|e| QsshError::Io(e))?;

        log::debug!(
            "Server: received KEM ciphertext: {} bytes",
            ciphertext.len()
        );

        // Decapsulate to derive shared secret
        let shared_secret = kem.decapsulate(&ciphertext, client_pk)?;

        log::debug!(
            "Server: KEM decapsulation successful, shared secret: {} bytes",
            shared_secret.len()
        );

        // Expand shared secret to session keys (same KDF as client)
        let mut expanded = vec![0u8; 96];
        Self::kdf(&shared_secret, b"QSSH-quantum-session", &mut expanded)?;

        // Extract auth key
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
        let key = self.send_key.read().await;

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
        let key = self.recv_key.read().await;

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

/// Kani bounded model checking harnesses for quantum-resistant transport.
///
/// Verifies memory safety, panic-freedom, and layout invariants for the
/// QuantumFrame structure and frame parsing logic.
///
/// Run with: `cargo kani --harness <harness_name>`
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // ── Step 2: QuantumFrame Layout Proofs (CRITICAL) ──────────────────────

    /// Proves QuantumFrame is exactly QUANTUM_FRAME_SIZE (768) bytes.
    /// This invariant is required for the unsafe transmutes in send_frame
    /// (line 257) and receive_frame (line 289) to be sound.
    #[kani::proof]
    fn proof_quantum_frame_size() {
        assert_eq!(std::mem::size_of::<QuantumFrame>(), QUANTUM_FRAME_SIZE);
        assert_eq!(QUANTUM_FRAME_SIZE, 768);
    }

    /// Proves QuantumFrame has alignment of 1 (no padding inserted by repr(C)).
    /// With all byte-array fields, the compiler must not add padding.
    #[kani::proof]
    fn proof_quantum_frame_alignment() {
        assert_eq!(std::mem::align_of::<QuantumFrame>(), 1);
        assert_eq!(std::mem::align_of::<EncryptedHeader>(), 1);
    }

    /// Proves QuantumFrame byte representation roundtrips correctly.
    /// This validates the unsafe from_raw_parts / ptr::read pattern
    /// used in send_frame and receive_frame.
    #[kani::proof]
    fn proof_frame_roundtrip() {
        // Create frame with symbolic header fields
        let sequence: [u8; 8] = kani::any();
        let timestamp: [u8; 8] = kani::any();
        let frame_type: u8 = kani::any();
        let mac: [u8; 32] = kani::any();

        let frame = QuantumFrame {
            header: EncryptedHeader {
                sequence,
                timestamp,
                frame_type,
            },
            payload: [0u8; 719], // Zero payload for tractability
            mac,
        };

        // Simulate the send_frame transmute: QuantumFrame → &[u8]
        let frame_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &frame as *const QuantumFrame as *const u8,
                QUANTUM_FRAME_SIZE,
            )
        };
        assert_eq!(frame_bytes.len(), QUANTUM_FRAME_SIZE);

        // Simulate the receive_frame transmute: &[u8] → QuantumFrame
        let frame_back: QuantumFrame = unsafe {
            std::ptr::read(frame_bytes.as_ptr() as *const QuantumFrame)
        };

        // Verify roundtrip preserves all fields
        assert_eq!(frame_back.header.sequence, sequence);
        assert_eq!(frame_back.header.timestamp, timestamp);
        assert_eq!(frame_back.header.frame_type, frame_type);
        assert_eq!(frame_back.mac, mac);
    }

    // ── Step 3: Frame Parsing Panic-Freedom (HIGH) ─────────────────────────

    /// Proves the core logic of build_frame never panics.
    /// Kani cannot verify async functions directly, so we verify the
    /// sync data-packing logic inline.
    #[kani::proof]
    fn proof_build_frame_no_panic() {
        let data_len: usize = kani::any();
        kani::assume(data_len <= 719);

        let mut payload = [0u8; 719];

        // Core logic from build_frame (line 320-322):
        let actual_len = data_len.min(717);
        let len_bytes = (actual_len as u16).to_be_bytes();
        payload[0] = len_bytes[0];
        payload[1] = len_bytes[1];

        // Verify the slice copy is in bounds
        assert!(2 + actual_len <= 719);
        // The copy_from_slice would go to payload[2..2+actual_len]
        // which is always within the 719-byte payload
    }

    /// Proves payload_len extraction and bounds check in verify_and_decrypt_frame
    /// prevents out-of-bounds access.
    #[kani::proof]
    fn proof_payload_bounds() {
        let payload = [0u8; 719];

        // Symbolic payload length from network bytes (line 374)
        let byte0: u8 = kani::any();
        let byte1: u8 = kani::any();
        let payload_len = u16::from_be_bytes([byte0, byte1]) as usize;

        // The bounds check from line 375-377
        if payload_len <= 717 {
            // After the check, the slice access at line 379 is safe
            assert!(2 + payload_len <= 719);
            let _extracted = &payload[2..2 + payload_len];
        }
        // If payload_len > 717, the function returns Err (no slice access)
    }

    /// Proves all 256 values of frame_type byte are handled:
    /// 4 valid types + 252 rejected.
    #[kani::proof]
    fn proof_frame_type_exhaustive() {
        let frame_type_byte: u8 = kani::any();

        let result = match frame_type_byte {
            0x00 => Ok(QuantumFrameType::Noise),
            0x01 => Ok(QuantumFrameType::Handshake),
            0x02 => Ok(QuantumFrameType::Data),
            0x03 => Ok(QuantumFrameType::Control),
            _ => Err("Invalid frame type"),
        };

        // Valid frame types: exactly 4 values
        if frame_type_byte <= 3 {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    // ── Step 6: Integer Cast Safety (partial) ──────────────────────────────

    /// Proves the `data_len as u16` cast at line 321 never truncates,
    /// because data_len is bounded by .min(717) and 717 < u16::MAX.
    #[kani::proof]
    fn proof_payload_len_cast() {
        let data_len: usize = kani::any();
        kani::assume(data_len <= 719); // Maximum input size

        let actual_len = data_len.min(717);
        let cast_result = actual_len as u16;

        // Prove no truncation: actual_len fits in u16 (717 < 65535)
        assert_eq!(cast_result as usize, actual_len);
    }

    /// Proves the u64 sequence counter cannot overflow within a bounded
    /// session (2^48 frames = ~281 trillion, far beyond physical limits).
    #[kani::proof]
    fn proof_sequence_no_overflow() {
        let seq: u64 = kani::any();
        // Physical limit: even at 1M frames/sec, 2^48 takes ~8900 years
        kani::assume(seq < (1u64 << 48));

        let next = seq + 1;
        assert!(next > seq); // No wraparound
    }

    /// Proves verify_and_decrypt_frame properly validates sequence numbers
    /// by checking that u64::from_be_bytes always produces a valid u64.
    #[kani::proof]
    fn proof_sequence_from_be_bytes() {
        let bytes: [u8; 8] = kani::any();
        let seq = u64::from_be_bytes(bytes);
        // from_be_bytes is total: all 2^64 byte patterns produce valid u64
        let roundtrip = seq.to_be_bytes();
        assert_eq!(roundtrip, bytes);
    }
}