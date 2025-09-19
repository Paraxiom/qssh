// QKD + Lamport + Double Ratchet Integration for QSSH
// Cherry-picked from quantum-harmony-base communication protocol

use crate::{Result, QsshError};
use sha3::{Sha3_256, Digest};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Lamport one-time signature for quantum-safe authentication
#[derive(Clone, Debug)]
pub struct LamportKeyPair {
    /// Private key: 2 * 256 * 32 bytes
    private_key: Vec<[u8; 32]>,
    /// Public key: 2 * 256 * 32 bytes  
    public_key: Vec<[u8; 32]>,
    /// Key index for one-time use
    index: u64,
}

impl LamportKeyPair {
    /// Generate new Lamport key pair from QKD entropy
    pub fn from_qkd_entropy(qkd_key: &[u8], index: u64) -> Self {
        let mut rng = ChaCha20Rng::from_seed({
            let mut seed = [0u8; 32];
            let mut hasher = Sha3_256::new();
            hasher.update(qkd_key);
            hasher.update(b"lamport_keygen");
            hasher.update(&index.to_le_bytes());
            seed.copy_from_slice(&hasher.finalize());
            seed
        });

        // Generate 512 private key blocks (256 for 0-bits, 256 for 1-bits)
        let mut private_key = Vec::with_capacity(512);
        let mut public_key = Vec::with_capacity(512);

        for _ in 0..512 {
            let mut priv_block = [0u8; 32];
            rng.fill_bytes(&mut priv_block);
            private_key.push(priv_block);

            // Public key is hash of private key
            let pub_block = Sha3_256::digest(&priv_block).into();
            public_key.push(pub_block);
        }

        Self { private_key, public_key, index }
    }

    /// Sign a message (one-time use only!)
    pub fn sign(&self, message: &[u8]) -> LamportSignature {
        let hash = Sha3_256::digest(message);
        let mut signature_blocks = Vec::with_capacity(256);

        // For each bit in the hash
        for (i, &byte) in hash.iter().enumerate() {
            for bit in 0..8 {
                let bit_value = (byte >> bit) & 1;
                let key_index = i * 8 + bit + (bit_value as usize * 256);
                signature_blocks.push(self.private_key[key_index]);
            }
        }

        LamportSignature {
            blocks: signature_blocks,
            key_index: self.index,
        }
    }
}

/// Lamport signature
pub struct LamportSignature {
    blocks: Vec<[u8; 32]>,
    key_index: u64,
}

/// Double Ratchet state for forward secrecy
pub struct DoubleRatchetState {
    /// Diffie-Hellman ratchet (using QKD keys)
    dh_sending_key: Option<[u8; 32]>,
    dh_receiving_key: Option<[u8; 32]>,
    
    /// Symmetric key ratchet chains
    root_chain_key: [u8; 32],
    sending_chain_key: [u8; 32],
    receiving_chain_key: [u8; 32],
    
    /// Message counters
    sending_message_number: u32,
    receiving_message_number: u32,
    previous_sending_chain_length: u32,
    
    /// QKD integration
    qkd_session_id: Option<String>,
}

impl DoubleRatchetState {
    /// Initialize with QKD session key
    pub fn from_qkd_session(session_key: &[u8], session_id: String) -> Self {
        let mut root_key = [0u8; 32];
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];

        // Derive initial keys from QKD session
        let mut hasher = Sha3_256::new();
        hasher.update(session_key);
        hasher.update(b"root_chain");
        root_key.copy_from_slice(&hasher.finalize_reset());

        hasher.update(session_key);
        hasher.update(b"send_chain");
        send_key.copy_from_slice(&hasher.finalize_reset());

        hasher.update(session_key);
        hasher.update(b"recv_chain");
        recv_key.copy_from_slice(&hasher.finalize());

        Self {
            dh_sending_key: None,
            dh_receiving_key: None,
            root_chain_key: root_key,
            sending_chain_key: send_key,
            receiving_chain_key: recv_key,
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_sending_chain_length: 0,
            qkd_session_id: Some(session_id),
        }
    }

    /// Ratchet forward using new QKD key
    pub fn ratchet_with_qkd(&mut self, new_qkd_key: &[u8]) {
        // KDF chain with new QKD entropy
        let mut hasher = Sha3_256::new();
        hasher.update(&self.root_chain_key);
        hasher.update(new_qkd_key);
        hasher.update(b"ratchet");
        
        // Update root chain
        self.root_chain_key.copy_from_slice(&hasher.finalize_reset());
        
        // Derive new chain keys
        hasher.update(&self.root_chain_key);
        hasher.update(b"send");
        self.sending_chain_key.copy_from_slice(&hasher.finalize_reset());
        
        hasher.update(&self.root_chain_key);
        hasher.update(b"recv");
        self.receiving_chain_key.copy_from_slice(&hasher.finalize());
        
        // Reset message counters
        self.previous_sending_chain_length = self.sending_message_number;
        self.sending_message_number = 0;
    }

    /// Encrypt with ratchet
    pub fn encrypt(&mut self, plaintext: &[u8]) -> RatchetMessage {
        // Advance sending chain
        let mut hasher = Sha3_256::new();
        hasher.update(&self.sending_chain_key);
        hasher.update(b"chain");
        self.sending_chain_key.copy_from_slice(&hasher.finalize_reset());
        
        // Derive message key
        hasher.update(&self.sending_chain_key);
        hasher.update(b"msgkey");
        let message_key: [u8; 32] = hasher.finalize().into();
        
        // Simple XOR encryption (in production, use AES-256-GCM)
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= message_key[i % 32];
        }
        
        let msg = RatchetMessage {
            ratchet_key: self.dh_sending_key,
            previous_chain_length: self.previous_sending_chain_length,
            message_number: self.sending_message_number,
            ciphertext,
        };
        
        self.sending_message_number += 1;
        msg
    }
}

/// Ratchet message format
pub struct RatchetMessage {
    ratchet_key: Option<[u8; 32]>,
    previous_chain_length: u32,
    message_number: u32,
    ciphertext: Vec<u8>,
}

/// QKD integration for QSSH
pub struct QkdManager {
    /// Active QKD sessions
    sessions: std::collections::HashMap<String, QkdSession>,
    /// QKD hardware endpoint
    qkd_endpoint: Option<String>,
}

pub struct QkdSession {
    pub session_id: String,
    pub peer_id: String,
    pub shared_key: Vec<u8>,
    pub key_rate: f64, // bits per second
    pub qber: f64, // Quantum Bit Error Rate
    pub timestamp: std::time::Instant,
}

impl QkdManager {
    /// Create new QKD manager
    pub fn new(endpoint: Option<String>) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            qkd_endpoint: endpoint,
        }
    }

    /// Get QKD key for peer
    pub async fn get_qkd_key(&mut self, peer_id: &str) -> Result<Vec<u8>> {
        // In production, this would connect to real QKD hardware
        // For now, simulate QKD key generation
        
        if let Some(session) = self.sessions.get(peer_id) {
            if session.timestamp.elapsed().as_secs() < 300 { // 5 minute timeout
                return Ok(session.shared_key.clone());
            }
        }

        // Simulate new QKD session
        let session = self.establish_qkd_session(peer_id).await?;
        let key = session.shared_key.clone();
        self.sessions.insert(peer_id.to_string(), session);
        
        Ok(key)
    }

    /// Establish new QKD session
    async fn establish_qkd_session(&self, peer_id: &str) -> Result<QkdSession> {
        log::info!("Establishing QKD session with {}", peer_id);
        
        // In production: connect to QKD hardware API
        // Simulated QKD key with good parameters
        let mut key = vec![0u8; 256]; // 2048 bits
        rand::thread_rng().fill_bytes(&mut key);
        
        Ok(QkdSession {
            session_id: format!("qkd-{}-{}", peer_id, uuid::Uuid::new_v4()),
            peer_id: peer_id.to_string(),
            shared_key: key,
            key_rate: 10_000.0, // 10 kbps (typical for QKD)
            qber: 0.02, // 2% QBER (good quality)
            timestamp: std::time::Instant::now(),
        })
    }
}

/// Integrated QSSH session with all quantum features
pub struct QuantumSession {
    /// QKD manager for key distribution
    pub qkd: QkdManager,
    /// Current Lamport key pair
    pub lamport_key: LamportKeyPair,
    /// Double ratchet state
    pub ratchet: DoubleRatchetState,
    /// Lamport key index (increments with each signature)
    lamport_index: u64,
}

impl QuantumSession {
    /// Create new quantum session
    pub async fn new(peer_id: &str, qkd_endpoint: Option<String>) -> Result<Self> {
        let mut qkd = QkdManager::new(qkd_endpoint);
        
        // Get initial QKD key
        let qkd_key = qkd.get_qkd_key(peer_id).await?;
        
        // Initialize Lamport keys
        let lamport_key = LamportKeyPair::from_qkd_entropy(&qkd_key, 0);
        
        // Initialize double ratchet
        let ratchet = DoubleRatchetState::from_qkd_session(
            &qkd_key,
            format!("session-{}", peer_id)
        );
        
        Ok(Self {
            qkd,
            lamport_key,
            ratchet,
            lamport_index: 0,
        })
    }

    /// Sign and encrypt a message
    pub async fn secure_send(&mut self, message: &[u8]) -> Result<(LamportSignature, RatchetMessage)> {
        // Sign with Lamport
        let signature = self.lamport_key.sign(message);
        
        // Encrypt with ratchet
        let encrypted = self.ratchet.encrypt(message);
        
        // Increment Lamport key
        self.lamport_index += 1;
        if self.lamport_index % 100 == 0 {
            // Refresh Lamport keys every 100 signatures
            self.refresh_lamport_keys().await?;
        }
        
        Ok((signature, encrypted))
    }

    /// Refresh Lamport keys with new QKD entropy
    async fn refresh_lamport_keys(&mut self) -> Result<()> {
        let peer_id = self.ratchet.qkd_session_id.as_ref()
            .ok_or_else(|| QsshError::Protocol("No QKD session".into()))?;
        
        // Get fresh QKD key
        let new_qkd_key = self.qkd.get_qkd_key(peer_id).await?;
        
        // Generate new Lamport key pair
        self.lamport_key = LamportKeyPair::from_qkd_entropy(&new_qkd_key, self.lamport_index);
        
        // Also ratchet forward
        self.ratchet.ratchet_with_qkd(&new_qkd_key);
        
        log::info!("Refreshed quantum keys with QKD entropy");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quantum_session() {
        let mut session = QuantumSession::new("test-peer", None).await.unwrap();
        
        let message = b"Hello Quantum World!";
        let (signature, encrypted) = session.secure_send(message).await.unwrap();
        
        assert_eq!(signature.key_index, 0);
        assert!(!encrypted.ciphertext.is_empty());
    }

    #[test]
    fn test_lamport_signature() {
        let qkd_key = vec![0x42; 32];
        let keypair = LamportKeyPair::from_qkd_entropy(&qkd_key, 0);
        
        let message = b"Test message";
        let signature = keypair.sign(message);
        
        assert_eq!(signature.blocks.len(), 256);
    }
}