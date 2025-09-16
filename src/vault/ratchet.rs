//! Double Ratchet implementation for QSSH
//! 
//! Based on Signal's Double Ratchet algorithm with quantum-safe modifications

use sha3::{Sha3_256, Digest};
use crate::{Result, QsshError};
use zeroize::Zeroize;

/// Double Ratchet state for continuous key derivation
pub struct DoubleRatchet {
    /// Root key for chain derivation
    root_key: [u8; 32],
    /// Sending chain key
    chain_key_send: [u8; 32],
    /// Receiving chain key
    chain_key_recv: [u8; 32],
    /// Message number for sending
    message_number_send: u64,
    /// Message number for receiving
    message_number_recv: u64,
    /// Previous chain key (for out-of-order messages)
    prev_chain_key: Option<[u8; 32]>,
}

impl DoubleRatchet {
    /// Create new double ratchet from root key
    pub fn new(root_key: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-RATCHET-ROOT");
        hasher.update(root_key);
        let mut root = [0u8; 32];
        root.copy_from_slice(&hasher.finalize());
        
        // Derive initial chain keys
        let chain_key_send = Self::kdf(&root, b"QSSH-CHAIN-SEND");
        let chain_key_recv = Self::kdf(&root, b"QSSH-CHAIN-RECV");
        
        Self {
            root_key: root,
            chain_key_send,
            chain_key_recv,
            message_number_send: 0,
            message_number_recv: 0,
            prev_chain_key: None,
        }
    }
    
    /// Perform Diffie-Hellman ratchet step with new key material
    pub fn dh_ratchet(&mut self, shared_secret: &[u8]) {
        // Save previous chain key for out-of-order messages
        self.prev_chain_key = Some(self.chain_key_recv);
        
        // Derive new root key
        let (new_root, new_recv_chain) = self.kdf_chain(&self.root_key, shared_secret);
        self.root_key = new_root;
        self.chain_key_recv = new_recv_chain;
        
        // Reset receive counter
        self.message_number_recv = 0;
        
        // Derive new sending chain
        let (new_root2, new_send_chain) = self.kdf_chain(&self.root_key, b"QSSH-SEND-RATCHET");
        self.root_key = new_root2;
        self.chain_key_send = new_send_chain;
        self.message_number_send = 0;
    }
    
    /// Get next encryption key
    pub fn next_send_key(&mut self) -> [u8; 32] {
        let (new_chain, message_key) = self.chain_step(&self.chain_key_send);
        self.chain_key_send = new_chain;
        self.message_number_send += 1;
        message_key
    }
    
    /// Get next decryption key
    pub fn next_recv_key(&mut self) -> [u8; 32] {
        let (new_chain, message_key) = self.chain_step(&self.chain_key_recv);
        self.chain_key_recv = new_chain;
        self.message_number_recv += 1;
        message_key
    }
    
    /// Get next key (for symmetric usage)
    pub fn next_key(&mut self) -> [u8; 32] {
        // For symmetric usage, advance both chains
        let send_key = self.next_send_key();
        let recv_key = self.next_recv_key();
        
        // XOR for combined key
        let mut combined = [0u8; 32];
        for i in 0..32 {
            combined[i] = send_key[i] ^ recv_key[i];
        }
        
        combined
    }
    
    /// Skip keys for out-of-order message handling
    pub fn skip_keys(&mut self, until: u64) -> Result<()> {
        if until > self.message_number_recv + 1000 {
            return Err(QsshError::Crypto("Too many keys to skip".into()));
        }
        
        while self.message_number_recv < until {
            let _ = self.next_recv_key();
        }
        
        Ok(())
    }
    
    /// Chain step: derive next chain key and message key
    fn chain_step(&self, chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let message_key = Self::kdf(chain_key, b"QSSH-MESSAGE-KEY");
        let next_chain = Self::kdf(chain_key, b"QSSH-CHAIN-KEY");
        (next_chain, message_key)
    }
    
    /// KDF for chain derivation (returns two keys)
    fn kdf_chain(&self, root: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-KDF-CHAIN");
        hasher.update(root);
        hasher.update(input);
        
        let output = hasher.finalize();
        
        // Expand to two keys
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        
        let mut hasher1 = Sha3_256::new();
        hasher1.update(&output);
        hasher1.update(&[0x01]);
        key1.copy_from_slice(&hasher1.finalize());
        
        let mut hasher2 = Sha3_256::new();
        hasher2.update(&output);
        hasher2.update(&[0x02]);
        key2.copy_from_slice(&hasher2.finalize());
        
        (key1, key2)
    }
    
    /// Simple KDF for single key derivation
    fn kdf(key: &[u8], label: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(label);
        hasher.update(key);
        let mut output = [0u8; 32];
        output.copy_from_slice(&hasher.finalize());
        output
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.chain_key_send.zeroize();
        self.chain_key_recv.zeroize();
        if let Some(ref mut key) = self.prev_chain_key {
            key.zeroize();
        }
    }
}

/// Ratchet header for key exchange coordination
#[derive(Clone, Debug)]
pub struct RatchetHeader {
    /// Ephemeral public key (Falcon or QKD key ID)
    pub ephemeral_key: Vec<u8>,
    /// Previous chain message number
    pub prev_chain_len: u32,
    /// Current message number
    pub message_number: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ratchet_basic() {
        let mut ratchet = DoubleRatchet::new(b"test-root-key");
        
        // Generate some keys
        let key1 = ratchet.next_key();
        let key2 = ratchet.next_key();
        let key3 = ratchet.next_key();
        
        // Keys should be different
        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_ne!(key1, key3);
    }
    
    #[test]
    fn test_dh_ratchet() {
        let mut ratchet = DoubleRatchet::new(b"test-root-key");
        
        let key_before = ratchet.next_send_key();
        
        // Perform DH ratchet with new shared secret
        ratchet.dh_ratchet(b"new-shared-secret");
        
        let key_after = ratchet.next_send_key();
        
        // Keys should be completely different after ratchet
        assert_ne!(key_before, key_after);
    }
}