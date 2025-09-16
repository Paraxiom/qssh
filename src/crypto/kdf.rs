//! Key derivation functions for QSSH

use crate::{Result, QsshError};
use sha3::{Sha3_256, Digest};
use hkdf::Hkdf;

/// Derive session keys from shared secret
pub struct SessionKeyDerivation;

impl SessionKeyDerivation {
    /// Derive all session keys from master secret
    pub fn derive_keys(
        master_secret: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
    ) -> Result<SessionKeys> {
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(client_random);
        salt.extend_from_slice(server_random);
        
        let hkdf = Hkdf::<Sha3_256>::new(Some(&salt), master_secret);
        
        let mut client_write_key = [0u8; 32];
        let mut server_write_key = [0u8; 32];
        let mut client_write_iv = [0u8; 12];
        let mut server_write_iv = [0u8; 12];
        
        hkdf.expand(b"client write key", &mut client_write_key)
            .map_err(|_| QsshError::Crypto("Key derivation failed".into()))?;
            
        hkdf.expand(b"server write key", &mut server_write_key)
            .map_err(|_| QsshError::Crypto("Key derivation failed".into()))?;
            
        hkdf.expand(b"client write iv", &mut client_write_iv)
            .map_err(|_| QsshError::Crypto("Key derivation failed".into()))?;
            
        hkdf.expand(b"server write iv", &mut server_write_iv)
            .map_err(|_| QsshError::Crypto("Key derivation failed".into()))?;
        
        Ok(SessionKeys {
            client_write_key,
            server_write_key,
            client_write_iv,
            server_write_iv,
        })
    }
    
    /// Mix QKD key with PQC shared secret
    pub fn mix_quantum_classical(qkd_key: &[u8], pqc_secret: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-QUANTUM-MIX-v1");
        
        // XOR for information-theoretic security
        let xor_len = qkd_key.len().min(pqc_secret.len());
        let mut xored = vec![0u8; xor_len];
        for i in 0..xor_len {
            xored[i] = qkd_key[i] ^ pqc_secret[i];
        }
        
        hasher.update(&xored);
        hasher.update(qkd_key);
        hasher.update(pqc_secret);
        
        hasher.finalize().to_vec()
    }
}

pub struct SessionKeys {
    pub client_write_key: [u8; 32],
    pub server_write_key: [u8; 32],
    pub client_write_iv: [u8; 12],
    pub server_write_iv: [u8; 12],
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_derivation() {
        let master_secret = vec![0x42; 32];
        let client_random = [0x01; 32];
        let server_random = [0x02; 32];
        
        let keys = SessionKeyDerivation::derive_keys(
            &master_secret,
            &client_random,
            &server_random
        ).expect("Failed to derive session keys");
        
        // Keys should be different
        assert_ne!(keys.client_write_key, keys.server_write_key);
        assert_ne!(keys.client_write_iv, keys.server_write_iv);
    }
    
    #[test]
    fn test_quantum_mixing() {
        let qkd_key = vec![0xAA; 32];
        let pqc_secret = vec![0x55; 32];
        
        let mixed = SessionKeyDerivation::mix_quantum_classical(&qkd_key, &pqc_secret);
        
        assert_eq!(mixed.len(), 32);
        // Mixed key should be different from inputs
        assert_ne!(&mixed[..], &qkd_key[..32]);
        assert_ne!(&mixed[..], &pqc_secret[..32]);
    }
}