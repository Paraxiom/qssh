//! Hybrid X25519 + ML-KEM-768 key exchange
//!
//! Provides defense-in-depth by combining classical (X25519) and post-quantum
//! (ML-KEM-768) key exchange. The shared secrets from both algorithms are
//! combined using SHA3-256 to produce the final shared secret.
//!
//! This approach ensures that:
//! - If X25519 is broken by quantum computers, ML-KEM provides security
//! - If ML-KEM has an undiscovered vulnerability, X25519 provides security
//!
//! ## Protocol Flow
//! 1. Server generates X25519 + ML-KEM-768 keypairs, sends public keys
//! 2. Client generates X25519 keypair, performs X25519 DH
//! 3. Client encapsulates against server's ML-KEM public key
//! 4. Client sends X25519 public key + ML-KEM ciphertext
//! 5. Both parties combine X25519 shared secret + ML-KEM shared secret

use crate::{QsshError, Result};
use crate::crypto::mlkem::{MlKem768KeyPair, mlkem768_encapsulate, mlkem768};
use x25519_dalek::{PublicKey, StaticSecret};
use rand::RngCore;
use sha3::{Sha3_256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 public key size
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
/// X25519 secret key size
pub const X25519_SECRET_KEY_SIZE: usize = 32;

/// Combined hybrid keypair (X25519 + ML-KEM-768)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeyPair {
    /// X25519 secret key
    x25519_secret: [u8; X25519_SECRET_KEY_SIZE],
    /// X25519 public key
    #[zeroize(skip)]
    x25519_public: [u8; X25519_PUBLIC_KEY_SIZE],
    /// ML-KEM-768 keypair
    mlkem: MlKem768KeyPair,
}

impl HybridKeyPair {
    /// Generate a new hybrid keypair
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();

        // Generate X25519 keypair
        let mut x25519_secret = [0u8; X25519_SECRET_KEY_SIZE];
        rng.fill_bytes(&mut x25519_secret);
        let x25519_static = StaticSecret::from(x25519_secret);
        let x25519_public = *PublicKey::from(&x25519_static).as_bytes();

        // Generate ML-KEM-768 keypair
        let mlkem = MlKem768KeyPair::generate()?;

        Ok(Self {
            x25519_secret,
            x25519_public,
            mlkem,
        })
    }

    /// Get the X25519 public key bytes
    pub fn x25519_public_key(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        &self.x25519_public
    }

    /// Get the ML-KEM-768 encapsulation key (public key) bytes
    pub fn mlkem_encapsulation_key(&self) -> &[u8] {
        self.mlkem.encapsulation_key()
    }

    /// Process a hybrid key exchange response from a client
    ///
    /// Takes the client's X25519 public key and ML-KEM ciphertext,
    /// returns the combined shared secret.
    pub fn process_response(
        &self,
        client_x25519_public: &[u8],
        mlkem_ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if client_x25519_public.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(QsshError::Crypto(format!(
                "Invalid X25519 public key size: expected {}, got {}",
                X25519_PUBLIC_KEY_SIZE,
                client_x25519_public.len()
            )));
        }

        // Perform X25519 DH
        let x25519_static = StaticSecret::from(self.x25519_secret);
        let client_public: [u8; 32] = client_x25519_public.try_into().unwrap();
        let client_public = PublicKey::from(client_public);
        let x25519_shared = x25519_static.diffie_hellman(&client_public);

        // Decapsulate ML-KEM
        let mlkem_shared = self.mlkem.decapsulate(mlkem_ciphertext)?;

        // Combine both shared secrets
        Ok(combine_secrets(
            x25519_shared.as_bytes(),
            &mlkem_shared,
        ))
    }
}

/// Client-side hybrid key exchange initiator
pub struct HybridClientExchange {
    /// X25519 secret key
    x25519_secret: [u8; X25519_SECRET_KEY_SIZE],
    /// X25519 public key (to send to server)
    x25519_public: [u8; X25519_PUBLIC_KEY_SIZE],
}

impl HybridClientExchange {
    /// Create a new client-side hybrid exchange
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();

        let mut x25519_secret = [0u8; X25519_SECRET_KEY_SIZE];
        rng.fill_bytes(&mut x25519_secret);
        let x25519_static = StaticSecret::from(x25519_secret);
        let x25519_public = *PublicKey::from(&x25519_static).as_bytes();

        Self {
            x25519_secret,
            x25519_public,
        }
    }

    /// Get the client's X25519 public key
    pub fn x25519_public_key(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        &self.x25519_public
    }

    /// Complete the hybrid key exchange
    ///
    /// Takes the server's X25519 public key and ML-KEM encapsulation key,
    /// returns (shared_secret, mlkem_ciphertext).
    pub fn complete(
        &self,
        server_x25519_public: &[u8],
        server_mlkem_ek: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if server_x25519_public.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(QsshError::Crypto(format!(
                "Invalid server X25519 public key size: expected {}, got {}",
                X25519_PUBLIC_KEY_SIZE,
                server_x25519_public.len()
            )));
        }

        // Perform X25519 DH
        let x25519_static = StaticSecret::from(self.x25519_secret);
        let server_public: [u8; 32] = server_x25519_public.try_into().unwrap();
        let server_public = PublicKey::from(server_public);
        let x25519_shared = x25519_static.diffie_hellman(&server_public);

        // Encapsulate against server's ML-KEM key
        let (mlkem_shared, mlkem_ciphertext) = mlkem768_encapsulate(server_mlkem_ek)?;

        // Combine both shared secrets
        let combined = combine_secrets(x25519_shared.as_bytes(), &mlkem_shared);

        Ok((combined, mlkem_ciphertext))
    }
}

impl Drop for HybridClientExchange {
    fn drop(&mut self) {
        self.x25519_secret.zeroize();
    }
}

impl Default for HybridClientExchange {
    fn default() -> Self {
        Self::new()
    }
}

/// Combine X25519 and ML-KEM shared secrets using SHA3-256
///
/// The domain separator ensures this derivation is unique to QSSH hybrid mode.
pub fn combine_secrets(x25519_shared: &[u8], mlkem_shared: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"QSSH-HYBRID-X25519-MLKEM768-v1");
    hasher.update(x25519_shared);
    hasher.update(mlkem_shared);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange() {
        // Server generates keypair
        let server = HybridKeyPair::generate().unwrap();

        // Client initiates exchange
        let client = HybridClientExchange::new();

        // Client completes exchange using server's public keys
        let (client_shared, mlkem_ct) = client.complete(
            server.x25519_public_key(),
            server.mlkem_encapsulation_key(),
        ).unwrap();

        // Server processes client's response
        let server_shared = server.process_response(
            client.x25519_public_key(),
            &mlkem_ct,
        ).unwrap();

        // Both parties should have the same shared secret
        assert_eq!(client_shared, server_shared);
        assert_eq!(client_shared.len(), 32);
    }

    #[test]
    fn test_hybrid_key_sizes() {
        let keypair = HybridKeyPair::generate().unwrap();
        assert_eq!(keypair.x25519_public_key().len(), X25519_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.mlkem_encapsulation_key().len(), mlkem768::EK_SIZE);
    }

    #[test]
    fn test_combine_secrets_deterministic() {
        let x25519 = [0x11u8; 32];
        let mlkem = [0x22u8; 32];

        let combined1 = combine_secrets(&x25519, &mlkem);
        let combined2 = combine_secrets(&x25519, &mlkem);

        assert_eq!(combined1, combined2);
    }

    #[test]
    fn test_combine_secrets_different_inputs() {
        let x25519 = [0x11u8; 32];
        let mlkem1 = [0x22u8; 32];
        let mlkem2 = [0x33u8; 32];

        let combined1 = combine_secrets(&x25519, &mlkem1);
        let combined2 = combine_secrets(&x25519, &mlkem2);

        assert_ne!(combined1, combined2);
    }

    #[test]
    fn test_invalid_x25519_public_key_size() {
        let server = HybridKeyPair::generate().unwrap();
        let client = HybridClientExchange::new();

        // Try with wrong-sized server public key
        let bad_pk = vec![0u8; 16];
        let result = client.complete(&bad_pk, server.mlkem_encapsulation_key());
        assert!(result.is_err());
    }
}
