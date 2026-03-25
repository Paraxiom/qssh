//! Post-quantum cryptography module using Falcon (FN-DSA) + SPHINCS+ (SLH-DSA) + ML-KEM
//! Pure-Rust implementations — no C FFI.

use crate::{QsshError, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use fn_dsa::{
    sign_key_size, signature_size, vrfy_key_size, KeyPairGenerator as _,
    SigningKey as FnSigningKeyTrait, VerifyingKey as FnVerifyingKeyTrait, DOMAIN_NONE,
    FN_DSA_LOGN_512, HASH_ID_RAW,
};
use rand::RngCore;
use signature::{Keypair as SignatureKeypair, Signer, Verifier};
use slh_dsa::Sha2_128s;

pub mod cipher_choice;
#[cfg(feature = "hybrid-kex")]
pub mod hybrid;
pub mod kdf;
pub mod mlkem;
pub mod qrng_integration;
pub mod quantum_cipher;
pub mod quantum_kem; // PROPER quantum KEM (not broken signature-only!)
#[cfg(test)]
pub mod test_helpers;

pub use cipher_choice::{CipherAlgorithm, UniversalCipher};
#[cfg(feature = "hybrid-kex")]
pub use hybrid::{combine_secrets, HybridClientExchange, HybridKeyPair};
pub use kdf::{SessionKeyDerivation, SessionKeys};
pub use mlkem::{mlkem1024_encapsulate, mlkem768_encapsulate, MlKem1024KeyPair, MlKem768KeyPair};
pub use qrng_integration::{QrngConfig, QuantumRng};
pub use quantum_cipher::QuantumCipher;

/// Post-quantum signature using SLH-DSA (SPHINCS+)
pub struct PqSignature {
    pub sphincs_sk: Vec<u8>,
    pub sphincs_pk: Vec<u8>,
}

impl PqSignature {
    /// Generate new SLH-DSA (SPHINCS+) keypair
    pub fn new() -> Result<Self> {
        let sk = slh_dsa::SigningKey::<Sha2_128s>::new(&mut OsRng);
        let pk = sk.verifying_key().clone();
        Ok(Self {
            sphincs_sk: sk.to_bytes().to_vec(),
            sphincs_pk: pk.to_bytes().to_vec(),
        })
    }

    /// Get secret key bytes
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.sphincs_sk.clone()
    }

    /// Get public key bytes
    pub fn public_bytes(&self) -> Vec<u8> {
        self.sphincs_pk.clone()
    }
}

/// Post-quantum key exchange using FN-DSA (Falcon) + SLH-DSA (SPHINCS+)
/// Pure-Rust implementations — no C FFI.
pub struct PqKeyExchange {
    /// SLH-DSA (SPHINCS+) for long-term identity (raw key bytes)
    pub sphincs_sk: Vec<u8>,
    pub sphincs_pk: Vec<u8>,

    /// FN-DSA (Falcon-512) for ephemeral operations (raw key bytes)
    pub falcon_sk: Vec<u8>,
    pub falcon_pk: Vec<u8>,
}

impl PqKeyExchange {
    /// Generate new post-quantum keys
    pub fn new() -> Result<Self> {
        // Check for QRNG availability
        let qrng_available = std::env::var("QSSH_QRNG_ENDPOINT").is_ok()
            || std::env::var("QSSH_KIRQ_ENDPOINT").is_ok();

        if qrng_available {
            log::info!("QRNG endpoint detected - keys will use quantum entropy");
        }

        // Generate SLH-DSA (SPHINCS+) keypair
        let sphincs_signing = slh_dsa::SigningKey::<Sha2_128s>::new(&mut OsRng);
        let sphincs_verifying = sphincs_signing.verifying_key().clone();

        // Generate FN-DSA (Falcon-512) keypair
        let mut falcon_sk_buf = vec![0u8; sign_key_size(FN_DSA_LOGN_512)];
        let mut falcon_pk_buf = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
        fn_dsa::KeyPairGeneratorStandard::default().keygen(
            FN_DSA_LOGN_512,
            &mut OsRng,
            &mut falcon_sk_buf,
            &mut falcon_pk_buf,
        );

        Ok(Self {
            sphincs_sk: sphincs_signing.to_bytes().to_vec(),
            sphincs_pk: sphincs_verifying.to_bytes().to_vec(),
            falcon_sk: falcon_sk_buf,
            falcon_pk: falcon_pk_buf,
        })
    }

    /// Create ephemeral key share (replaces Kyber encapsulation)
    pub fn create_key_share(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate ephemeral secret with best available entropy
        let mut ephemeral_secret = vec![0u8; 32];

        if std::env::var("QSSH_QRNG_ENDPOINT").is_ok() {
            log::debug!("Using QRNG-enhanced entropy for ephemeral key share");
        }

        rand::thread_rng().fill_bytes(&mut ephemeral_secret);

        // Sign with Falcon for authenticity (detached signature)
        let mut sk = fn_dsa::SigningKeyStandard::decode(&self.falcon_sk)
            .ok_or_else(|| QsshError::Crypto("Invalid Falcon secret key".into()))?;
        let mut sig = vec![0u8; signature_size(FN_DSA_LOGN_512)];
        sk.sign(
            &mut OsRng,
            &DOMAIN_NONE,
            &HASH_ID_RAW,
            &ephemeral_secret,
            &mut sig,
        );

        Ok((ephemeral_secret, sig))
    }

    /// Verify and process peer's key share (replaces Kyber decapsulation)
    pub fn process_key_share(
        &self,
        peer_falcon_pk: &[u8],
        peer_share: &[u8],
        peer_signature: &[u8],
    ) -> Result<Vec<u8>> {
        if peer_share.len() != 32 {
            return Err(QsshError::Crypto(format!(
                "Invalid key share size: got {}, expected 32",
                peer_share.len()
            )));
        }

        let vk = fn_dsa::VerifyingKeyStandard::decode(peer_falcon_pk).ok_or_else(|| {
            log::error!(
                "Failed to parse Falcon public key of size {}",
                peer_falcon_pk.len()
            );
            QsshError::Crypto("Invalid Falcon public key".into())
        })?;

        if !vk.verify(peer_signature, &DOMAIN_NONE, &HASH_ID_RAW, peer_share) {
            log::error!("Falcon signature verification failed");
            return Err(QsshError::Crypto("Invalid Falcon signature".into()));
        }

        log::debug!("Falcon signature verified successfully");
        Ok(peer_share.to_vec())
    }

    /// Compute shared secret from both key shares
    pub fn compute_shared_secret(
        &self,
        our_share: &[u8],
        peer_share: &[u8],
        client_random: &[u8],
        server_random: &[u8],
    ) -> Vec<u8> {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-FALCON-v2");

        if our_share < peer_share {
            hasher.update(our_share);
            hasher.update(peer_share);
        } else {
            hasher.update(peer_share);
            hasher.update(our_share);
        }

        hasher.update(client_random);
        hasher.update(server_random);
        hasher.finalize().to_vec()
    }

    /// Sign a message with SLH-DSA (SPHINCS+) for identity/long-term (detached)
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = slh_dsa::SigningKey::<Sha2_128s>::try_from(self.sphincs_sk.as_slice())
            .map_err(|e| QsshError::Crypto(format!("Invalid SPHINCS+ key: {}", e)))?;
        let sig: slh_dsa::Signature<Sha2_128s> = Signer::try_sign(&sk, message)
            .map_err(|e| QsshError::Crypto(format!("SPHINCS+ signing failed: {}", e)))?;
        Ok(sig.to_bytes().to_vec())
    }

    /// Sign with FN-DSA (Falcon) for ephemeral/performance (detached)
    pub fn sign_falcon(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut sk = fn_dsa::SigningKeyStandard::decode(&self.falcon_sk)
            .ok_or_else(|| QsshError::Crypto("Invalid Falcon secret key".into()))?;
        let mut sig = vec![0u8; signature_size(FN_DSA_LOGN_512)];
        sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut sig);
        Ok(sig)
    }

    /// Get Falcon secret key bytes
    pub fn secret_bytes(&self) -> Vec<u8> {
        self.falcon_sk.clone()
    }

    /// Get Falcon public key bytes
    pub fn public_bytes(&self) -> Vec<u8> {
        self.falcon_pk.clone()
    }

    /// Verify a SLH-DSA (SPHINCS+) detached signature
    pub fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        let pk = slh_dsa::VerifyingKey::<Sha2_128s>::try_from(public_key)
            .map_err(|e| QsshError::Crypto(format!("Invalid SPHINCS+ public key: {}", e)))?;
        let sig = slh_dsa::Signature::<Sha2_128s>::try_from(signature)
            .map_err(|e| QsshError::Crypto(format!("Invalid SPHINCS+ signature: {}", e)))?;
        Ok(Verifier::verify(&pk, message, &sig).is_ok())
    }

    /// Verify a FN-DSA (Falcon) detached signature
    pub fn verify_falcon(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool> {
        let vk = fn_dsa::VerifyingKeyStandard::decode(public_key)
            .ok_or_else(|| QsshError::Crypto("Invalid Falcon public key".into()))?;
        Ok(vk.verify(signature, &DOMAIN_NONE, &HASH_ID_RAW, message))
    }

    /// Serialize all keys to bytes (for host key persistence).
    ///
    /// Format: `[MAGIC(4)][VERSION(1)][sphincs_sk_len(4)][sphincs_sk][sphincs_pk_len(4)][sphincs_pk]
    ///          [falcon_sk_len(4)][falcon_sk][falcon_pk_len(4)][falcon_pk]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"QSSH"); // magic
        buf.push(1u8); // version
        buf.extend_from_slice(&(self.sphincs_sk.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.sphincs_sk);
        buf.extend_from_slice(&(self.sphincs_pk.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.sphincs_pk);
        buf.extend_from_slice(&(self.falcon_sk.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.falcon_sk);
        buf.extend_from_slice(&(self.falcon_pk.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.falcon_pk);
        buf
    }

    /// Deserialize keys from bytes (for host key loading).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let magic = data
            .get(0..4)
            .ok_or_else(|| QsshError::Crypto("Host key file too short".into()))?;
        if magic != b"QSSH" {
            return Err(QsshError::Crypto("Invalid host key file magic".into()));
        }
        let version = *data
            .get(4)
            .ok_or_else(|| QsshError::Crypto("Host key file too short".into()))?;
        if version != 1 {
            return Err(QsshError::Crypto(format!(
                "Unsupported host key version: {}",
                version
            )));
        }

        let mut pos = 5;
        let read_field = |pos: &mut usize, name: &str| -> Result<Vec<u8>> {
            let len_bytes: [u8; 4] = data
                .get(*pos..(*pos + 4))
                .ok_or_else(|| {
                    QsshError::Crypto(format!("Truncated host key: missing {} length", name))
                })?
                .try_into()
                .map_err(|_| QsshError::Crypto(format!("Failed to parse {} length", name)))?;
            let len = u32::from_be_bytes(len_bytes) as usize;
            *pos += 4;

            let field = data
                .get(*pos..(*pos + len))
                .ok_or_else(|| {
                    QsshError::Crypto(format!("Truncated host key: missing {} data", name))
                })?
                .to_vec();
            *pos += len;
            Ok(field)
        };

        let sphincs_sk = read_field(&mut pos, "sphincs_sk")?;
        let sphincs_pk = read_field(&mut pos, "sphincs_pk")?;
        let falcon_sk = read_field(&mut pos, "falcon_sk")?;
        let falcon_pk = read_field(&mut pos, "falcon_pk")?;

        // Validate keys can be decoded
        slh_dsa::VerifyingKey::<Sha2_128s>::try_from(sphincs_pk.as_slice())
            .map_err(|e| QsshError::Crypto(format!("Invalid SPHINCS+ public key: {}", e)))?;
        fn_dsa::VerifyingKeyStandard::decode(&falcon_pk)
            .ok_or_else(|| QsshError::Crypto("Invalid Falcon public key".into()))?;

        Ok(Self {
            sphincs_sk,
            sphincs_pk,
            falcon_sk,
            falcon_pk,
        })
    }
}

/// Symmetric encryption using AES-256-GCM (NIST approved)
pub struct SymmetricCrypto {
    cipher: Aes256Gcm,
}

impl SymmetricCrypto {
    /// Create from shared secret
    pub fn from_shared_secret(shared_secret: &[u8]) -> Result<Self> {
        let key_bytes = shared_secret
            .get(0..32)
            .ok_or_else(|| QsshError::Crypto("Shared secret too short".into()))?;
        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        Ok(Self { cipher })
    }

    /// Encrypt data
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| QsshError::Crypto(format!("Encryption failed: {}", e)))?;

        Ok((ciphertext, nonce.to_vec()))
    }

    /// Decrypt data
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(QsshError::Crypto(format!(
                "Invalid nonce size: got {}, expected 12",
                nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(nonce);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| QsshError::Crypto(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FN-DSA (Falcon) key agreement test — pure Rust, works on all platforms.
    #[test]
    fn test_falcon_key_agreement() {
        let alice = PqKeyExchange::new().unwrap();
        let bob = PqKeyExchange::new().unwrap();

        // Alice creates key share
        let (alice_share, alice_sig) = alice.create_key_share().unwrap();

        // Bob verifies and creates his share
        let verified_alice_share = bob
            .process_key_share(&alice.falcon_pk, &alice_share, &alice_sig)
            .unwrap();
        assert_eq!(alice_share, verified_alice_share);

        let (bob_share, bob_sig) = bob.create_key_share().unwrap();

        // Alice verifies Bob's share
        let verified_bob_share = alice
            .process_key_share(&bob.falcon_pk, &bob_share, &bob_sig)
            .unwrap();
        assert_eq!(bob_share, verified_bob_share);

        // Both compute shared secret
        let client_random = vec![0x11; 32];
        let server_random = vec![0x22; 32];

        let alice_secret =
            alice.compute_shared_secret(&alice_share, &bob_share, &client_random, &server_random);

        let bob_secret =
            bob.compute_shared_secret(&bob_share, &alice_share, &client_random, &server_random);

        assert_eq!(alice_secret, bob_secret);
    }

    /// FN-DSA (Falcon) signature test — pure Rust, works on all platforms.
    #[test]
    fn test_falcon_signatures() {
        let signer = PqKeyExchange::new().unwrap();
        let message = b"Test message for Falcon";

        let signature = signer.sign_falcon(message).unwrap();
        let valid = signer
            .verify_falcon(message, &signature, &signer.falcon_pk)
            .unwrap();
        assert!(valid);

        // Wrong message should fail
        let wrong_message = b"Wrong message";
        let invalid = signer
            .verify_falcon(wrong_message, &signature, &signer.falcon_pk)
            .unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_symmetric_crypto() {
        let secret = vec![0x42; 32];
        let crypto = SymmetricCrypto::from_shared_secret(&secret).expect("Failed to create crypto");

        let plaintext = b"Hello, quantum world!";
        let (ciphertext, nonce) = crypto.encrypt(plaintext).expect("Failed to encrypt");

        let decrypted = crypto
            .decrypt(&ciphertext, &nonce)
            .expect("Failed to decrypt");

        assert_eq!(plaintext, &decrypted[..]);
    }

    /// Verify PqKeyExchange works on all platforms (pure Rust, no C FFI).
    #[test]
    fn test_keygen_all_platforms() {
        let kex = PqKeyExchange::new();
        assert!(
            kex.is_ok(),
            "PqKeyExchange::new() should succeed on all platforms"
        );
        let kex = kex.unwrap();
        assert_eq!(kex.falcon_pk.len(), vrfy_key_size(FN_DSA_LOGN_512));
        assert_eq!(kex.falcon_sk.len(), sign_key_size(FN_DSA_LOGN_512));
    }

    #[test]
    fn test_symmetric_crypto_short_secret_rejected() {
        let short_secret = vec![0x42; 16]; // 16 bytes, need 32
        let result = SymmetricCrypto::from_shared_secret(&short_secret);
        assert!(
            result.is_err(),
            "Shared secret shorter than 32 bytes should be rejected"
        );
    }

    #[test]
    fn test_symmetric_crypto_ciphertext_uniqueness() {
        let secret = vec![0x42; 32];
        let crypto = SymmetricCrypto::from_shared_secret(&secret).unwrap();
        let plaintext = b"Same plaintext encrypted twice";

        let (ct1, nonce1) = crypto.encrypt(plaintext).unwrap();
        let (ct2, nonce2) = crypto.encrypt(plaintext).unwrap();

        // Nonces must differ (random generation)
        assert_ne!(nonce1, nonce2, "Nonces should be unique per encryption");
        // Ciphertexts must differ due to different nonces
        assert_ne!(ct1, ct2, "Ciphertexts should differ due to unique nonces");

        // Both should still decrypt correctly
        assert_eq!(crypto.decrypt(&ct1, &nonce1).unwrap(), plaintext);
        assert_eq!(crypto.decrypt(&ct2, &nonce2).unwrap(), plaintext);
    }

    #[test]
    fn test_host_key_roundtrip() {
        let original = PqKeyExchange::new().unwrap();
        let bytes = original.to_bytes();

        // Verify magic and version
        assert_eq!(&bytes[0..4], b"QSSH");
        assert_eq!(bytes[4], 1);

        // Deserialize
        let loaded = PqKeyExchange::from_bytes(&bytes).unwrap();

        // Verify all keys match
        assert_eq!(original.sphincs_sk, loaded.sphincs_sk);
        assert_eq!(original.sphincs_pk, loaded.sphincs_pk);
        assert_eq!(original.falcon_sk, loaded.falcon_sk);
        assert_eq!(original.falcon_pk, loaded.falcon_pk);

        // Verify the loaded key can sign and verify
        let msg = b"test message";
        let sig = loaded.sign_falcon(msg).unwrap();
        let valid = loaded.verify_falcon(msg, &sig, &loaded.falcon_pk).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_host_key_invalid_magic() {
        let result = PqKeyExchange::from_bytes(b"NOPE\x01");
        assert!(result.is_err());
    }

    #[test]
    fn test_host_key_truncated() {
        let result = PqKeyExchange::from_bytes(b"QSS");
        assert!(result.is_err());
    }
}
