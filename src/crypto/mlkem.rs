//! ML-KEM (FIPS 203) key encapsulation mechanism
//!
//! Provides post-quantum key exchange using ML-KEM-768 and ML-KEM-1024.
//! ML-KEM is the NIST-standardized version of Kyber, free from the KyberSlash
//! timing vulnerabilities that affected earlier implementations.
//!
//! ## Security Levels
//! - ML-KEM-768: NIST Level 3 (roughly equivalent to AES-192)
//! - ML-KEM-1024: NIST Level 5 (roughly equivalent to AES-256)
//!
//! ## Constants
//! - ML-KEM-768: EK=1184, DK=2400, CT=1088, SS=32 bytes
//! - ML-KEM-1024: EK=1568, DK=3168, CT=1568, SS=32 bytes

use crate::{QsshError, Result};
use kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem1024};
use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-768 constants (NIST Level 3)
pub mod mlkem768 {
    /// Encapsulation key (public key) size in bytes
    pub const EK_SIZE: usize = 1184;
    /// Decapsulation key (secret key) size in bytes
    pub const DK_SIZE: usize = 2400;
    /// Ciphertext size in bytes
    pub const CT_SIZE: usize = 1088;
    /// Shared secret size in bytes
    pub const SS_SIZE: usize = 32;
}

/// ML-KEM-1024 constants (NIST Level 5)
pub mod mlkem1024 {
    /// Encapsulation key (public key) size in bytes
    pub const EK_SIZE: usize = 1568;
    /// Decapsulation key (secret key) size in bytes
    pub const DK_SIZE: usize = 3168;
    /// Ciphertext size in bytes
    pub const CT_SIZE: usize = 1568;
    /// Shared secret size in bytes
    pub const SS_SIZE: usize = 32;
}

/// ML-KEM-768 keypair for key exchange
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem768KeyPair {
    /// Decapsulation key (secret, kept private)
    dk_bytes: Vec<u8>,
    /// Encapsulation key (public, shared with peer)
    #[zeroize(skip)]
    ek_bytes: Vec<u8>,
}

impl MlKem768KeyPair {
    /// Generate a new ML-KEM-768 keypair
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng);

        let ek_bytes = EncodedSizeUser::as_bytes(&ek).to_vec();
        let dk_bytes = EncodedSizeUser::as_bytes(&dk).to_vec();

        Ok(Self { dk_bytes, ek_bytes })
    }

    /// Get the encapsulation key (public key) bytes
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.ek_bytes
    }

    /// Get the decapsulation key (secret key) bytes
    pub fn decapsulation_key(&self) -> &[u8] {
        &self.dk_bytes
    }

    /// Decapsulate a ciphertext to recover the shared secret
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() != mlkem768::CT_SIZE {
            return Err(QsshError::Crypto(format!(
                "Invalid ML-KEM-768 ciphertext size: expected {}, got {}",
                mlkem768::CT_SIZE,
                ciphertext.len()
            )));
        }

        // Parse the decapsulation key
        let dk_array: ml_kem::Encoded<DecapsulationKey<ml_kem::MlKem768Params>> =
            self.dk_bytes.as_slice().try_into().map_err(|_| {
                QsshError::Crypto("Invalid ML-KEM-768 decapsulation key".into())
            })?;
        let dk = DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(&dk_array);

        // Parse the ciphertext
        let ct_array: [u8; mlkem768::CT_SIZE] = ciphertext.try_into().unwrap();
        let ct = ml_kem::array::Array::from(ct_array);

        // Decapsulate
        let ss = dk.decapsulate(&ct).map_err(|_| {
            QsshError::Crypto("ML-KEM-768 decapsulation failed".into())
        })?;

        Ok(ss.as_slice().to_vec())
    }
}

/// ML-KEM-1024 keypair for key exchange (higher security level)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem1024KeyPair {
    /// Decapsulation key (secret, kept private)
    dk_bytes: Vec<u8>,
    /// Encapsulation key (public, shared with peer)
    #[zeroize(skip)]
    ek_bytes: Vec<u8>,
}

impl MlKem1024KeyPair {
    /// Generate a new ML-KEM-1024 keypair
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem1024::generate(&mut rng);

        let ek_bytes = EncodedSizeUser::as_bytes(&ek).to_vec();
        let dk_bytes = EncodedSizeUser::as_bytes(&dk).to_vec();

        Ok(Self { dk_bytes, ek_bytes })
    }

    /// Get the encapsulation key (public key) bytes
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.ek_bytes
    }

    /// Get the decapsulation key (secret key) bytes
    pub fn decapsulation_key(&self) -> &[u8] {
        &self.dk_bytes
    }

    /// Decapsulate a ciphertext to recover the shared secret
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() != mlkem1024::CT_SIZE {
            return Err(QsshError::Crypto(format!(
                "Invalid ML-KEM-1024 ciphertext size: expected {}, got {}",
                mlkem1024::CT_SIZE,
                ciphertext.len()
            )));
        }

        // Parse the decapsulation key
        let dk_array: ml_kem::Encoded<DecapsulationKey<ml_kem::MlKem1024Params>> =
            self.dk_bytes.as_slice().try_into().map_err(|_| {
                QsshError::Crypto("Invalid ML-KEM-1024 decapsulation key".into())
            })?;
        let dk = DecapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&dk_array);

        // Parse the ciphertext
        let ct_array: [u8; mlkem1024::CT_SIZE] = ciphertext.try_into().unwrap();
        let ct = ml_kem::array::Array::from(ct_array);

        // Decapsulate
        let ss = dk.decapsulate(&ct).map_err(|_| {
            QsshError::Crypto("ML-KEM-1024 decapsulation failed".into())
        })?;

        Ok(ss.as_slice().to_vec())
    }
}

/// Encapsulate against an ML-KEM-768 encapsulation key
///
/// Returns (shared_secret, ciphertext)
pub fn mlkem768_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if ek_bytes.len() != mlkem768::EK_SIZE {
        return Err(QsshError::Crypto(format!(
            "Invalid ML-KEM-768 encapsulation key size: expected {}, got {}",
            mlkem768::EK_SIZE,
            ek_bytes.len()
        )));
    }

    let mut rng = rand::thread_rng();

    // Parse the encapsulation key
    let ek_array: ml_kem::Encoded<EncapsulationKey<ml_kem::MlKem768Params>> =
        ek_bytes.try_into().map_err(|_| {
            QsshError::Crypto("Invalid ML-KEM-768 encapsulation key".into())
        })?;
    let ek = EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(&ek_array);

    // Encapsulate
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| {
        QsshError::Crypto("ML-KEM-768 encapsulation failed".into())
    })?;

    Ok((ss.as_slice().to_vec(), ct.as_slice().to_vec()))
}

/// Encapsulate against an ML-KEM-1024 encapsulation key
///
/// Returns (shared_secret, ciphertext)
pub fn mlkem1024_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if ek_bytes.len() != mlkem1024::EK_SIZE {
        return Err(QsshError::Crypto(format!(
            "Invalid ML-KEM-1024 encapsulation key size: expected {}, got {}",
            mlkem1024::EK_SIZE,
            ek_bytes.len()
        )));
    }

    let mut rng = rand::thread_rng();

    // Parse the encapsulation key
    let ek_array: ml_kem::Encoded<EncapsulationKey<ml_kem::MlKem1024Params>> =
        ek_bytes.try_into().map_err(|_| {
            QsshError::Crypto("Invalid ML-KEM-1024 encapsulation key".into())
        })?;
    let ek = EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&ek_array);

    // Encapsulate
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| {
        QsshError::Crypto("ML-KEM-1024 encapsulation failed".into())
    })?;

    Ok((ss.as_slice().to_vec(), ct.as_slice().to_vec()))
}

/// Derive session key material from ML-KEM shared secret
///
/// Uses SHA3-256 to combine the shared secret with client/server randoms
/// following a similar pattern to the existing Falcon-based derivation.
pub fn derive_session_material(
    shared_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Vec<u8> {
    use sha3::{Sha3_256, Digest};

    let mut hasher = Sha3_256::new();
    hasher.update(b"QSSH-MLKEM-v1");
    hasher.update(shared_secret);
    hasher.update(client_random);
    hasher.update(server_random);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem768_roundtrip() {
        let keypair = MlKem768KeyPair::generate().unwrap();

        // Encapsulate
        let (ss_sender, ct) = mlkem768_encapsulate(keypair.encapsulation_key()).unwrap();

        // Decapsulate
        let ss_receiver = keypair.decapsulate(&ct).unwrap();

        // Shared secrets must match
        assert_eq!(ss_sender, ss_receiver);
        assert_eq!(ss_sender.len(), mlkem768::SS_SIZE);
    }

    #[test]
    fn test_mlkem1024_roundtrip() {
        let keypair = MlKem1024KeyPair::generate().unwrap();

        // Encapsulate
        let (ss_sender, ct) = mlkem1024_encapsulate(keypair.encapsulation_key()).unwrap();

        // Decapsulate
        let ss_receiver = keypair.decapsulate(&ct).unwrap();

        // Shared secrets must match
        assert_eq!(ss_sender, ss_receiver);
        assert_eq!(ss_receiver.len(), mlkem1024::SS_SIZE);
    }

    #[test]
    fn test_mlkem768_key_sizes() {
        let keypair = MlKem768KeyPair::generate().unwrap();
        assert_eq!(keypair.encapsulation_key().len(), mlkem768::EK_SIZE);
        assert_eq!(keypair.decapsulation_key().len(), mlkem768::DK_SIZE);
    }

    #[test]
    fn test_mlkem1024_key_sizes() {
        let keypair = MlKem1024KeyPair::generate().unwrap();
        assert_eq!(keypair.encapsulation_key().len(), mlkem1024::EK_SIZE);
        assert_eq!(keypair.decapsulation_key().len(), mlkem1024::DK_SIZE);
    }

    #[test]
    fn test_invalid_ciphertext_size() {
        let keypair = MlKem768KeyPair::generate().unwrap();
        let bad_ct = vec![0u8; 100]; // Wrong size
        let result = keypair.decapsulate(&bad_ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ek_size() {
        let bad_ek = vec![0u8; 100]; // Wrong size
        let result = mlkem768_encapsulate(&bad_ek);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_material_derivation() {
        let client_random = [0x11u8; 32];
        let server_random = [0x22u8; 32];
        let shared_secret = [0x33u8; 32];

        let material1 = derive_session_material(&shared_secret, &client_random, &server_random);
        let material2 = derive_session_material(&shared_secret, &client_random, &server_random);

        // Same inputs produce same output
        assert_eq!(material1, material2);
        assert_eq!(material1.len(), 32);

        // Different inputs produce different output
        let material3 = derive_session_material(&shared_secret, &server_random, &client_random);
        assert_ne!(material1, material3);
    }
}
