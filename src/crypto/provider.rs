//! Modular cryptographic provider system
//!
//! Allows easy swapping of algorithms and custom implementations

use crate::{Result, QsshError};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use fn_dsa::{KeyPairGenerator as _, SigningKey as FnSigningKeyTrait, VerifyingKey as FnVerifyingKeyTrait};

/// Cryptographic algorithm provider trait
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Get provider name
    fn name(&self) -> &str;

    /// Get supported algorithms
    fn algorithms(&self) -> Vec<AlgorithmInfo>;

    /// Generate keypair
    async fn generate_keypair(&self, algorithm: &str) -> Result<KeyPair>;

    /// Sign data
    async fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>>;

    /// Verify signature
    async fn verify(&self, key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool>;

    /// Key exchange
    async fn key_exchange(&self, our_key: &[u8], their_public: &[u8]) -> Result<Vec<u8>>;
}

/// Algorithm information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmInfo {
    pub name: String,
    pub algorithm_type: AlgorithmType,
    pub security_level: u32,
    pub key_size: usize,
    pub signature_size: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AlgorithmType {
    Lattice,      // Falcon, Dilithium, Kyber
    HashBased,    // SPHINCS+, XMSS
    CodeBased,    // McEliece
    Multivariate, // Rainbow
    Isogeny,      // SIKE (broken, but for completeness)
    Custom,       // User-provided
}

/// Keypair container
pub struct KeyPair {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Default Falcon provider (built-in, pure Rust via fn-dsa)
pub struct FalconProvider;

#[async_trait]
impl CryptoProvider for FalconProvider {
    fn name(&self) -> &str {
        "falcon"
    }

    fn algorithms(&self) -> Vec<AlgorithmInfo> {
        vec![
            AlgorithmInfo {
                name: "falcon-512".to_string(),
                algorithm_type: AlgorithmType::Lattice,
                security_level: 128,
                key_size: fn_dsa::vrfy_key_size(fn_dsa::FN_DSA_LOGN_512),
                signature_size: fn_dsa::signature_size(fn_dsa::FN_DSA_LOGN_512),
            },
        ]
    }

    async fn generate_keypair(&self, algorithm: &str) -> Result<KeyPair> {
        match algorithm {
            "falcon-512" => {
                let mut sk = vec![0u8; fn_dsa::sign_key_size(fn_dsa::FN_DSA_LOGN_512)];
                let mut pk = vec![0u8; fn_dsa::vrfy_key_size(fn_dsa::FN_DSA_LOGN_512)];
                fn_dsa::KeyPairGeneratorStandard::default()
                    .keygen(fn_dsa::FN_DSA_LOGN_512, &mut aes_gcm::aead::OsRng, &mut sk, &mut pk);
                Ok(KeyPair {
                    algorithm: algorithm.to_string(),
                    public_key: pk,
                    secret_key: sk,
                })
            }
            _ => Err(QsshError::Crypto("Unsupported algorithm".into())),
        }
    }

    async fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut sk = fn_dsa::SigningKeyStandard::decode(key)
            .ok_or_else(|| QsshError::Crypto("Invalid secret key".into()))?;
        let mut sig = vec![0u8; fn_dsa::signature_size(fn_dsa::FN_DSA_LOGN_512)];
        sk.sign(&mut aes_gcm::aead::OsRng, &fn_dsa::DOMAIN_NONE, &fn_dsa::HASH_ID_RAW, data, &mut sig);
        Ok(sig)
    }

    async fn verify(&self, key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        let vk = fn_dsa::VerifyingKeyStandard::decode(key)
            .ok_or_else(|| QsshError::Crypto("Invalid public key".into()))?;
        Ok(vk.verify(signature, &fn_dsa::DOMAIN_NONE, &fn_dsa::HASH_ID_RAW, data))
    }

    async fn key_exchange(&self, our_key: &[u8], their_public: &[u8]) -> Result<Vec<u8>> {
        use sha3::{Sha3_256, Digest};

        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-KEX-FALCON");
        hasher.update(our_key);
        hasher.update(their_public);
        Ok(hasher.finalize().to_vec())
    }
}

/// SPHINCS+ provider (pure Rust via slh-dsa)
pub struct SphincsProvider;

#[async_trait]
impl CryptoProvider for SphincsProvider {
    fn name(&self) -> &str {
        "sphincs"
    }

    fn algorithms(&self) -> Vec<AlgorithmInfo> {
        vec![
            AlgorithmInfo {
                name: "sphincs-sha256-128s".to_string(),
                algorithm_type: AlgorithmType::HashBased,
                security_level: 128,
                key_size: 32,  // SLH-DSA-SHA2-128s public key
                signature_size: 7856,  // SLH-DSA-SHA2-128s signature
            },
        ]
    }

    async fn generate_keypair(&self, algorithm: &str) -> Result<KeyPair> {
        use slh_dsa::Sha2_128s;

        let _ = algorithm; // all variants use same params for now
        let sk = slh_dsa::SigningKey::<Sha2_128s>::new(&mut aes_gcm::aead::OsRng);
        let pk = sk.verifying_key().clone();
        Ok(KeyPair {
            algorithm: algorithm.to_string(),
            public_key: pk.to_bytes().to_vec(),
            secret_key: sk.to_bytes().to_vec(),
        })
    }

    async fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use slh_dsa::Sha2_128s;
        use signature::Signer;

        let sk = slh_dsa::SigningKey::<Sha2_128s>::try_from(key)
            .map_err(|_| QsshError::Crypto("Invalid secret key".into()))?;
        let sig: slh_dsa::Signature<Sha2_128s> = Signer::try_sign(&sk, data)
            .map_err(|e| QsshError::Crypto(format!("Signing failed: {}", e)))?;
        Ok(sig.to_bytes().to_vec())
    }

    async fn verify(&self, key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        use slh_dsa::Sha2_128s;
        use signature::Verifier;

        let pk = slh_dsa::VerifyingKey::<Sha2_128s>::try_from(key)
            .map_err(|_| QsshError::Crypto("Invalid public key".into()))?;
        let sig = slh_dsa::Signature::<Sha2_128s>::try_from(signature)
            .map_err(|_| QsshError::Crypto("Invalid signature".into()))?;
        Ok(Verifier::verify(&pk, data, &sig).is_ok())
    }

    async fn key_exchange(&self, our_key: &[u8], their_public: &[u8]) -> Result<Vec<u8>> {
        use sha3::{Sha3_256, Digest};

        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-KEX-SPHINCS");
        hasher.update(our_key);
        hasher.update(their_public);
        Ok(hasher.finalize().to_vec())
    }
}

/// Custom algorithm provider wrapper
pub struct CustomProvider {
    name: String,
    provider: Box<dyn CryptoProvider>,
}

impl CustomProvider {
    pub fn new(name: String, provider: Box<dyn CryptoProvider>) -> Self {
        Self { name, provider }
    }
}

#[async_trait]
impl CryptoProvider for CustomProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn algorithms(&self) -> Vec<AlgorithmInfo> {
        self.provider.algorithms()
    }

    async fn generate_keypair(&self, algorithm: &str) -> Result<KeyPair> {
        self.provider.generate_keypair(algorithm).await
    }

    async fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.provider.sign(key, data).await
    }

    async fn verify(&self, key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        self.provider.verify(key, data, signature).await
    }

    async fn key_exchange(&self, our_key: &[u8], their_public: &[u8]) -> Result<Vec<u8>> {
        self.provider.key_exchange(our_key, their_public).await
    }
}

/// Crypto provider registry
pub struct CryptoRegistry {
    providers: std::collections::HashMap<String, Box<dyn CryptoProvider>>,
    default_provider: String,
}

impl CryptoRegistry {
    /// Create new registry with default providers
    pub fn new() -> Self {
        let mut registry = Self {
            providers: std::collections::HashMap::new(),
            default_provider: "falcon".to_string(),
        };

        registry.register(Box::new(FalconProvider));
        registry.register(Box::new(SphincsProvider));

        registry
    }

    /// Register a crypto provider
    pub fn register(&mut self, provider: Box<dyn CryptoProvider>) {
        let name = provider.name().to_string();
        self.providers.insert(name, provider);
    }

    /// Get provider by name
    pub fn get(&self, name: &str) -> Option<&dyn CryptoProvider> {
        self.providers.get(name).map(|p| p.as_ref())
    }

    /// Get default provider
    pub fn default(&self) -> &dyn CryptoProvider {
        self.providers.get(&self.default_provider)
            .map(|p| p.as_ref())
            .expect("Default provider not found")
    }

    /// Set default provider
    pub fn set_default(&mut self, name: &str) -> Result<()> {
        if self.providers.contains_key(name) {
            self.default_provider = name.to_string();
            Ok(())
        } else {
            Err(QsshError::Crypto(format!("Provider '{}' not found", name)))
        }
    }
}
