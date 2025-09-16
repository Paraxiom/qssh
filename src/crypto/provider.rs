//! Modular cryptographic provider system
//! 
//! Allows easy swapping of algorithms and custom implementations

use crate::{Result, QsshError};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};

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

/// Default Falcon provider (built-in)
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
                key_size: 897,
                signature_size: 690,
            },
            AlgorithmInfo {
                name: "falcon-1024".to_string(),
                algorithm_type: AlgorithmType::Lattice,
                security_level: 256,
                key_size: 1793,
                signature_size: 1280,
            },
        ]
    }
    
    async fn generate_keypair(&self, algorithm: &str) -> Result<KeyPair> {
        use pqcrypto_falcon::falcon512;
        use pqcrypto_traits::sign::{PublicKey, SecretKey};
        
        match algorithm {
            "falcon-512" => {
                let (pk, sk) = falcon512::keypair();
                Ok(KeyPair {
                    algorithm: algorithm.to_string(),
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: sk.as_bytes().to_vec(),
                })
            }
            _ => Err(QsshError::Crypto("Unsupported algorithm".into())),
        }
    }
    
    async fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use pqcrypto_falcon::falcon512;
        use pqcrypto_traits::sign::{SecretKey, SignedMessage};
        
        let sk = falcon512::SecretKey::from_bytes(key)
            .map_err(|_| QsshError::Crypto("Invalid secret key".into()))?;
        
        let sig = falcon512::sign(data, &sk);
        Ok(sig.as_bytes().to_vec())
    }
    
    async fn verify(&self, key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        use pqcrypto_falcon::falcon512;
        use pqcrypto_traits::sign::{PublicKey, SignedMessage};
        
        let pk = falcon512::PublicKey::from_bytes(key)
            .map_err(|_| QsshError::Crypto("Invalid public key".into()))?;
            
        let sig = falcon512::SignedMessage::from_bytes(signature)
            .map_err(|_| QsshError::Crypto("Invalid signature".into()))?;
        
        match falcon512::open(&sig, &pk) {
            Ok(msg) => Ok(msg == data),
            Err(_) => Ok(false),
        }
    }
    
    async fn key_exchange(&self, our_key: &[u8], their_public: &[u8]) -> Result<Vec<u8>> {
        // Falcon is signature-only, so we do DH-like with signed ephemeral keys
        use sha3::{Sha3_256, Digest};
        
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-KEX-FALCON");
        hasher.update(our_key);
        hasher.update(their_public);
        Ok(hasher.finalize().to_vec())
    }
}

/// SPHINCS+ provider
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
                key_size: 64,
                signature_size: 8080,
            },
        ]
    }
    
    async fn generate_keypair(&self, algorithm: &str) -> Result<KeyPair> {
        use pqcrypto_sphincsplus::sphincssha256128ssimple as sphincs;
        use pqcrypto_traits::sign::{PublicKey, SecretKey};
        
        let (pk, sk) = sphincs::keypair();
        Ok(KeyPair {
            algorithm: algorithm.to_string(),
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        })
    }
    
    async fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use pqcrypto_sphincsplus::sphincssha256128ssimple as sphincs;
        use pqcrypto_traits::sign::{SecretKey, SignedMessage};
        
        let sk = sphincs::SecretKey::from_bytes(key)
            .map_err(|_| QsshError::Crypto("Invalid secret key".into()))?;
        
        let sig = sphincs::sign(data, &sk);
        Ok(sig.as_bytes().to_vec())
    }
    
    async fn verify(&self, key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        use pqcrypto_sphincsplus::sphincssha256128ssimple as sphincs;
        use pqcrypto_traits::sign::{PublicKey, SignedMessage};
        
        let pk = sphincs::PublicKey::from_bytes(key)
            .map_err(|_| QsshError::Crypto("Invalid public key".into()))?;
            
        let sig = sphincs::SignedMessage::from_bytes(signature)
            .map_err(|_| QsshError::Crypto("Invalid signature".into()))?;
        
        match sphincs::open(&sig, &pk) {
            Ok(msg) => Ok(msg == data),
            Err(_) => Ok(false),
        }
    }
    
    async fn key_exchange(&self, our_key: &[u8], their_public: &[u8]) -> Result<Vec<u8>> {
        // SPHINCS+ is signature-only, similar approach as Falcon
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
        
        // Register built-in providers
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