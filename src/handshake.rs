//! QSSH handshake implementation

use crate::{
    Result, QsshError, QsshConfig, PqAlgorithm,
    crypto::{PqKeyExchange, SymmetricCrypto, SessionKeyDerivation},
    transport::{Transport, Message, ClientHelloMessage, ServerHelloMessage, 
                KeyExchangeMessage, AuthMessage, AuthMethod, PROTOCOL_VERSION},
    auth::AuthorizedKeysManager,
};
#[cfg(feature = "qkd")]
use crate::qkd::QkdClient;
use pqcrypto_traits::sign::{PublicKey as SignPublicKeyTrait, SecretKey as SignSecretKeyTrait, SignedMessage as SignedMessageTrait};
use tokio::net::TcpStream;
use rand::{thread_rng, RngCore};

/// Client-side handshake
pub struct ClientHandshake<'a> {
    config: &'a QsshConfig,
    stream: TcpStream,
    identity_key: Option<Vec<u8>>,  // Client's identity private key
    identity_pubkey: Option<Vec<u8>>,  // Client's identity public key
    #[cfg(feature = "qkd")]
    qkd_client: Option<QkdClient>,
}

impl<'a> ClientHandshake<'a> {
    pub fn new(config: &'a QsshConfig, stream: TcpStream) -> Self {
        log::debug!("Creating client handshake, QKD enabled: {}", config.use_qkd);
        
        // Load identity key from ~/.qssh/id_qssh
        let (identity_key, identity_pubkey) = Self::load_identity_key();
        
        #[cfg(feature = "qkd")]
        let qkd_client = if config.use_qkd {
            // Create QKD configuration from QSSH config
            let qkd_config = crate::qkd::QkdConfig {
                cert_path: config.qkd_cert_path.clone(),
                key_path: config.qkd_key_path.clone(),
                ca_path: config.qkd_ca_path.clone(),
                timeout_ms: 5000,
                cache_size: 10,
                min_entropy: 0.9,
            };
            
            let endpoint = config.qkd_endpoint.clone()
                .unwrap_or_else(|| "https://192.168.0.4/api/v1/keys".to_string());
            
            match QkdClient::new(endpoint, Some(qkd_config)) {
                Ok(client) => {
                    log::info!("QKD client initialized successfully");
                    Some(client)
                },
                Err(e) => {
                    log::warn!("Failed to create QKD client: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        Self {
            config,
            stream,
            identity_key,
            identity_pubkey,
            #[cfg(feature = "qkd")]
            qkd_client,
        }
    }
    
    /// Load identity key from filesystem
    fn load_identity_key() -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        use std::path::PathBuf;
        use std::fs;
        
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let key_path = PathBuf::from(home).join(".qssh/id_qssh");
        let pubkey_path = PathBuf::from(&key_path).with_extension("pub");
        
        // Load private key
        let identity_key = match fs::read_to_string(&key_path) {
            Ok(data) => {
                // Parse the PEM format
                if data.contains("BEGIN QSSH PRIVATE KEY") {
                    // Extract the base64 data between the headers
                    let lines: Vec<&str> = data.lines().collect();
                    let mut base64_data = String::new();
                    let mut in_key = false;
                    
                    for line in lines {
                        if line.contains("BEGIN QSSH PRIVATE KEY") {
                            in_key = true;
                            continue;
                        }
                        if line.contains("END QSSH PRIVATE KEY") {
                            break;
                        }
                        if in_key && !line.starts_with("Algorithm:") {
                            base64_data.push_str(line.trim());
                        }
                    }
                    
                    // Decode base64
                    use base64::Engine;
                    match base64::engine::general_purpose::STANDARD.decode(&base64_data) {
                        Ok(key_bytes) => {
                            log::debug!("Loaded and decoded identity key from {:?} ({} bytes)", key_path, key_bytes.len());
                            Some(key_bytes)
                        }
                        Err(e) => {
                            log::error!("Failed to decode private key: {}", e);
                            None
                        }
                    }
                } else {
                    // Try as raw bytes for backward compatibility
                    log::debug!("Trying to load as raw bytes from {:?}", key_path);
                    Some(data.into_bytes())
                }
            }
            Err(e) => {
                log::warn!("Failed to load identity key from {:?}: {}", key_path, e);
                None
            }
        };
        
        // Load public key
        let identity_pubkey = match fs::read_to_string(&pubkey_path) {
            Ok(data) => {
                // Parse the public key from the file format: "qssh-algorithm base64data comment"
                let parts: Vec<&str> = data.trim().split_whitespace().collect();
                if parts.len() >= 2 {
                    // Decode base64 public key
                    use base64::Engine;
                    match base64::engine::general_purpose::STANDARD.decode(parts[1]) {
                        Ok(pubkey) => {
                            log::debug!("Loaded identity public key from {:?}", pubkey_path);
                            Some(pubkey)
                        }
                        Err(e) => {
                            log::warn!("Failed to decode public key: {}", e);
                            None
                        }
                    }
                } else {
                    log::warn!("Invalid public key format in {:?}", pubkey_path);
                    None
                }
            }
            Err(e) => {
                log::warn!("Failed to load public key from {:?}: {}", pubkey_path, e);
                None
            }
        };
        
        (identity_key, identity_pubkey)
    }
    
    /// Perform client handshake
    pub async fn perform(mut self) -> Result<Transport> {
        log::debug!("Starting client handshake");
        
        // Generate client random
        let mut client_random = [0u8; 32];
        thread_rng().fill_bytes(&mut client_random);
        log::debug!("Generated client random");
        
        // Send client hello
        log::debug!("Creating ClientHelloMessage");
        let client_hello = ClientHelloMessage {
            version: PROTOCOL_VERSION,
            random: client_random,
            kex_algorithms: vec![PqAlgorithm::Falcon512],
            sig_algorithms: vec![PqAlgorithm::SphincsPlus],
            ciphers: vec!["aes256-gcm".to_string()],
            qkd_capable: cfg!(feature = "qkd") && self.config.use_qkd,
            extensions: vec![],
        };
        
        log::debug!("Sending ClientHello");
        self.send_raw(&Message::ClientHello(client_hello)).await?;
        log::debug!("ClientHello sent");
        
        // Receive server hello
        log::debug!("Waiting for ServerHello");
        let server_hello = match self.receive_raw().await? {
            Message::ServerHello(msg) => {
                log::debug!("Received ServerHello");
                msg
            },
            _ => return Err(QsshError::Protocol("Expected ServerHello".into())),
        };
        
        // Validate server selection
        if server_hello.version != PROTOCOL_VERSION {
            return Err(QsshError::Protocol("Version mismatch".into()));
        }
        
        // Perform key exchange
        let pq_kex = PqKeyExchange::new()?;
        
        // Create our key share
        let (our_share, our_signature) = pq_kex.create_key_share()?;
        
        // Process server's key share
        let server_share = pq_kex.process_key_share(
            &server_hello.falcon_public_key,
            &server_hello.key_share,
            &server_hello.key_share_signature,
        )?;
        
        // Compute shared secret
        let shared_secret = pq_kex.compute_shared_secret(
            &our_share,
            &server_share,
            &client_random,
            &server_hello.random,
        );
        
        // Get QKD key if available
        log::debug!("Checking QKD: enabled={}, endpoint={:?}", self.config.use_qkd, server_hello.qkd_endpoint);
        #[cfg(feature = "qkd")]
        let (qkd_key, qkd_proof) = if self.config.use_qkd && server_hello.qkd_endpoint.is_some() {
            if let Some(qkd_client) = &self.qkd_client {
                match qkd_client.get_key(256).await {
                    Ok(key) => {
                        log::info!("QKD key obtained: {} bytes", key.len());
                        // Use first half as key, second half as proof
                        let proof = if key.len() >= 32 {
                            key[..16].to_vec()
                        } else {
                            key.clone()
                        };
                        (Some(key), Some(proof))
                    }
                    Err(e) => {
                        log::warn!("QKD failed, continuing with PQC only: {}", e);
                        (None, None)
                    }
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        #[cfg(not(feature = "qkd"))]
        let (qkd_key, qkd_proof): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
        
        // Send key exchange
        log::debug!("Creating KeyExchangeMessage");
        let key_exchange = KeyExchangeMessage {
            falcon_public_key: {
                use SignPublicKeyTrait;
                let pk_bytes = pq_kex.falcon_pk.as_bytes().to_vec();
                log::debug!("Falcon public key: {} bytes", pk_bytes.len());
                pk_bytes
            },
            key_share: our_share,
            key_share_signature: our_signature,
            sphincs_public_key: {
                use SignPublicKeyTrait;
                let pk_bytes = pq_kex.sphincs_pk.as_bytes().to_vec();
                log::debug!("SPHINCS+ public key: {} bytes", pk_bytes.len());
                pk_bytes
            },
            qkd_proof,
        };
        
        log::debug!("Sending KeyExchangeMessage");
        self.send_raw(&Message::KeyExchange(key_exchange)).await?;
        log::debug!("KeyExchangeMessage sent");
        
        // Derive session keys - combine PQC shared secret with QKD key if available
        log::debug!("Deriving session keys");
        #[cfg(feature = "qkd")]
        let (final_secret, has_qkd) = match qkd_key {
            Some(qkd_key_bytes) => {
                log::info!("Combining PQC shared secret with QKD key for enhanced security");
                // XOR the PQC shared secret with QKD key for quantum-safe combination
                let mut combined = shared_secret.clone();
                for (i, byte) in combined.iter_mut().enumerate() {
                    if i < qkd_key_bytes.len() {
                        *byte ^= qkd_key_bytes[i];
                    }
                }
                (combined, true)
            }
            None => (shared_secret.clone(), false)
        };

        #[cfg(not(feature = "qkd"))]
        let final_secret = shared_secret.clone();

        let session_keys = SessionKeyDerivation::derive_keys(
            &final_secret,
            &client_random,
            &server_hello.random,
        )?;
        #[cfg(feature = "qkd")]
        let security_type = if has_qkd { "PQC+QKD" } else { "PQC-only" };
        #[cfg(not(feature = "qkd"))]
        let security_type = "PQC-only";
        log::debug!("Session keys derived with {} security", security_type);
        
        // Authenticate - compute session ID before moving stream
        log::debug!("Computing session ID");
        let session_id = self.compute_session_id(&client_random, &server_hello.random);
        log::debug!("Session ID computed: {} bytes", session_id.len());
        
        // Create transport with encryption - client uses client_write_key for sending, server_write_key for receiving
        log::debug!("Creating symmetric crypto");
        let send_crypto = SymmetricCrypto::from_shared_secret(&session_keys.client_write_key)?;
        let recv_crypto = SymmetricCrypto::from_shared_secret(&session_keys.server_write_key)?;
        log::debug!("Creating transport");
        let transport = Transport::new_bidirectional(self.stream, send_crypto, recv_crypto);
        
        // Determine authentication method
        let auth_msg = if let (Some(priv_key), Some(pub_key)) =
            (&self.identity_key, &self.identity_pubkey) {
            // Use public key authentication
            log::info!("Using identity Falcon key for authentication");

            // Parse the Falcon secret key
            use pqcrypto_falcon::falcon512;
            use pqcrypto_traits::sign::DetachedSignature as DetachedSigTrait;
            let sk = falcon512::SecretKey::from_bytes(priv_key)
                .map_err(|e| QsshError::Crypto(format!("Invalid identity key: {:?}", e)))?;

            // Sign the session ID
            let sig = falcon512::detached_sign(&session_id, &sk);
            let signature = sig.as_bytes().to_vec();

            log::debug!("Session ID signed: {} bytes", signature.len());

            AuthMessage {
                username: self.config.username.clone(),
                auth_method: AuthMethod::PublicKey {
                    algorithm: PqAlgorithm::Falcon512,
                    public_key: pub_key.clone(),
                },
                signature,
                session_id: session_id.clone(),
            }
        } else if let Some(password) = &self.config.password {
            // Use password authentication
            log::info!("Using password authentication for user {}", self.config.username);

            // Send password as plaintext (will be encrypted by transport layer)
            let password_bytes = password.as_bytes().to_vec();

            AuthMessage {
                username: self.config.username.clone(),
                auth_method: AuthMethod::Password {
                    password_hash: password_bytes,
                },
                signature: Vec::new(), // No signature needed for password auth
                session_id: session_id.clone(),
            }
        } else {
            // Fall back to ephemeral key authentication
            log::info!("Using ephemeral Falcon key for authentication");

            let signature = pq_kex.sign_falcon(&session_id)?;
            let public_key = pq_kex.falcon_pk.as_bytes().to_vec();

            AuthMessage {
                username: self.config.username.clone(),
                auth_method: AuthMethod::PublicKey {
                    algorithm: PqAlgorithm::Falcon512,
                    public_key,
                },
                signature,
                session_id: session_id.clone(),
            }
        };
        
        transport.send_message(&Message::Auth(auth_msg)).await?;
        
        // Wait for auth response
        match transport.receive_message::<Message>().await? {
            Message::Auth(_) => Ok(transport),
            Message::Disconnect(d) => Err(QsshError::Protocol(d.description)),
            _ => Err(QsshError::Protocol("Authentication failed".into())),
        }
    }
    
    /// Send raw message (before encryption is established)
    async fn send_raw(&mut self, msg: &Message) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let data = bincode::serialize(msg)
            .map_err(|e| QsshError::Protocol(format!("Serialization failed: {}", e)))?;
        
        let len = (data.len() as u32).to_be_bytes();
        self.stream.write_all(&len).await?;
        self.stream.write_all(&data).await?;
        self.stream.flush().await?;
        Ok(())
    }
    
    /// Receive raw message (before encryption is established)
    async fn receive_raw(&mut self) -> Result<Message> {
        use tokio::io::AsyncReadExt;
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        let mut data = vec![0u8; len];
        self.stream.read_exact(&mut data).await?;
        
        let msg = bincode::deserialize(&data)
            .map_err(|e| QsshError::Protocol(format!("Deserialization failed: {}", e)))?;
        Ok(msg)
    }
    
    fn compute_session_id(&self, client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-SESSION-ID");
        hasher.update(client_random);
        hasher.update(server_random);
        hasher.finalize().to_vec()
    }
}

/// Server-side handshake
pub struct ServerHandshake {
    stream: TcpStream,
    host_key: PqKeyExchange,
    auth_manager: Option<AuthorizedKeysManager>,
    password_manager: Option<crate::auth::PasswordAuthManager>,
    qkd_endpoint: Option<String>,
}

impl ServerHandshake {
    pub fn new(stream: TcpStream, host_key: PqKeyExchange) -> Self {
        let mut password_manager = crate::auth::system_password_auth();

        // Try to load passwords (ignore errors)
        let pm_clone = crate::auth::system_password_auth();
        tokio::spawn(async move {
            let _ = pm_clone.load_passwords().await;
        });

        Self {
            stream,
            host_key,
            auth_manager: Some(crate::auth::system_authorized_keys()),
            password_manager: Some(password_manager),
            qkd_endpoint: None,
        }
    }
    
    /// Set QKD endpoint for server
    pub fn with_qkd_endpoint(mut self, endpoint: Option<String>) -> Self {
        self.qkd_endpoint = endpoint;
        self
    }
    
    /// Perform server handshake
    pub async fn perform(mut self) -> Result<(Transport, String)> {
        // Receive client hello
        let client_hello = match self.receive_raw().await? {
            Message::ClientHello(msg) => msg,
            _ => return Err(QsshError::Protocol("Expected ClientHello".into())),
        };
        
        // Generate server random and Falcon keys
        let mut server_random = [0u8; 32];
        thread_rng().fill_bytes(&mut server_random);
        
        let server_kex = PqKeyExchange::new()?;
        
        // Create server's key share
        let (server_share, server_signature) = server_kex.create_key_share()?;
        
        // Send server hello
        let server_hello = ServerHelloMessage {
            version: PROTOCOL_VERSION,
            random: server_random,
            selected_kex: PqAlgorithm::Falcon512,
            selected_sig: PqAlgorithm::SphincsPlus,
            selected_cipher: "aes256-gcm".to_string(),
            falcon_public_key: {
                use SignPublicKeyTrait;
                server_kex.falcon_pk.as_bytes().to_vec()
            },
            key_share: server_share.clone(),
            key_share_signature: server_signature,
            qkd_endpoint: self.qkd_endpoint.clone(),
            extensions: vec![],
        };
        
        self.send_raw(&Message::ServerHello(server_hello)).await?;
        
        // Receive key exchange
        let key_exchange = match self.receive_raw().await? {
            Message::KeyExchange(msg) => msg,
            _ => return Err(QsshError::Protocol("Expected KeyExchange".into())),
        };
        
        // Process client's key share
        let client_share = server_kex.process_key_share(
            &key_exchange.falcon_public_key,
            &key_exchange.key_share,
            &key_exchange.key_share_signature,
        )?;
        
        // Compute shared secret (note: server reverses the order)
        let shared_secret = server_kex.compute_shared_secret(
            &server_share,  // server's share first
            &client_share,  // client's share second
            &client_hello.random,
            &server_random,
        );
        
        // Derive session keys
        let session_keys = SessionKeyDerivation::derive_keys(
            &shared_secret,
            &client_hello.random,
            &server_random,
        )?;
        
        // Compute session ID before moving stream
        let session_id = self.compute_session_id(&client_hello.random, &server_random);
        
        // Create transport with encryption - server uses server_write_key for sending, client_write_key for receiving
        let send_crypto = SymmetricCrypto::from_shared_secret(&session_keys.server_write_key)?;
        let recv_crypto = SymmetricCrypto::from_shared_secret(&session_keys.client_write_key)?;
        let transport = Transport::new_bidirectional(self.stream, send_crypto, recv_crypto);
        
        // Receive authentication
        let auth_msg = match transport.receive_message::<Message>().await? {
            Message::Auth(msg) => msg,
            _ => return Err(QsshError::Protocol("Expected Auth".into())),
        };
        // Verify authentication
        let authorized = match &auth_msg.auth_method {
            AuthMethod::PublicKey { algorithm: _, public_key } => {
                // Verify signature (expecting Falcon512 as we use it for signing)
                let sig_valid = server_kex.verify_falcon(&session_id, &auth_msg.signature, public_key)?;

                if !sig_valid {
                    log::warn!("Signature verification failed for user {}", auth_msg.username);
                    false
                } else if let Some(auth_mgr) = &self.auth_manager {
                    // Check authorized_keys
                    match auth_mgr.verify_public_key(&auth_msg.username, PqAlgorithm::Falcon512, public_key).await {
                        Ok(Some(_)) => {
                            log::info!("User {} authenticated successfully with public key", auth_msg.username);
                            true
                        }
                        Ok(None) => {
                            log::warn!("Public key not authorized for user {}", auth_msg.username);
                            false
                        }
                        Err(e) => {
                            log::error!("Failed to verify authorized_keys: {}", e);
                            false
                        }
                    }
                } else {
                    // No auth manager, reject
                    log::warn!("No authorized_keys manager configured");
                    false
                }
            }
            AuthMethod::Password { password_hash } => {
                if let Some(password_mgr) = &self.password_manager {
                    // The password_hash is actually the password (client should hash it)
                    // For now, we'll treat it as plaintext and hash it server-side
                    let password = String::from_utf8_lossy(password_hash);
                    match password_mgr.verify_password(&auth_msg.username, &password).await {
                        Ok(true) => {
                            log::info!("User {} authenticated successfully with password", auth_msg.username);
                            true
                        }
                        Ok(false) => {
                            log::warn!("Invalid password for user {}", auth_msg.username);
                            false
                        }
                        Err(e) => {
                            log::error!("Failed to verify password: {}", e);
                            false
                        }
                    }
                } else {
                    log::warn!("Password authentication not configured");
                    false
                }
            }
        };
        
        if !authorized {
            let disconnect = Message::Disconnect(crate::transport::protocol::DisconnectMessage {
                reason_code: crate::transport::protocol::disconnect_reasons::AUTHENTICATION_FAILED,
                description: "Authentication failed".into(),
            });
            transport.send_message(&disconnect).await?;
            return Err(QsshError::Protocol("Authentication failed".into()));
        }
        
        // Send auth success
        transport.send_message(&Message::Auth(auth_msg.clone())).await?;
        
        Ok((transport, auth_msg.username))
    }
    
    /// Send raw message (before encryption is established)
    async fn send_raw(&mut self, msg: &Message) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let data = bincode::serialize(msg)
            .map_err(|e| QsshError::Protocol(format!("Serialization failed: {}", e)))?;
        
        let len = (data.len() as u32).to_be_bytes();
        self.stream.write_all(&len).await?;
        self.stream.write_all(&data).await?;
        self.stream.flush().await?;
        Ok(())
    }
    
    /// Receive raw message (before encryption is established)
    async fn receive_raw(&mut self) -> Result<Message> {
        use tokio::io::AsyncReadExt;
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        let mut data = vec![0u8; len];
        self.stream.read_exact(&mut data).await?;
        
        let msg = bincode::deserialize(&data)
            .map_err(|e| QsshError::Protocol(format!("Deserialization failed: {}", e)))?;
        Ok(msg)
    }
    
    fn compute_session_id(&self, client_random: &[u8], server_random: &[u8]) -> Vec<u8> {
        use sha3::{Sha3_256, Digest};
        let mut hasher = Sha3_256::new();
        hasher.update(b"QSSH-SESSION-ID");
        hasher.update(client_random);
        hasher.update(server_random);
        hasher.finalize().to_vec()
    }
}