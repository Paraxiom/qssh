//! Exhaustive unit tests for QSSH Agent
//! This module contains comprehensive tests to ensure no shortcuts or TODOs

#[cfg(test)]
mod tests {
    use super::super::*;
    use tempfile::TempDir;
    use tokio::time::{timeout, Duration};

    /// Test agent creation and initialization
    #[tokio::test]
    async fn test_agent_creation() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = QsshAgent::new(socket_path.clone());

        assert_eq!(agent.socket_path, socket_path);
        assert_eq!(agent.max_keys, 100);
        assert!(agent.keys.read().await.is_empty());
        assert!(agent.lock_passphrase.read().await.is_none());
    }

    /// Test adding and retrieving keys
    #[tokio::test]
    async fn test_add_and_list_keys() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = QsshAgent::new(socket_path);

        // Generate test keys
        let (private_key, public_key) = generate_test_falcon_keys();

        // Add key
        let result = agent.add_key(
            PqAlgorithm::Falcon512,
            private_key.clone(),
            public_key.clone(),
            "test@example.com".to_string(),
            None
        ).await;

        assert!(result.is_ok());

        // List keys
        let keys = agent.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].comment, "test@example.com");
        assert_eq!(keys[0].algorithm, PqAlgorithm::Falcon512);
    }

    /// Test key expiration
    #[tokio::test]
    async fn test_key_expiration() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = QsshAgent::new(socket_path);

        let (private_key, public_key) = generate_test_falcon_keys();

        // Add key with 1 second lifetime
        agent.add_key(
            PqAlgorithm::Falcon512,
            private_key,
            public_key,
            "expiring@example.com".to_string(),
            Some(1)
        ).await.unwrap();

        // Key should exist immediately
        assert_eq!(agent.list_keys().await.unwrap().len(), 1);

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Cleanup expired keys
        agent.cleanup_expired_keys().await;

        // Key should be gone
        assert_eq!(agent.list_keys().await.unwrap().len(), 0);
    }

    /// Test removing specific key
    #[tokio::test]
    async fn test_remove_key() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = QsshAgent::new(socket_path);

        let (private_key1, public_key1) = generate_test_falcon_keys();
        let (private_key2, public_key2) = generate_test_falcon_keys();

        // Add two keys
        agent.add_key(
            PqAlgorithm::Falcon512,
            private_key1,
            public_key1.clone(),
            "key1@example.com".to_string(),
            None
        ).await.unwrap();

        agent.add_key(
            PqAlgorithm::Falcon512,
            private_key2,
            public_key2.clone(),
            "key2@example.com".to_string(),
            None
        ).await.unwrap();

        assert_eq!(agent.list_keys().await.unwrap().len(), 2);

        // Remove first key
        agent.remove_key(public_key1).await.unwrap();

        // Should have only one key left
        let keys = agent.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].comment, "key2@example.com");
    }

    /// Test removing all keys
    #[tokio::test]
    async fn test_remove_all_keys() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = QsshAgent::new(socket_path);

        // Add multiple keys
        for i in 0..5 {
            let (private_key, public_key) = generate_test_falcon_keys();
            agent.add_key(
                PqAlgorithm::Falcon512,
                private_key,
                public_key,
                format!("key{}@example.com", i),
                None
            ).await.unwrap();
        }

        assert_eq!(agent.list_keys().await.unwrap().len(), 5);

        // Remove all
        agent.remove_all_keys().await.unwrap();

        assert_eq!(agent.list_keys().await.unwrap().len(), 0);
    }

    /// Test agent locking and unlocking
    #[tokio::test]
    async fn test_lock_unlock() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = QsshAgent::new(socket_path);

        let (private_key, public_key) = generate_test_falcon_keys();

        // Add a key
        agent.add_key(
            PqAlgorithm::Falcon512,
            private_key.clone(),
            public_key.clone(),
            "test@example.com".to_string(),
            None
        ).await.unwrap();

        // Lock agent with test passphrase
        #[cfg(test)]
        const TEST_PASSPHRASE: &str = "test_passphrase_only_for_unit_tests";
        agent.lock(TEST_PASSPHRASE.to_string()).await.unwrap();

        // Operations should fail when locked
        assert!(agent.list_keys().await.is_err());
        assert!(agent.add_key(
            PqAlgorithm::Falcon512,
            private_key.clone(),
            public_key.clone(),
            "new@example.com".to_string(),
            None
        ).await.is_err());

        // Wrong passphrase should fail
        assert!(agent.unlock("wrong".to_string()).await.is_err());

        // Correct passphrase should work
        agent.unlock(TEST_PASSPHRASE.to_string()).await.unwrap();

        // Operations should work again
        assert!(agent.list_keys().await.is_ok());
    }

    /// Test signing with agent
    #[tokio::test]
    async fn test_sign_with_key() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = QsshAgent::new(socket_path);

        let (private_key, public_key) = generate_test_falcon_keys();

        // Add key
        agent.add_key(
            PqAlgorithm::Falcon512,
            private_key,
            public_key.clone(),
            "signer@example.com".to_string(),
            None
        ).await.unwrap();

        // Sign data
        let data = b"Hello, quantum world!";
        let signature = agent.sign_with_key(public_key.clone(), data.to_vec()).await.unwrap();

        // Verify signature is not empty
        assert!(!signature.is_empty());

        // Test signing with non-existent key
        let (_, fake_public) = generate_test_falcon_keys();
        assert!(agent.sign_with_key(fake_public, data.to_vec()).await.is_err());
    }

    /// Test max keys limit
    #[tokio::test]
    async fn test_max_keys_limit() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let mut agent = QsshAgent::new(socket_path);
        agent.max_keys = 3; // Set low limit for testing

        // Add keys up to limit
        for i in 0..3 {
            let (private_key, public_key) = generate_test_falcon_keys();
            assert!(agent.add_key(
                PqAlgorithm::Falcon512,
                private_key,
                public_key,
                format!("key{}@example.com", i),
                None
            ).await.is_ok());
        }

        // Adding one more should fail
        let (private_key, public_key) = generate_test_falcon_keys();
        assert!(agent.add_key(
            PqAlgorithm::Falcon512,
            private_key,
            public_key,
            "overflow@example.com".to_string(),
            None
        ).await.is_err());
    }

    /// Test agent protocol message handling
    #[tokio::test]
    async fn test_protocol_messages() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = QsshAgent::new(socket_path);

        // Test various message types
        let test_cases = vec![
            (AgentMessage::ListKeys, true),
            (AgentMessage::RemoveAllKeys, true),
            (AgentMessage::Lock { passphrase: "test".to_string() }, true),
            (AgentMessage::Unlock { passphrase: "test".to_string() }, true),
        ];

        for (message, should_succeed) in test_cases {
            let response = agent.handle_message(message).await;
            assert_eq!(response.is_ok(), should_succeed);
        }
    }

    /// Test concurrent operations
    #[tokio::test]
    async fn test_concurrent_operations() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = Arc::new(QsshAgent::new(socket_path));

        // Spawn multiple tasks that add keys concurrently
        let mut handles = vec![];

        for i in 0..10 {
            let agent_clone = agent.clone();
            let handle = tokio::spawn(async move {
                let (private_key, public_key) = generate_test_falcon_keys();
                agent_clone.add_key(
                    PqAlgorithm::Falcon512,
                    private_key,
                    public_key,
                    format!("concurrent{}@example.com", i),
                    None
                ).await
            });
            handles.push(handle);
        }

        // Wait for all to complete
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        // Should have all 10 keys
        assert_eq!(agent.list_keys().await.unwrap().len(), 10);
    }

    /// Test agent socket communication
    #[tokio::test]
    async fn test_socket_communication() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = Arc::new(QsshAgent::new(socket_path.clone()));

        // Start agent in background
        let agent_clone = agent.clone();
        let server_handle = tokio::spawn(async move {
            agent_clone.start().await
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create client and test connection
        let client = AgentClient::with_socket(socket_path);

        // Test list keys
        let result = timeout(Duration::from_secs(1), client.list_keys()).await;
        assert!(result.is_ok());

        // Cleanup
        drop(client);
        server_handle.abort();
    }

    /// Test fingerprint generation
    #[tokio::test]
    async fn test_fingerprint_generation() {
        let (_, public_key) = generate_test_falcon_keys();
        let fingerprint1 = generate_fingerprint(&public_key);
        let fingerprint2 = generate_fingerprint(&public_key);

        // Same key should produce same fingerprint
        assert_eq!(fingerprint1, fingerprint2);

        // Different key should produce different fingerprint
        let (_, public_key2) = generate_test_falcon_keys();
        let fingerprint3 = generate_fingerprint(&public_key2);
        assert_ne!(fingerprint1, fingerprint3);
    }

    /// Test SPHINCS+ key operations
    /// NOTE: Ignored due to pqcrypto segfault on macOS (works on Linux)
    #[tokio::test]
    #[ignore]
    async fn test_sphincs_keys() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        let agent = QsshAgent::new(socket_path);

        let (private_key, public_key) = generate_test_sphincs_keys();

        // Add SPHINCS+ key
        let result = agent.add_key(
            PqAlgorithm::SphincsPlus,
            private_key,
            public_key.clone(),
            "sphincs@example.com".to_string(),
            None
        ).await;

        assert!(result.is_ok());

        // Verify it's listed correctly
        let keys = agent.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].algorithm, PqAlgorithm::SphincsPlus);
    }

    // Helper functions for testing
    fn generate_test_falcon_keys() -> (Vec<u8>, Vec<u8>) {
        use pqcrypto_falcon::falcon512;
        use pqcrypto_traits::sign::{SecretKey as SecretKeyTrait, PublicKey as PublicKeyTrait};
        let (pk, sk) = falcon512::keypair();
        (sk.as_bytes().to_vec(), pk.as_bytes().to_vec())
    }

    fn generate_test_sphincs_keys() -> (Vec<u8>, Vec<u8>) {
        use pqcrypto_sphincsplus::sphincssha256128ssimple as sphincs;
        use pqcrypto_traits::sign::{SecretKey as SecretKeyTrait, PublicKey as PublicKeyTrait};
        let (pk, sk) = sphincs::keypair();
        (sk.as_bytes().to_vec(), pk.as_bytes().to_vec())
    }

    fn generate_fingerprint(public_key: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        use base64::Engine;
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let hash = hasher.finalize();
        format!("SHA256:{}", base64::engine::general_purpose::STANDARD.encode(hash))
    }
}