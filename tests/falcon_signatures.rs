//! Tests for Falcon signature verification fix
//!
//! NOTE: All tests ignored due to pqcrypto segfault on macOS

use qssh::crypto::PqKeyExchange;

#[test]
#[ignore]
fn test_falcon_detached_signatures_basic() {
    // Create two parties
    let alice = PqKeyExchange::new().expect("Failed to create Alice");
    let bob = PqKeyExchange::new().expect("Failed to create Bob");

    // Alice creates key share with detached signature
    let (alice_share, alice_signature) = alice.create_key_share()
        .expect("Failed to create Alice's key share");

    assert_eq!(alice_share.len(), 32, "Key share should be 32 bytes");
    assert!(alice_signature.len() > 0, "Signature should not be empty");

    // Get public keys
    let alice_falcon_pk = alice.public_bytes();
    let bob_falcon_pk = bob.public_bytes();

    // Bob verifies Alice's detached signature
    let verified_share = bob.process_key_share(&alice_falcon_pk, &alice_share, &alice_signature)
        .expect("Failed to verify Alice's signature");

    assert_eq!(verified_share, alice_share, "Verified share should match original");
}

#[test]
#[ignore]
fn test_bidirectional_key_exchange() {
    let alice = PqKeyExchange::new().expect("Failed to create Alice");
    let bob = PqKeyExchange::new().expect("Failed to create Bob");

    // Alice -> Bob
    let (alice_share, alice_sig) = alice.create_key_share().unwrap();
    let alice_pk = alice.public_bytes();
    let verified_alice = bob.process_key_share(&alice_pk, &alice_share, &alice_sig).unwrap();
    assert_eq!(verified_alice, alice_share);

    // Bob -> Alice
    let (bob_share, bob_sig) = bob.create_key_share().unwrap();
    let bob_pk = bob.public_bytes();
    let verified_bob = alice.process_key_share(&bob_pk, &bob_share, &bob_sig).unwrap();
    assert_eq!(verified_bob, bob_share);

    // Compute shared secrets
    let alice_secret = alice.compute_shared_secret(
        &alice_share,
        &bob_share,
        b"client_random",
        b"server_random"
    );

    let bob_secret = bob.compute_shared_secret(
        &alice_share,
        &bob_share,
        b"client_random",
        b"server_random"
    );

    assert_eq!(alice_secret, bob_secret, "Shared secrets should match");
    assert_eq!(alice_secret.len(), 32, "Shared secret should be 32 bytes");
}

#[test]
#[ignore]
fn test_invalid_signature_rejection() {
    let alice = PqKeyExchange::new().unwrap();
    let bob = PqKeyExchange::new().unwrap();

    let (alice_share, mut alice_sig) = alice.create_key_share().unwrap();
    let alice_pk = alice.public_bytes();

    // Corrupt the signature
    alice_sig[0] ^= 0xFF;

    // Bob should reject corrupted signature
    let result = bob.process_key_share(&alice_pk, &alice_share, &alice_sig);
    assert!(result.is_err(), "Corrupted signature should be rejected");
}

#[test]
#[ignore]
fn test_wrong_public_key_rejection() {
    let alice = PqKeyExchange::new().unwrap();
    let bob = PqKeyExchange::new().unwrap();
    let charlie = PqKeyExchange::new().unwrap();

    let (alice_share, alice_sig) = alice.create_key_share().unwrap();
    let charlie_pk = charlie.public_bytes(); // Wrong key!

    // Bob verifies with wrong public key
    let result = bob.process_key_share(&charlie_pk, &alice_share, &alice_sig);
    assert!(result.is_err(), "Wrong public key should fail verification");
}

#[test]
#[ignore]
fn test_tampered_share_detection() {
    let alice = PqKeyExchange::new().unwrap();
    let bob = PqKeyExchange::new().unwrap();

    let (mut alice_share, alice_sig) = alice.create_key_share().unwrap();
    let alice_pk = alice.public_bytes();

    // Tamper with the share after signing
    alice_share[0] ^= 0xFF;

    // Bob should detect tampering
    let result = bob.process_key_share(&alice_pk, &alice_share, &alice_sig);
    assert!(result.is_err(), "Tampered share should fail verification");
}

#[test]
#[ignore]
fn test_empty_inputs() {
    let bob = PqKeyExchange::new().unwrap();

    // Test empty public key
    let result = bob.process_key_share(&[], &[0u8; 32], &[0u8; 100]);
    assert!(result.is_err(), "Empty public key should be rejected");

    // Test empty share
    let alice = PqKeyExchange::new().unwrap();
    let alice_pk = alice.public_bytes();
    let result = bob.process_key_share(&alice_pk, &[], &[0u8; 100]);
    assert!(result.is_err(), "Empty share should be rejected");

    // Test empty signature
    let result = bob.process_key_share(&alice_pk, &[0u8; 32], &[]);
    assert!(result.is_err(), "Empty signature should be rejected");
}

#[test]
#[ignore]
fn test_signature_determinism() {
    let alice = PqKeyExchange::new().unwrap();

    // Create multiple signatures - they should be different due to randomness in shares
    let (share1, sig1) = alice.create_key_share().unwrap();
    let (share2, sig2) = alice.create_key_share().unwrap();

    // Shares should be different (random)
    assert_ne!(share1, share2, "Random shares should be different");

    // Signatures should also be different
    assert_ne!(sig1, sig2, "Signatures of different data should be different");
}

#[test]
#[ignore]
fn test_key_exchange_uniqueness() {
    // Each key exchange should produce unique secrets
    let alice = PqKeyExchange::new().unwrap();
    let bob = PqKeyExchange::new().unwrap();

    let mut secrets = Vec::new();

    for _ in 0..10 {
        let (alice_share, _) = alice.create_key_share().unwrap();
        let (bob_share, _) = bob.create_key_share().unwrap();

        let secret = alice.compute_shared_secret(
            &alice_share,
            &bob_share,
            b"random1",
            b"random2"
        );

        // Check this secret is unique
        assert!(!secrets.contains(&secret), "Secrets should be unique");
        secrets.push(secret);
    }
}

#[test]
#[ignore]
fn test_falcon_public_key_size() {
    let kex = PqKeyExchange::new().unwrap();
    let falcon_pk = kex.public_bytes();

    // Falcon-512 public key should be 897 bytes
    assert_eq!(falcon_pk.len(), 897, "Falcon-512 public key size");
}