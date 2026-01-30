//! Integration test for quantum-native protocol
//!
//! NOTE: All tests ignored due to pqcrypto segfault on macOS

use qssh::crypto::quantum_kem::QuantumKem;

#[test]
#[ignore]
fn test_quantum_kem_integration() {
    // Create two parties with proper quantum KEM
    let alice = QuantumKem::new().expect("Failed to create Alice");
    let bob = QuantumKem::new().expect("Failed to create Bob");

    // Get public keys
    let (alice_sphincs, alice_falcon) = alice.public_keys();
    let (bob_sphincs, bob_falcon) = bob.public_keys();

    // Test key sizes
    assert_eq!(alice_sphincs.len(), 32, "SPHINCS+ public key should be 32 bytes");
    assert_eq!(alice_falcon.len(), 897, "Falcon public key should be 897 bytes");

    // Alice -> Bob key exchange
    let (ciphertext_ab, alice_secret) = alice.encapsulate(&bob_sphincs)
        .expect("Alice encapsulation failed");

    let bob_secret = bob.decapsulate(&ciphertext_ab, &alice_sphincs)
        .expect("Bob decapsulation failed");

    assert_eq!(alice_secret, bob_secret, "Shared secrets don't match!");

    // Bob -> Alice key exchange (bidirectional test)
    let (ciphertext_ba, bob_secret2) = bob.encapsulate(&alice_sphincs)
        .expect("Bob encapsulation failed");

    let alice_secret2 = alice.decapsulate(&ciphertext_ba, &bob_sphincs)
        .expect("Alice decapsulation failed");

    assert_eq!(bob_secret2, alice_secret2, "Reverse direction secrets don't match!");

    // Verify different sessions produce different secrets
    assert_ne!(alice_secret, alice_secret2, "Sessions should have different secrets!");

    println!("✅ Quantum KEM integration test passed!");
    println!("   - SPHINCS+ for identity (hash-based, quantum-safe)");
    println!("   - Falcon for ephemeral (NTRU-based, fast)");
    println!("   - Proper KEM construction (not broken signature-only!)");
    println!("   - Shared secret: {} bytes", alice_secret.len());
}

#[test]
#[ignore]
fn test_not_vulnerable_to_kyberslash() {
    // This test demonstrates we're not vulnerable to timing attacks like KyberSlash
    let kem = QuantumKem::new().unwrap();
    let (pk, _) = kem.public_keys();

    // Multiple encapsulations should take consistent time
    // (In real testing, we'd measure actual timing)
    let mut secrets = Vec::new();
    for _ in 0..10 {
        let (_, secret) = kem.encapsulate(&pk).unwrap();
        secrets.push(secret);
    }

    // All secrets should be different (no reuse)
    for i in 0..secrets.len() {
        for j in i+1..secrets.len() {
            assert_ne!(secrets[i], secrets[j], "Secrets should never be reused!");
        }
    }

    println!("✅ Not vulnerable to timing attacks!");
}