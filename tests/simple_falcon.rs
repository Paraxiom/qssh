//! Simple test for Falcon signature fix without complex interactions
//!
//! NOTE: All tests ignored due to pqcrypto segfault on macOS

use qssh::crypto::PqKeyExchange;

#[test]
#[ignore]
fn test_basic_key_share_creation() {
    println!("Creating PqKeyExchange instance...");
    let kex = PqKeyExchange::new().expect("Failed to create key exchange");

    println!("Creating key share...");
    let (share, signature) = kex.create_key_share()
        .expect("Failed to create key share");

    // Basic validations
    assert_eq!(share.len(), 32, "Key share should be 32 bytes");
    assert!(signature.len() > 0, "Signature should not be empty");

    // Check that signature is reasonable size for Falcon detached signature
    // Falcon-512 detached signature is ~690 bytes
    assert!(signature.len() > 600, "Signature seems too small");
    assert!(signature.len() < 800, "Signature seems too large");

    println!("✅ Basic key share creation working");
}

#[test]
#[ignore]
fn test_public_key_access() {
    let kex = PqKeyExchange::new().expect("Failed to create key exchange");

    let public_key = kex.public_bytes();

    // Falcon-512 public key should be 897 bytes
    assert_eq!(public_key.len(), 897, "Falcon public key size incorrect");

    println!("✅ Public key access working");
}

#[test]
#[ignore]
fn test_key_share_uniqueness() {
    let kex = PqKeyExchange::new().expect("Failed to create key exchange");

    // Create multiple key shares - they should all be different
    let (share1, sig1) = kex.create_key_share().unwrap();
    let (share2, sig2) = kex.create_key_share().unwrap();
    let (share3, sig3) = kex.create_key_share().unwrap();

    // All shares should be different (they're random)
    assert_ne!(share1, share2);
    assert_ne!(share2, share3);
    assert_ne!(share1, share3);

    // All signatures should be different too
    assert_ne!(sig1, sig2);
    assert_ne!(sig2, sig3);
    assert_ne!(sig1, sig3);

    println!("✅ Key share uniqueness verified");
}