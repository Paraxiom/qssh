//! Minimal test to verify pure-Rust PQ crypto (fn-dsa + slh-dsa)

use qssh::crypto::PqKeyExchange;

#[test]
fn test_pq_key_exchange_creation() {
    let kex = PqKeyExchange::new().unwrap();

    // fn-dsa Falcon-512: PK = 897 bytes
    assert_eq!(kex.falcon_pk.len(), 897, "Falcon-512 public key size");
    // slh-dsa SPHINCS+: PK = 32 bytes
    assert_eq!(kex.sphincs_pk.len(), 32, "SPHINCS+ public key size");
}

#[test]
fn test_falcon_sign_verify_roundtrip() {
    let kex = PqKeyExchange::new().unwrap();
    let msg = b"test message for falcon signing";

    let sig = kex.sign_falcon(msg).unwrap();
    assert!(kex.verify_falcon(msg, &sig, &kex.falcon_pk).unwrap(),
        "Falcon signature should verify");
}

#[test]
fn test_sphincs_sign_verify_roundtrip() {
    let kex = PqKeyExchange::new().unwrap();
    let msg = b"test message for sphincs signing";

    let sig = kex.sign(msg).unwrap();
    assert!(kex.verify(msg, &sig, &kex.sphincs_pk).unwrap(),
        "SPHINCS+ signature should verify");
}

#[test]
fn test_no_c_ffi_dependencies() {
    // Verify that pqcrypto C-FFI types are not referenced in crypto module
    let output = std::process::Command::new("grep")
        .args(&["-rn", "pqcrypto_falcon\\|pqcrypto_sphincsplus\\|pqcrypto_traits", "src/crypto/"])
        .output()
        .expect("Failed to run grep");

    let result = String::from_utf8_lossy(&output.stdout);
    assert!(result.is_empty(),
        "Should NOT reference pqcrypto C-FFI crates: {}", result);
}
