//! Integration tests for qssh-keygen binary
//!
//! Verifies CLI argument validation, classical algorithm rejection, and
//! quantum-safe key generation output format.
//!
//! NOTE: Tests that invoke actual PQ keygen are `#[ignore]` on macOS due to
//! the pqcrypto-falcon FFI segfault. They run on Linux CI.

use std::process::Command;

/// Helper to run qssh-keygen with given args and return (exit_code, stderr)
fn run_keygen(args: &[&str]) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_qssh-keygen"))
        .args(args)
        .output()
        .expect("failed to execute qssh-keygen");

    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stderr)
}

#[test]
fn test_rsa_key_type_rejected() {
    let (code, stderr) = run_keygen(&["-t", "rsa", "-y", "-f", "/tmp/qssh_test_rsa_key"]);
    assert_eq!(code, 1, "RSA key generation should exit with code 1");
    assert!(
        stderr.contains("not quantum-safe"),
        "stderr should warn about non-quantum-safe algorithm, got: {}",
        stderr
    );
}

#[test]
fn test_ed25519_key_type_rejected() {
    let (code, stderr) = run_keygen(&["-t", "ed25519", "-y", "-f", "/tmp/qssh_test_ed25519_key"]);
    assert_eq!(code, 1, "Ed25519 key generation should exit with code 1");
    assert!(
        stderr.contains("not quantum-safe"),
        "stderr should warn about non-quantum-safe algorithm, got: {}",
        stderr
    );
}

/// Ignored on macOS: pqcrypto-falcon FFI segfaults during Falcon keygen.
#[test]
#[cfg_attr(target_os = "macos", ignore)]
fn test_falcon512_key_generation_succeeds() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let key_path = tmp_dir.path().join("id_falcon");
    let key_path_str = key_path.to_str().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_qssh-keygen"))
        .args(&["-t", "falcon512", "-y", "-f", key_path_str, "-C", "test@qssh"])
        .output()
        .expect("failed to execute qssh-keygen");

    assert!(
        output.status.success(),
        "Falcon512 keygen should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Private key file should exist
    assert!(key_path.exists(), "Private key file should be created");
    // Public key file should exist
    let pub_path = tmp_dir.path().join("id_falcon.pub");
    assert!(pub_path.exists(), "Public key file should be created");

    // Public key should contain the algorithm identifier and comment
    let pub_contents = std::fs::read_to_string(&pub_path).unwrap();
    assert!(pub_contents.starts_with("qssh-falcon512 "), "Public key should start with algorithm");
    assert!(pub_contents.contains("test@qssh"), "Public key should contain the comment");
}

/// Ignored on macOS: pqcrypto-falcon FFI segfaults during keygen init.
#[test]
#[cfg_attr(target_os = "macos", ignore)]
fn test_sphincsplus_key_generation_succeeds() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let key_path = tmp_dir.path().join("id_sphincs");
    let key_path_str = key_path.to_str().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_qssh-keygen"))
        .args(&["-t", "sphincs+", "-y", "-f", key_path_str, "-C", "test@qssh"])
        .output()
        .expect("failed to execute qssh-keygen");

    assert!(
        output.status.success(),
        "SPHINCS+ keygen should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pub_path = tmp_dir.path().join("id_sphincs.pub");
    assert!(pub_path.exists(), "Public key file should be created");

    let pub_contents = std::fs::read_to_string(&pub_path).unwrap();
    assert!(pub_contents.starts_with("qssh-sphincs+ "), "Public key should start with algorithm");
}

/// Ignored on macOS: pqcrypto-falcon FFI segfaults during keygen.
#[test]
#[cfg_attr(target_os = "macos", ignore)]
fn test_private_key_permissions() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let key_path = tmp_dir.path().join("id_perms");
    let key_path_str = key_path.to_str().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_qssh-keygen"))
        .args(&["-t", "falcon512", "-y", "-f", key_path_str])
        .output()
        .expect("failed to execute qssh-keygen");

    assert!(output.status.success());

    // Verify private key has 0600 permissions
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(&key_path).unwrap();
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Private key should have 0600 permissions, got {:o}", mode);
}

/// Ignored on macOS: pqcrypto-falcon FFI segfaults during keygen.
#[test]
#[cfg_attr(target_os = "macos", ignore)]
fn test_private_key_format() {
    let tmp_dir = tempfile::TempDir::new().unwrap();
    let key_path = tmp_dir.path().join("id_format");
    let key_path_str = key_path.to_str().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_qssh-keygen"))
        .args(&["-t", "falcon512", "-y", "-f", key_path_str])
        .output()
        .expect("failed to execute qssh-keygen");

    assert!(output.status.success());

    let contents = std::fs::read_to_string(&key_path).unwrap();
    assert!(contents.starts_with("-----BEGIN QSSH PRIVATE KEY-----"));
    assert!(contents.contains("Algorithm: Falcon512"));
    assert!(contents.trim_end().ends_with("-----END QSSH PRIVATE KEY-----"));
}
