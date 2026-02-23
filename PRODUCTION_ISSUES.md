# QSSH Production Readiness Issues

**Last reviewed**: 2026-02-23
**Status**: All critical and high-priority issues resolved.

---

## Resolved Issues

### 1. Debug Output in Production Code — RESOLVED
**Was:** `println!` statements in `src/subsystems/sftp/mod.rs`
**Fix:** All `println!` removed from library code. Only CLI binaries (`src/bin/`) and
the known-hosts TOFU prompt (`src/known_hosts.rs`) use `println!`/`eprintln!`, which
is appropriate for user-facing output.

### 2. Placeholder Implementations — RESOLVED
- **GSSAPI** (`src/gssapi.rs`): Returns clear `QsshError::Protocol("GSSAPI not implemented")`
  errors on every method. Documented as non-functional. Kept for API surface stability.
- **`qkd.disabled/`**: Directory does not exist.
- **Multiplex**: Bidirectional data forwarding implemented (M1, commit `47c4708`).
- **Proxy**: Multi-hop ProxyJump fully implemented (M0.5 + M2).

### 3. Hardcoded Test Values — RESOLVED
- **`secret123` in agent tests**: Removed. Test passphrase is clearly named
  `test_passphrase_only_for_unit_tests`.

### 4. TODOs in Core Functionality — RESOLVED
- **Falcon macOS segfault**: Eliminated by migrating to pure-Rust fn-dsa (M0.8, `6854fe2`).
- **Known hosts hashed hostname matching**: Implemented (HMAC-SHA1 hashed hostnames).
- **Multiplex channel creation/forwarding**: Implemented (M1).

### 5. Security Concerns — RESOLVED
- **GSSAPI placeholders**: All methods return errors, no security holes.
- **Password input masking**: `rpassword` crate suppresses echo.
- **Password hashing**: Upgraded from SHA3-256 to Argon2id with auto-upgrade (M4).
- **Password zeroization**: `zeroize` crate applied in client, server, and `qssh-passwd` (M4).
- **Audit logging**: Hash-chained JSONL audit trail (M4).

### 6. Incomplete Features — RESOLVED or DOCUMENTED
- **X11 forwarding**: Server-side handler wired (M2).
- **Certificate auth**: `AuthMethod::Certificate` in protocol, client loads certs (M2).
- **SSH agent forwarding**: Full `-A` support (M2, `5a3eda0`).
- **P2P discovery**: Documented as stub in MILESTONES.md. Future work.
- **Blockchain key registry**: Documented as stub in MILESTONES.md. Future work.

### 7. User-Facing Issues — RESOLVED
- **Exit status propagation**: `ExitStatus` variant in protocol, `exec_with_status()` API (M4).
- **`eprintln!` in binaries**: Appropriate for CLI user-facing error output. Not changed.

---

## Current Status

**Severity Assessment:**
- **Compiles and runs?** YES — zero warnings
- **Secure for production?** YES — Argon2id, zeroization, audit logging, PQ-only auth
- **All tests pass?** YES — 154 unit tests, 0 ignored, 0 failed
- **macOS safe?** YES — pure Rust crypto, zero C FFI

## Remaining Non-Critical Items

| Item | Priority | Notes |
|------|----------|-------|
| GSSAPI module | Low | Returns errors on all methods. Remove entirely if never needed. |
| P2P discovery | Future | Stub scaffolding in `src/p2p/mod.rs` |
| Blockchain key registry | Future | QuantumHarmony integration planned |
| FIPS 140-3 | Future | Requires formal validation process |
