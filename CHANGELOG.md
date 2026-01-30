# Changelog

All notable changes to QSSH are documented in this file.

## [1.0.0] - 2026-01-30

### Added

- **Security Tiers (T0-T5)**: Configurable security levels based on threat model
  - T0: Classical (deprecated, for compatibility only)
  - T1: Post-Quantum algorithms
  - T2: Hardened PQ with 768-byte fixed frames (default)
  - T3: Entropy-Enhanced with QRNG
  - T4: Quantum-Secured with QKD
  - T5: Hybrid Quantum (all layers)

- **Connection Multiplexing**: Full SSH-style ControlMaster implementation
  - `create_channel()`: Proper SSH_MSG_CHANNEL_OPEN handling
  - `forward_to_channel()`: Data chunking per SSH limits
  - Graceful shutdown with cleanup
  - 11 new tests for multiplexing

- **Quantum Transport KEM**: Complete bidirectional key exchange
  - Client-side encapsulation with network transmission
  - Server-side decapsulation with proper validation
  - HKDF-SHA256 key derivation with domain separation
  - DoS protection (ciphertext size validation)

- **Session Encryption**: Production-ready session state protection
  - HKDF-based session key derivation
  - AES-256-GCM authenticated encryption
  - Proper salt and nonce generation

- **Production Documentation**: `PRODUCTION_READINESS.md`
  - Deployment guide
  - API reference
  - Security architecture
  - Troubleshooting guide

### Fixed

- **DirectTcpipChannel::into_stream()**: Returns `Result` instead of `panic!`
- **qssh-keygen**: Handles all PqAlgorithm variants (Falcon512, Falcon1024, SPHINCS+)
- **Session keys**: No longer uses placeholder zeros
- **Session state encryption**: Actually encrypts (was returning plaintext)

### Changed

- Moved Drista integration to separate repository (github.com/Paraxiom/drista)
- Renamed `quantum_native` module to `quantum_resistant` for accuracy
- Default security tier is now T2 (HardenedPQ)

### Security

- All panic! calls removed from production code paths
- Session encryption uses proper cryptographic primitives
- KEM handshake includes DoS protection
- Fixed frame sizes (768 bytes) for traffic analysis resistance

### Known Issues

- Falcon algorithm segfaults on macOS (pqcrypto library issue)
  - Workaround: Use SPHINCS+ on macOS
  - Tests pass on Linux
- Remote port forwarding (-R) partially implemented
- ProxyJump/ProxyCommand incomplete
- X11 forwarding transport mock needed

### Test Coverage

- Library: 75 tests passing, 4 ignored (macOS pqcrypto)
- Integration: 35 tests passing, 40 ignored (macOS pqcrypto)
- Total: 110 tests passing

## [0.9.0] - 2026-01-27

### Added

- Initial quantum-native transport with 768-byte frames
- SPHINCS+ and Falcon signature support
- Basic QKD integration
- Port forwarding (local and dynamic)

### Security

- Removed vulnerable Kyber algorithms (KyberSlash)
- Added replay attack protection with sequence numbers
