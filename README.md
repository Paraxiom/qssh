# QSSH - Quantum-Resistant Secure Shell

[![Crates.io](https://img.shields.io/crates/v/qssh.svg)](https://crates.io/crates/qssh)
[![Documentation](https://docs.rs/qssh/badge.svg)](https://docs.rs/qssh)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)

**Post-quantum secure shell** implementing NIST-standardized algorithms (Falcon, SPHINCS+, ML-KEM) with quantum-resistant protocol design. Built for organizations preparing for the post-quantum transition.

## Security Status

| Component | Status | Details |
|-----------|--------|---------|
| **NIST PQC Algorithms** | Implemented | Falcon-512/1024, SPHINCS+-SHA256, ML-KEM |
| **Protocol Hardening** | Implemented | 768-byte uniform frames, no metadata leakage |
| **Test Coverage** | 110 tests | 75 library + 35 integration tests passing |
| **Production Hardening** | Implemented | No panics in production paths, proper error handling |
| **Formal Security Audit** | Not yet performed | Recommended before production deployment |
| **Formal Verification** | Planned | ProVerif/F* models in roadmap |

**Recommendation**: Suitable for research, testing, PQC migration planning, and non-production environments. Security audit recommended before deployment with sensitive data.

## Why QSSH?

**The Quantum Threat Timeline**:
- IBM roadmap: 100,000+ qubit systems by 2033
- NIST mandate: Federal PQC migration required by 2035
- **"Harvest now, decrypt later"**: Adversaries capturing encrypted traffic today for future decryption

**Who Should Evaluate QSSH**:
- Financial institutions with 10+ year data retention requirements
- Healthcare systems bound by HIPAA's 6-year minimum
- Government contractors under NIST PQC migration mandate
- Organizations with long-lived cryptographic keys
- Security teams planning PQC migration strategies

## Security Tiers

QSSH implements configurable security tiers based on threat model:

| Tier | Name | Description | Use Case |
|------|------|-------------|----------|
| T0 | Classical | RSA/ECDSA (deprecated) | Legacy compatibility only |
| T1 | Post-Quantum | PQC algorithms | Basic quantum resistance |
| T2 | Hardened PQ | 768-byte fixed frames | Traffic analysis resistance (default) |
| T3 | Entropy-Enhanced | T2 + QRNG | High-assurance environments |
| T4 | Quantum-Secured | T3 + QKD | Critical infrastructure |
| T5 | Hybrid Quantum | All layers quantum-secured | Maximum assurance |

## The Quantum-Resistant Difference

### Traditional "Quantum-Safe" Approach
```
Classical SSH Protocol + Post-Quantum Algorithms = "Quantum-Safe"
ClientHello (215 bytes) → ServerHello (312 bytes) → KeyExchange (1847 bytes)
↑ Variable-length messages leak metadata
```

### QSSH Quantum-Resistant Approach
```
→→→→→→→→→→→→→→→→→→→→→ (uniform 768-byte frames)
←←←←←←←←←←←←←←←←←← (continuous obfuscated stream)
↑ All traffic indistinguishable
```

**Key Design Decisions**:
- **Indistinguishable Frames**: All traffic exactly 768 bytes
- **Proper KEM Usage**: ML-KEM for key exchange, signatures for authentication
- **Traffic Analysis Resistance**: No metadata leakage from message sizes
- **Defense in Depth**: Multiple quantum-safe algorithm options

## Quick Start

```bash
# Install from crates.io
cargo install qssh

# Or build from source
git clone https://github.com/Paraxiom/qssh
cd qssh
cargo build --release

# Generate quantum-safe keys
qssh-keygen

# Connect (works like SSH)
qssh user@server

# Server daemon
qsshd --security-tier t2
```

## Feature Status

**17/19 core SSH features implemented**

### Implemented
- Interactive shell sessions with PTY support
- Command execution (`qssh user@host -c "command"`)
- Post-quantum key exchange (Falcon-512, SPHINCS+)
- SFTP file transfer
- Port forwarding (-L local, -R remote, -D dynamic/SOCKS)
- Config file parsing (~/.qssh/config)
- Public key and password authentication
- SSH agent support (qssh-agent, qssh-add)
- X11 forwarding (-X, -Y)
- Connection multiplexing (ControlMaster/ControlPath)
- ProxyJump multi-hop connections
- Known hosts management (TOFU)
- Compression (zlib, zstd, lz4)
- Session resumption

### In Development
- Certificate-based authentication
- GSSAPI/Kerberos authentication

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Security Tiers                           │
├─────────────────────────────────────────────────────────────────┤
│  T0: Classical  │  T1: PQ  │  T2: Hardened  │  T3-T5: Quantum  │
└────────┬────────┴────┬─────┴───────┬────────┴────────┬─────────┘
         │             │             │                  │
         ▼             ▼             ▼                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                      QSSH Protocol Layer                        │
├─────────────────────────────────────────────────────────────────┤
│  Falcon-512/1024  │  SPHINCS+-SHA256  │  ML-KEM  │  AES-256-GCM │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│              Quantum-Resistant Transport (T2+)                  │
├─────────────────────────────────────────────────────────────────┤
│  768-byte uniform frames  │  Traffic obfuscation  │  No leakage │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Optional Quantum Hardware                    │
├─────────────────────────────────────────────────────────────────┤
│         QRNG (T3+)        │           QKD (T4+)                 │
└─────────────────────────────────────────────────────────────────┘
```

## Cryptographic Algorithms

| Component | Default | Alternative | NIST Status |
|-----------|---------|-------------|-------------|
| Signatures | Falcon-512 | SPHINCS+-SHA256 | FIPS 204, 205 |
| Key Exchange | ML-KEM-768 | ML-KEM-1024 | FIPS 203 |
| Encryption | AES-256-GCM | ChaCha20-Poly1305 | FIPS 197 |
| KDF | HKDF-SHA256 | SHA3-256 | SP 800-56C |

## Performance

| Operation | Falcon-512 | SPHINCS+ | RSA-2048 |
|-----------|------------|----------|----------|
| Key Generation | 0.8ms | 3.2ms | 84ms |
| Sign | 0.4ms | 5.1ms | 1.2ms |
| Verify | 0.1ms | 2.4ms | 0.04ms |
| Full Handshake | 3.2ms | 14ms | 5.6ms |

*Benchmarks on Intel i7-10700K. Falcon recommended for performance-sensitive applications.*

## Configuration

### Client Config (~/.qssh/config)

```ssh-config
Host production
    Hostname prod.example.com
    User admin
    PqAlgorithm falcon-512
    SecurityTier t2

Host critical
    Hostname critical.example.com
    SecurityTier t4
    RequireQKD yes
```

### Environment Variables

```bash
export QSSH_SECURITY_TIER=t2
export QSSH_ALGORITHM=falcon-512
export QSSH_QKD_ENDPOINT=qkd://alice.quantum.net
```

## Integration

### As a Library

```rust
use qssh::{QsshClient, QsshConfig, SecurityTier, PqAlgorithm};

let config = QsshConfig {
    server: "server.example.com".to_string(),
    username: "admin".to_string(),
    security_tier: SecurityTier::HardenedPQ,  // T2
    pq_algorithm: PqAlgorithm::Falcon512,
    ..Default::default()
};

let mut client = QsshClient::new(config);
client.connect().await?;
```

### With qcomm-core (PQ Triple Ratchet)

QSSH integrates with [qcomm-core](https://github.com/Paraxiom/drista) for Signal SPQR-aligned triple ratchet messaging:

```rust
use qcomm_core::crypto::{PqTripleRatchet, RatchetConfig};
use qssh::{QsshClient, SecurityTier};

// Establish QSSH tunnel
let client = QsshClient::new(config);
client.connect().await?;

// Layer triple ratchet for forward-secure messaging
let ratchet = PqTripleRatchet::init_initiator_with_config(
    shared_secret,
    their_public_key,
    RatchetConfig::sparse(50),  // SPQR-style epoch ratcheting
)?;
```

## Known Limitations

- **Falcon on macOS**: pqcrypto library segfaults on some macOS versions (use SPHINCS+ as workaround)
- **No SSH Agent Forwarding**: Security review pending
- **Performance**: PQC signatures larger and slower than classical (expected tradeoff)

## Roadmap

- [ ] Formal security audit
- [ ] ProVerif protocol verification
- [ ] Certificate-based authentication
- [ ] Hardware security module (HSM) integration
- [ ] FIPS 140-3 validation path

## Documentation

- [API Documentation](https://docs.rs/qssh)
- [Quantum-Native Paradigm](QUANTUM_NATIVE_PARADIGM.md)
- [Production Readiness](PRODUCTION_READINESS.md)
- [Changelog](CHANGELOG.md)

## License

Licensed under either:
- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Acknowledgments

- NIST Post-Quantum Cryptography standardization team
- Signal Protocol research (SPQR, Triple Ratchet)
- PQClean reference implementations
- QuantumHarmony blockchain integration

---

*Building quantum-resistant infrastructure for the post-quantum era.*
