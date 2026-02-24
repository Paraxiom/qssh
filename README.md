# QSSH - Quantum-Resistant Secure Shell

[![Crates.io](https://img.shields.io/crates/v/qssh.svg)](https://crates.io/crates/qssh)
[![Documentation](https://docs.rs/qssh/badge.svg)](https://docs.rs/qssh)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)

**Post-quantum secure shell** implementing NIST-standardized algorithms (Falcon-512, SPHINCS+, ML-KEM) with quantum-resistant protocol design. **Pure Rust** — zero C FFI, zero `unsafe` in crypto paths. Built for organizations preparing for the post-quantum transition.

## Security Status

| Component | Status | Details |
|-----------|--------|---------|
| **NIST PQC Algorithms** | Implemented | Falcon-512 (fn-dsa), SPHINCS+ (slh-dsa), ML-KEM |
| **Crypto Backend** | Pure Rust | Zero C FFI — fn-dsa 0.3 + slh-dsa 0.0.3 + ml-kem |
| **Protocol Hardening** | Implemented | 768-byte uniform frames, no metadata leakage |
| **Test Coverage** | 229 tests | 154 unit + 75 integration, 0 ignored, 0 warnings |
| **Production Hardening** | Implemented | Argon2id passwords, audit logging, zeroization |
| **Formal Verification** | Complete | 3-tier: Kani (30) + Verus (20) + Lean 4 (67 theorems) |
| **Formal Security Audit** | Not yet performed | Recommended before production deployment |

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

**All core SSH features implemented** (+ PQ-specific extras)

### Core SSH
- Interactive shell sessions with PTY support + SIGWINCH resize
- Command execution (`qssh user@host -c "command"`) with exit status propagation
- Post-quantum key exchange (Falcon-512, SPHINCS+, ML-KEM) — pure Rust
- SFTP file transfer (SFTPv3 subsystem + `qscp` client)
- Port forwarding (-L local, -R remote, -D dynamic/SOCKS5)
- ProxyJump (`-J user@jumphost`) with multi-hop chaining
- SSH agent forwarding (`-A`) with per-session sockets
- Config file parsing (~/.qssh/config with Host stanzas)
- Public key authentication (PQ-only), password auth (Argon2id)
- Certificate-based authentication
- SSH agent support (qssh-agent, qssh-add)
- X11 forwarding (-X, -Y)
- Connection multiplexing (-S ControlMaster/ControlClient)
- Known hosts management (TOFU with hashed hostnames)
- Compression (zlib, zstd, lz4)
- Session resumption (ticket encryption with HMAC-SHA256)
- Auto-reconnect with exponential backoff (--persistent)
- Automatic key rotation (configurable interval)
- Server daemonization (--daemon, PID file, double-fork)

### PQ-Specific
- 768-byte uniform quantum frames (traffic analysis resistance)
- Security tiers T0-T5 (configurable threat model)
- QRNG entropy integration (T3+)
- QKD integration via ETSI API (T4+)
- BB84 protocol with noise model and QBER tracking
- HSM key storage backend (Software, File, PKCS#11)
- Hash-chained JSONL audit logging
- Password zeroization (zeroize crate)

### Operator Tools
- Signing service (qssh-sign, vault + Lamport OTS)
- One-liner node connect (qssh-node, auto-binds standard ports)
- Key generation (qssh-keygen — Falcon-512 + SPHINCS+)
- Password management (qssh-passwd with Argon2id)

### Not Implemented
- GSSAPI/Kerberos authentication (stub, feature-gated)
- FIPS 140-3 validation (requires formal process)

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

| Component | Default | Crate | NIST Status |
|-----------|---------|-------|-------------|
| Signatures | Falcon-512 | fn-dsa 0.3 (Thomas Pornin) | FIPS 204 |
| Signatures | SPHINCS+-SHA2-128s | slh-dsa 0.0.3 (RustCrypto) | FIPS 205 |
| Key Exchange | ML-KEM-768 | ml-kem (RustCrypto) | FIPS 203 |
| Encryption | AES-256-GCM | aes-gcm | FIPS 197 |
| KDF | HKDF-SHA256 | hkdf | SP 800-56C |
| Password Hash | Argon2id | argon2 | RFC 9106 |

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

- **Not wire-compatible with OpenSSH** — custom binary protocol over TCP
- **PQ-only authentication** — no RSA/ECDSA acceptance (by design)
- **Default port 22222** — avoids conflict with system sshd
- **PQC signatures larger and slower than classical** — expected tradeoff for quantum resistance

## Formal Verification

3-tier verification pipeline — zero sorries, zero axiomatized transcendentals.

| Tier | Tool | Scope | Count |
|------|------|-------|-------|
| **Tier 1** | Kani (AWS) | Panic-freedom, integer overflow, UB | 30 harnesses |
| **Tier 2** | Verus (MSR) | Functional correctness via Z3 | 20 proofs |
| **Tier 3** | Lean 4 + Mathlib | Mathematical foundations | 67 theorems |

**Lean 4 proof files** (`lean/QSSHProofs/`):
- `MLKem.lean` — q=3329 is prime, NTT compatibility (q % 256 = 1), Z_3329 field instance, ML-KEM-768/1024 parameter bounds
- `Transport.lean` — 768-byte uniform frame properties, padding bounds, information-theoretic frame security
- `KDF.lean` — HKDF-SHA256 entropy preservation, key independence, KDF chain composition
- `Falcon.lean` — q=12289 is prime, NTT compatibility (q % 512 = 1), signature size bounds, Falcon vs SPHINCS+ ratios
- `Sphincs.lean` — SPHINCS+-SHAKE-256s parameters, 128-bit PQ security (Grover), statelessness, frame fitting
- `Handshake.lean` — Hybrid KEM composition, forward secrecy chain length

```bash
cd lean && lake build  # 0 errors, 0 sorries
```

**Paper**: [162 Lean 4 Theorems for Post-Quantum Infrastructure](https://doi.org/10.5281/zenodo.18663125) (Zenodo, Feb 2026)

## Roadmap

- [x] Certificate-based authentication
- [x] HSM key storage backend
- [x] SSH agent forwarding
- [x] Audit logging (hash-chained JSONL)
- [x] Argon2id password hashing
- [ ] Formal security audit
- [ ] FIPS 140-3 validation
- [ ] P2P discovery
- [ ] Blockchain-based key registry (QuantumHarmony)

## Documentation

- [API Documentation](https://docs.rs/qssh)
- [Production Readiness](PRODUCTION_READINESS.md)
- [Milestones & Roadmap](MILESTONES.md)
- [Changelog](CHANGELOG.md)

## License

Licensed under either:
- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Acknowledgments

- NIST Post-Quantum Cryptography standardization team
- [fn-dsa](https://crates.io/crates/fn-dsa) — Thomas Pornin's pure-Rust Falcon implementation
- [slh-dsa](https://crates.io/crates/slh-dsa) — RustCrypto SPHINCS+ implementation
- [ml-kem](https://crates.io/crates/ml-kem) — RustCrypto ML-KEM implementation
- Signal Protocol research (SPQR, Triple Ratchet)
- QuantumHarmony blockchain integration

---

*Building quantum-resistant infrastructure for the post-quantum era.*
