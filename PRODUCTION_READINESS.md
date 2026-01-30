# QSSH Production Readiness Guide

## Overview

QSSH (Quantum-Secure Shell) is a post-quantum cryptographic replacement for SSH, designed to resist attacks from both classical and quantum computers.

## Current Status: Beta

**Version**: 1.0.0
**Last Updated**: January 2026

### Production-Ready Features

| Feature | Status | Notes |
|---------|--------|-------|
| PQ Key Exchange | ✅ Ready | SPHINCS+ and Falcon-512/1024 |
| AES-256-GCM Encryption | ✅ Ready | NIST-approved symmetric crypto |
| Session Resumption | ✅ Ready | Proper HKDF key derivation |
| Local Port Forwarding (-L) | ✅ Ready | Full implementation |
| Dynamic Port Forwarding (-D) | ✅ Ready | SOCKS5 proxy support |
| Security Tiers (T0-T5) | ✅ Ready | Configurable threat models |
| 768-byte Quantum Frames | ✅ Ready | Traffic analysis resistance |
| Connection Multiplexing | ✅ Ready | SSH-style ControlMaster |
| Quantum Transport KEM | ✅ Ready | Bidirectional key exchange |

### Known Limitations

| Feature | Status | Workaround |
|---------|--------|------------|
| Falcon on macOS | ⚠️ Segfault | Use SPHINCS+ or run on Linux |
| Remote Port Forwarding (-R) | 🚧 Partial | Use local forwarding |
| ProxyJump | 🚧 Partial | Use direct connections |
| X11 Forwarding | 🚧 Partial | Use X11 over port forward |
| GSSAPI/Kerberos | ❌ Not Implemented | Use password/key auth |

## Security Architecture

### Cryptographic Algorithms

```
┌─────────────────────────────────────────────────────────┐
│                    QSSH Crypto Stack                     │
├─────────────────────────────────────────────────────────┤
│  Key Exchange    │  SPHINCS+ (hash-based, NIST Level 1) │
│                  │  Falcon-512 (NTRU lattice)            │
│                  │  Falcon-1024 (NTRU, NIST Level 5)     │
├──────────────────┼──────────────────────────────────────┤
│  Symmetric       │  AES-256-GCM (authenticated)          │
├──────────────────┼──────────────────────────────────────┤
│  Key Derivation  │  HKDF-SHA256                          │
├──────────────────┼──────────────────────────────────────┤
│  Integrity       │  SHA3-256, HMAC-SHA256                │
└──────────────────┴──────────────────────────────────────┘
```

### Security Tiers

| Tier | Name | Use Case | Features |
|------|------|----------|----------|
| T0 | Classical | Legacy only | RSA/ECDSA (deprecated) |
| T1 | Post-Quantum | Standard | PQ algorithms, variable frames |
| T2 | Hardened PQ | **Default** | PQ + 768-byte fixed frames |
| T3 | Entropy-Enhanced | High security | T2 + QRNG entropy |
| T4 | Quantum-Secured | Critical infra | T3 + QKD keys |
| T5 | Hybrid Quantum | Nation-state | All layers combined |

### Frame Format (768 bytes, fixed)

```
┌────────────────────────────────────────────────┐
│  Header (17 bytes)                             │
│  ├── Sequence Number (8 bytes)                 │
│  ├── Timestamp (8 bytes)                       │
│  └── Frame Type (1 byte)                       │
├────────────────────────────────────────────────┤
│  Payload (719 bytes, padded)                   │
│  ├── Length Prefix (2 bytes)                   │
│  └── Data + Padding (717 bytes)                │
├────────────────────────────────────────────────┤
│  MAC (32 bytes)                                │
└────────────────────────────────────────────────┘
```

All frames are exactly 768 bytes, making traffic analysis infeasible.

## Deployment

### System Requirements

- **OS**: Linux (recommended), macOS (limited Falcon support)
- **Rust**: 1.70+ for building
- **Memory**: 64MB minimum
- **Network**: TCP port 22222 (default)

### Installation

```bash
# From source
git clone https://github.com/Paraxiom/qssh.git
cd qssh
cargo build --release

# Install binaries
sudo cp target/release/qssh /usr/local/bin/
sudo cp target/release/qsshd /usr/local/bin/
sudo cp target/release/qssh-keygen /usr/local/bin/
```

### Generate Keys

```bash
# Generate Falcon-512 key (recommended for Linux)
qssh-keygen -t falcon512 -f ~/.qssh/id_falcon

# Generate SPHINCS+ key (works on all platforms)
qssh-keygen -t sphincs -f ~/.qssh/id_sphincs
```

### Server Configuration

```bash
# /etc/qssh/qsshd_config
Port 22222
PqAlgorithm falcon512
SecurityTier T2
QuantumNative yes
KeyRotationInterval 3600
```

### Client Configuration

```bash
# ~/.qssh/config
Host *
    Port 22222
    PqAlgorithm falcon512
    SecurityTier T2

Host secure-server
    Hostname 192.168.1.100
    User admin
    SecurityTier T4
    UseQkd yes
    QkdEndpoint https://qkd.example.com/api/v1/keys
```

## API Reference

### QsshConfig

```rust
pub struct QsshConfig {
    pub server: String,           // host:port
    pub username: String,
    pub password: Option<String>,
    pub port_forwards: Vec<PortForward>,
    pub use_qkd: bool,
    pub qkd_endpoint: Option<String>,
    pub pq_algorithm: PqAlgorithm,
    pub key_rotation_interval: u64,
    pub security_tier: SecurityTier,
    pub quantum_native: bool,     // 768-byte frames
}
```

### PqAlgorithm

```rust
pub enum PqAlgorithm {
    SphincsPlus,   // Hash-based, conservative
    Falcon512,     // NTRU lattice, NIST Level 1
    Falcon1024,    // NTRU lattice, NIST Level 5
}
```

### SecurityTier

```rust
pub enum SecurityTier {
    Classical,        // T0: Legacy (deprecated)
    PostQuantum,      // T1: PQ algorithms
    HardenedPQ,       // T2: PQ + fixed frames (default)
    EntropyEnhanced,  // T3: T2 + QRNG
    QuantumSecured,   // T4: T3 + QKD
    HybridQuantum,    // T5: All layers
}
```

## Testing

### Run All Tests

```bash
cargo test
```

### Test Results (January 2026)

```
Library tests:     75 passed, 4 ignored
Integration tests: 35 passed, 40 ignored (macOS pqcrypto)
Total:            110 passed, 44 ignored
```

Ignored tests are due to pqcrypto-falcon segfaults on macOS. These tests pass on Linux.

### Run on Linux (Full Coverage)

```bash
# Using Docker
docker run -v $(pwd):/app -w /app rust:latest cargo test
```

## Performance

### Handshake Latency

| Algorithm | Key Gen | Encapsulate | Decapsulate |
|-----------|---------|-------------|-------------|
| SPHINCS+ | ~50ms | ~5ms | ~5ms |
| Falcon-512 | ~10ms | ~2ms | ~2ms |
| Falcon-1024 | ~20ms | ~3ms | ~3ms |

### Throughput

| Mode | Throughput | Notes |
|------|------------|-------|
| Classical frames | ~100 MB/s | Variable size |
| Quantum frames (768B) | ~80 MB/s | Fixed size, padded |

## Monitoring

### Metrics

QSSH exposes the following metrics:

- `qssh_connections_total` - Total connections
- `qssh_handshake_duration_seconds` - Handshake time
- `qssh_bytes_transferred` - Data transferred
- `qssh_key_rotations` - Key rotation events
- `qssh_security_tier` - Active security tier

### Logging

```bash
# Enable debug logging
RUST_LOG=debug qssh user@host

# Log to file
RUST_LOG=info qssh user@host 2>> /var/log/qssh.log
```

## Troubleshooting

### Falcon Segfault on macOS

**Symptom**: Crash during key generation or handshake on macOS.

**Cause**: pqcrypto-falcon library has memory issues on macOS.

**Solution**:
```bash
# Use SPHINCS+ instead
qssh --pq-algo sphincs user@host

# Or set in config
echo "PqAlgorithm sphincs" >> ~/.qssh/config
```

### Connection Timeout

**Symptom**: Handshake times out after 30 seconds.

**Cause**: Firewall blocking port 22222 or server not running.

**Solution**:
```bash
# Check server is running
ss -tlnp | grep 22222

# Check firewall
sudo ufw allow 22222/tcp
```

### Key Rotation Failures

**Symptom**: "Key rotation failed" in logs.

**Cause**: QKD endpoint unreachable or certificate issues.

**Solution**:
```bash
# Verify QKD endpoint
curl -v https://qkd.example.com/api/v1/keys/status

# Check certificates
openssl verify -CAfile /etc/qssh/qkd-ca.pem /etc/qssh/qkd-cert.pem
```

## Security Considerations

### Key Storage

- Private keys stored with mode 0600
- Session keys zeroed after use (zeroize crate)
- No keys logged or printed

### Network Security

- All traffic encrypted with AES-256-GCM
- Sequence numbers prevent replay attacks
- Fixed frame sizes prevent traffic analysis

### Quantum Resistance

- SPHINCS+ provides hash-based security (no lattice assumptions)
- Falcon provides efficient lattice-based security
- Hybrid mode uses both for defense in depth

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

MIT OR Apache-2.0

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [SPHINCS+ Specification](https://sphincs.org/)
- [Falcon Specification](https://falcon-sign.info/)
- [ETSI QKD API](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/)
