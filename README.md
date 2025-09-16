# QSSH - Quantum Secure Shell

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)

Quantum-resistant SSH replacement using post-quantum cryptography. Your encrypted connections remain secure even against quantum computers.

## Why QSSH?

RSA and ECDSA encryption will be broken by quantum computers in 5-10 years. Your SSH sessions are being recorded today for future decryption ("harvest now, decrypt later" attacks). QSSH provides immediate protection using lattice-based cryptography that resists quantum attacks, while seamlessly integrating with quantum key distribution networks and hardware entropy sources.

## Ecosystem Positioning

QSSH is part of a comprehensive post-quantum security ecosystem:

- **Application Layer (QSSH)**: Provides SSH-specific PQ features with QKD/QRNG integration
- **Network Layer (PQConnect)**: Transparent PQ protection for all traffic (complementary, not competitive)
- **Infrastructure (PQ-QKD-Proxy)**: Secures QKD hardware APIs from quantum attacks

See [architecture/ecosystem-comparison.md](docs/architecture/ecosystem-comparison.md) for detailed analysis of how QSSH works with PQConnect and other PQ solutions.

## Quick Start

```bash
# Install
cargo install qssh

# Generate quantum-safe keys
qssh-keygen

# Connect (just like SSH)
qssh user@server
```

That's it! You're now quantum-safe with zero configuration.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Advanced Configuration](#advanced-configuration)
- [P2P Mode](#p2p-mode)
- [Testing](#testing)
- [Development](#development)
- [Performance](#performance)
- [Contributing](#contributing)

## OpenSSH Feature Parity Status

**Current: 100% Feature Parity** 🎉 (19/19 core SSH features)

### ✅ Implemented (Phase 1 - Core)
- [x] Basic SSH connection and authentication
- [x] Interactive shell sessions with PTY support
- [x] Command execution (`qssh user@host -c "command"`)
- [x] Post-quantum key exchange (Falcon-512, SPHINCS+, Kyber)
- [x] **SFTP subsystem** (file transfer protocol)
- [x] **Port forwarding** (-L local, -R remote, -D dynamic/SOCKS)
- [x] **Config file parsing** (~/.qssh/config compatible with SSH format)
- [x] Public key authentication
- [x] Key generation (qssh-keygen)

### ✅ Implemented (Phase 2 - Extended)
- [x] **Password authentication** (with qssh-passwd utility)
- [x] **SSH agent support** (qssh-agent and qssh-add utilities)
- [x] **X11 forwarding** (-X for untrusted, -Y for trusted)

### ✅ Implemented (Phase 2 - Extended Continued)
- [x] **Connection multiplexing** (ControlMaster/ControlPath support)
- [x] **ProxyJump support** (multi-hop connections through jump hosts)

### ✅ Implemented (Phase 3 - Security)
- [x] **Known hosts management** (host key verification with TOFU)

### ✅ Implemented (Phase 3 - Advanced)
- [x] **Compression** (zlib, zstd, lz4 with adaptive compression)
- [x] **Session resumption** (fast reconnection for mobile networks)

### ✅ Implemented (Phase 3 - Advanced Continued)
- [x] **Certificate-based authentication** (CA-signed certificates with post-quantum signatures)
- [x] **GSSAPI/Kerberos authentication** (Enterprise SSO support)

## Features

### Core Security
- **Post-Quantum Algorithms**: Falcon-512 (default), SPHINCS+, custom providers
- **Quantum Integration**: QKD networks, QRNG devices, hardware security modules
- **Forward Secrecy**: Double Ratchet protocol with automatic key rotation
- **Zero-Trust**: No default trust, all peers authenticated

### Compatibility
- **Drop-in Replacement**: Works like SSH, same commands
- **Cross-Platform**: Linux, macOS, Windows
- **Standard Protocols**: SSH-compatible authorized_keys format

### Advanced Features
- **P2P Mode**: Direct peer connections without central servers
- **Modular Crypto**: Plug in any post-quantum algorithm
- **Blockchain Integration**: QuantumHarmony validator discovery
- **Hardware Support**: TPM, HSM, PKCS#11 tokens

## Installation

### From Source
```bash
git clone https://github.com/QuantumVerseProtocols/qssh
cd qssh
cargo build --release
sudo cp target/release/qssh* /usr/local/bin/
```

### Package Managers
```bash
# Arch Linux
yay -S qssh

# macOS
brew install qssh

# Debian/Ubuntu
sudo apt install qssh
```

## Basic Usage

### Configuration File

QSSH supports configuration files similar to OpenSSH. Place your config at `~/.qssh/config`:

```ssh-config
# Example ~/.qssh/config
Host myserver
    Hostname server.example.com
    User myuser
    Port 22222
    PqAlgorithm falcon
    LocalForward 8080:localhost:80

Host *.internal
    User admin
    PqAlgorithm kyber1024
```

Then connect simply with:
```bash
qssh myserver
```

See [example.qssh.config](example.qssh.config) for a complete configuration example.

## Basic Commands

### Generate Keys
```bash
# Default (Falcon-512)
qssh-keygen

# SPHINCS+ for maximum security
qssh-keygen -t sphincs+

# Custom output location
qssh-keygen -f ~/.qssh/id_production
```

### Password Management
```bash
# Set password for user (server-side)
sudo qssh-passwd username

# Verify password
qssh-passwd -c username
```

### Connect to Server
```bash
# Standard connection (with public key)
qssh user@quantum.example.com

# Password authentication
qssh -P user@quantum.example.com

# Custom port
qssh user@quantum.example.com:42

# Execute command
qssh user@server "df -h"

# Interactive shell with verbosity
qssh -v user@server
```

### File Transfer
```bash
# Copy local to remote
qscp report.pdf user@server:/home/user/

# Copy remote to local
qscp user@server:/data/results.csv ./

# Recursive copy
qscp -r ./project user@server:/deploy/
```

### Server Setup
```bash
# Start daemon (default port 42)
qsshd

# Custom configuration
qsshd --listen :22 --max-connections 1000

# With quantum devices
qsshd --qkd qkd://alice.local --qrng /dev/qrandom
```

## Architecture

### Quantum Pipeline
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Quantum Devices │     │   QKD Network   │     │  QRNG Sources   │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ • Photon pairs  │     │ • Alice node    │     │ • Quantum decay │
│ • Entangled     │────▶│ • Bob node      │     │ • Shot noise    │
│ • Single photon │     │ • ETSI API      │     │ • Vacuum noise  │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                         │
         └───────────────────────┴─────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      QSSH Protocol      │
                    ├─────────────────────────┤
                    │ • Falcon-512 (default)  │
                    │ • SPHINCS+ (optional)   │
                    │ • Custom providers      │
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┴─────────────────────────┐
         │                                                 │
┌────────▼────────┐                              ┌─────────▼────────┐
│   Your Device   │                              │  Remote Server   │
├─────────────────┤                              ├──────────────────┤
│ qssh client     │◄────── Encrypted Channel ───►│ qsshd daemon     │
└─────────────────┘         (TCP Port 42)        └──────────────────┘
```

### OSI Model Integration
```
┌─────────────────────────────────────────────────────┐
│ Layer 7 - Application │ Shell, SFTP, Port Forward   │
├───────────────────────┼─────────────────────────────┤
│ Layer 6 - Presentation│ QSSH Protocol               │
│                       │ • Post-quantum crypto       │
│                       │ • Key exchange & auth       │
├───────────────────────┼─────────────────────────────┤
│ Layer 5 - Session     │ Channel multiplexing        │
├───────────────────────┼─────────────────────────────┤
│ Layer 4 - Transport   │ TCP (Port 42 default)       │
├───────────────────────┼─────────────────────────────┤
│ Layer 3 - Network     │ IP (IPv4/IPv6)              │
├───────────────────────┼─────────────────────────────┤
│ Layer 2 - Data Link   │ Ethernet/WiFi               │
├───────────────────────┼─────────────────────────────┤
│ Layer 1 - Physical    │ Cable/Radio/Fiber           │
└─────────────────────────────────────────────────────┘
```

### Protocol Flow
1. **TCP Connection**: Client connects to server port 42
2. **Version Exchange**: Protocol version negotiation
3. **Algorithm Selection**: Choose quantum-safe algorithms
4. **Key Exchange**: Falcon-512 signed ephemeral keys
5. **Authentication**: SPHINCS+ signature verification
6. **Session Establishment**: AES-256-GCM encrypted channel
7. **Key Rotation**: Double Ratchet for forward secrecy

## Security Model

### Cryptographic Algorithms

| Component | Default | Alternative | Purpose |
|-----------|---------|-------------|---------|
| Key Exchange | Falcon-512 | SPHINCS+, Custom | Fast ephemeral keys |
| Signatures | Falcon-512 | SPHINCS+, Lamport | Authentication |
| Encryption | AES-256-GCM | ChaCha20-Poly1305 | Channel encryption |
| KDF | SHA3-256 | SHAKE256 | Key derivation |
| Random | QRNG→System | /dev/urandom | Nonce generation |

### Security Levels

- **Level 1 (128-bit)**: Falcon-512, AES-128
- **Level 3 (192-bit)**: Falcon-768, AES-192  
- **Level 5 (256-bit)**: Falcon-1024, AES-256, SPHINCS+

### Threat Model

QSSH protects against:
- **Quantum attacks**: Shor's algorithm (RSA/ECDSA break)
- **Classical attacks**: Lattice reduction, collision finding
- **Implementation attacks**: Side channels, timing attacks
- **Network attacks**: MITM, replay, downgrade

## Advanced Configuration

### Configuration Files

`~/.qssh/config.toml`:
```toml
[defaults]
algorithm = "falcon-512"
port = 42
compression = true
keepalive = 60

[hosts."*.quantum.net"]
algorithm = "sphincs+"
use_qkd = true
forward_agent = true

[hosts."critical.server"]
require_qkd = true
require_lamport = true
min_entropy = 256
```

### Environment Variables
```bash
export QSSH_ALGORITHM=falcon-512
export QSSH_QKD_ENDPOINT=qkd://alice.quantum.net
export QSSH_QRNG_SOURCE=/dev/qrandom
export QSSH_LOG_LEVEL=debug
```

### Quantum Device Integration

#### QKD (Quantum Key Distribution)
```bash
# Connect with QKD
qssh --qkd qkd://alice.local/api user@server

# Require QKD
qssh --require-qkd user@critical.server

# QKD with fallback
qssh --qkd-fallback user@server
```

#### QRNG (Quantum Random Number Generator)
```bash
# Local quantum device
qsshd --qrng /dev/qrandom

# Network QRNG
qsshd --qrng kirq://entropy.hub:8080

# Multiple sources
qsshd --qrng /dev/qrandom,kirq://backup.net
```

### Port Forwarding

```bash
# Local forward (access remote service locally)
qssh -L 5432:db.internal:5432 user@gateway

# Remote forward (expose local service remotely)  
qssh -R 8080:localhost:3000 user@public.server

# Dynamic SOCKS proxy
qssh -D 1080 user@gateway

# Multiple forwards
qssh -L 3306:mysql:3306 -L 5432:postgres:5432 user@server
```

## P2P Mode

Decentralized operation without daemons:

### Basic P2P
```bash
# Start P2P listener
qssh --p2p --listen

# Connect to peer
qssh --p2p alice@192.168.1.100

# Discover peers
qssh --p2p --discover
```

### P2P with NAT Traversal
```bash
# Enable STUN
qssh --p2p --stun stun.l.google.com:19302

# Use TURN relay
qssh --p2p --turn turn.example.com --turn-user alice
```

### Blockchain Discovery
```bash
# Use QuantumHarmony validators
qssh --p2p --blockchain harmony://mainnet
```

## Testing

### Running Tests
```bash
# All tests
cargo test

# Unit tests only
cargo test --lib

# Integration tests
cargo test --test integration

# Specific test
cargo test test_handshake

# With output
cargo test -- --nocapture

# Parallel tests
cargo test -- --test-threads=8
```

### Test Categories

#### Unit Tests (`src/*/mod.rs`)
- Crypto primitives
- Protocol messages  
- Key derivation
- Serialization

#### Integration Tests (`tests/`)
- Client-server handshake
- Key exchange protocols
- Channel multiplexing
- Error handling

#### Quantum Tests (`tests/quantum_tests.rs`)
- QKD integration
- QRNG functionality
- Lamport signatures
- Double Ratchet

#### Performance Tests (`benches/`)
```bash
# Run benchmarks
cargo bench

# Specific benchmark
cargo bench handshake

# Compare implementations
cargo bench --bench crypto_bench
```

### Test Coverage
```bash
# Generate coverage report
cargo tarpaulin --out Html

# With branch coverage
cargo tarpaulin --branch --out Lcov
```

## Development

### Building from Source

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# All targets
cargo build --all-targets

# With features
cargo build --features "qkd,hardware"
```

### Adding Custom Algorithms

1. **Implement CryptoProvider trait**:
```rust
use qssh::crypto::{CryptoProvider, AlgorithmInfo};

pub struct MyAlgorithm;

#[async_trait]
impl CryptoProvider for MyAlgorithm {
    fn name(&self) -> &str { "my-algo" }
    
    async fn generate_keypair(&self, algorithm: &str) -> Result<KeyPair> {
        // Your implementation
    }
    
    async fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        // Your implementation
    }
}
```

2. **Register provider**:
```rust
let mut registry = CryptoRegistry::new();
registry.register(Box::new(MyAlgorithm));
```

3. **Use it**:
```bash
qssh --algorithm my-algo user@server
```

### Debugging

```bash
# Verbose output
qssh -vvv user@server

# Debug specific subsystem
QSSH_DEBUG=handshake,crypto qssh user@server

# Protocol trace
qssh --trace protocol.log user@server

# Analyze core dumps
gdb qssh core
```

## Performance

### Benchmarks (Intel i7-10700K)

| Operation | Falcon-512 | SPHINCS+ | RSA-2048 |
|-----------|------------|----------|----------|
| Keygen | 0.8ms | 3.2ms | 84ms |
| Sign | 0.4ms | 5.1ms | 1.2ms |
| Verify | 0.1ms | 2.4ms | 0.04ms |
| Handshake | 3.2ms | 14ms | 5.6ms |

### Optimization Tips

1. **Use Falcon for speed**: 10x faster than SPHINCS+
2. **Enable compression**: For slow networks
3. **Reuse connections**: Connection pooling
4. **Hardware acceleration**: AES-NI, SHA extensions

## Troubleshooting

### Connection Issues

```bash
# Test connectivity
qssh-diag test user@server

# Check algorithms
qssh-diag algorithms

# Verify quantum devices
qssh-diag quantum
```

### Common Problems

**"No quantum entropy available"**
- Install QRNG driver or use `--no-qrng`

**"Algorithm negotiation failed"**  
- Update both client and server
- Check `--algorithms` match

**"QKD key exhausted"**
- Increase key generation rate
- Enable QKD cache



### Quick Guide
1. Fork the repository
2. Create feature branch
3. Write tests
4. Submit PR

### Code Style
```bash
# Format code
cargo fmt

# Lint
cargo clippy

# Security audit
cargo audit
```

## License

Licensed under either:
- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Acknowledgments

- NIST Post-Quantum Cryptography project
- QuantumHarmony blockchain team
- PQClean reference implementations
- Signal Protocol (Double Ratchet)

---

*Building quantum-safe infrastructure for the next generation of secure communications.*
