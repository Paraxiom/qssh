# QSSH - Quantum-Safe SSH

SSH reimplemented with post-quantum cryptography to protect against quantum computer attacks.

## Features

- ✅ **Post-Quantum Algorithms**: Falcon-512, SPHINCS+, Kyber
- ✅ **Full SSH Compatibility**: Shell, commands, port forwarding, SFTP
- ✅ **Drop-in Replacement**: Works like regular SSH
- ✅ **Future-Proof**: Ready for the quantum computing era
- ✅ **Optional QKD**: Can integrate with quantum key distribution

## Quick Start

```bash
# Build
cargo build --release

# Generate quantum-safe keys
./target/release/qssh-keygen

# Connect (just like SSH)
./target/release/qssh user@host

# Start server
./target/release/qsshd
```

## Why QSSH?

Current SSH uses RSA/ECDSA which quantum computers will break. QSSH uses quantum-resistant algorithms approved by NIST.

## Installation

```bash
# From source
git clone https://github.com/QuantumVerseProtocols/qssh
cd qssh
cargo install --path .

# Or download release
wget https://github.com/QuantumVerseProtocols/qssh/releases/latest/qssh
chmod +x qssh
```

## Configuration

QSSH uses the same config format as OpenSSH:

```bash
# ~/.qssh/config
Host myserver
    HostName example.com
    Port 2222
    PqAlgorithm falcon512
```

## License

MIT or Apache-2.0