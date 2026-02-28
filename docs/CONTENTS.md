# QSSH Repository Contents

## Core Source Files (/src)
- **client.rs** - SSH client implementation
- **server.rs** - SSH server implementation  
- **handshake.rs** - Post-quantum key exchange
- **auth.rs** - Authentication (password, public key)
- **transport.rs** - Encrypted transport layer
- **certificate.rs** - Quantum-safe certificates

## Cryptography (/src/crypto)
- **pq_kex.rs** - Post-quantum key exchange (Falcon, SPHINCS+)
- **aead.rs** - Authenticated encryption
- **key_encapsulation.rs** - Kyber implementation
- **cipher_choice.rs** - Algorithm negotiation

## Binaries (/src/bin)
- **qssh.rs** - Client binary
- **qsshd.rs** - Server daemon
- **qssh-keygen.rs** - Key generation
- **qssh-agent.rs** - Authentication agent
- **qssh-add.rs** - Add keys to agent

## Features
- **vault/** - Quantum-secure key storage
- **qkd/** - Quantum Key Distribution integration
- **port_forward.rs** - Port forwarding
- **sftp/** - Secure file transfer
- **x11/** - X11 forwarding

## Documentation
- **README.md** - Main documentation
- **docs/** - Additional guides
- **LICENSE-MIT** - MIT license
- **LICENSE-APACHE** - Apache 2.0 license

## Build Files
- **Cargo.toml** - Rust dependencies
- **build.sh** - Build script
- **.gitignore** - Git ignore rules

Total: 57 source files implementing a complete quantum-safe SSH.