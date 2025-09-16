# QSSH Protocol Specification v0.1.0

## Abstract

QSSH (Quantum Secure Shell) is a post-quantum secure remote access protocol designed to replace SSH in quantum computing environments. It provides information-theoretic security through optional Quantum Key Distribution (QKD) integration and computational security through post-quantum cryptographic algorithms.

## Table of Contents

1. [Introduction](#introduction)
2. [Threat Model](#threat-model)
3. [Protocol Architecture](#protocol-architecture)
4. [Wire Protocol](#wire-protocol)
5. [Handshake Sequence](#handshake-sequence)
6. [Key Management](#key-management)
7. [Transport Layer](#transport-layer)
8. [Security Properties](#security-properties)
9. [Implementation Requirements](#implementation-requirements)

## 1. Introduction

### 1.1 Motivation

Traditional SSH relies on RSA, ECDSA, and other classical cryptographic algorithms that will be broken by sufficiently large quantum computers. QSSH addresses this vulnerability by:

1. Using post-quantum cryptographic algorithms (NIST PQC winners)
2. Integrating with quantum key distribution hardware when available
3. Providing a migration path from classical to quantum-secure infrastructure

### 1.2 Design Goals

- **Post-Quantum Security**: Resistant to attacks by quantum computers
- **Backward Compatibility**: Can fall back to post-quantum crypto when QKD unavailable
- **Performance**: Minimal latency overhead compared to SSH
- **Simplicity**: Clear protocol with minimal complexity
- **Forward Secrecy**: Compromise of long-term keys doesn't compromise past sessions

## 2. Threat Model

### 2.1 Adversary Capabilities

We assume an adversary who:
- Has access to a large-scale quantum computer
- Can perform active man-in-the-middle attacks
- Can store encrypted traffic for future cryptanalysis
- Cannot compromise endpoint security
- Cannot break information-theoretic security (QKD)

### 2.2 Security Goals

- **Confidentiality**: Data remains secret even against quantum adversaries
- **Integrity**: Data cannot be modified without detection
- **Authentication**: Both parties can verify each other's identity
- **Forward Secrecy**: Past sessions remain secure if keys are compromised

## 3. Protocol Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
│                   (Shell, SFTP, Port Forwarding)        │
├─────────────────────────────────────────────────────────┤
│                    QSSH Protocol Layer                   │
│              (Authentication, Channel Mgmt)              │
├─────────────────────────────────────────────────────────┤
│                 Post-Quantum Crypto Layer                │
│            (SPHINCS+, Falcon, AES-256-GCM)              │
├─────────────────────────────────────────────────────────┤
│                      QKD Layer (Optional)                │
│                  (ETSI GS QKD 014 API)                  │
├─────────────────────────────────────────────────────────┤
│                      Transport Layer                     │
│                        (TCP/IP)                         │
└─────────────────────────────────────────────────────────┘
```

## 4. Wire Protocol

### 4.1 Message Format

All QSSH messages follow this format:

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Packet Length                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Padding   |                Message Type                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         Payload                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    MAC (if encrypted)                         |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.2 Message Types

```rust
enum MessageType {
    // Handshake messages
    ClientHello = 0x01,
    ServerHello = 0x02,
    ClientKeyExchange = 0x03,
    ServerKeyExchange = 0x04,
    ClientAuth = 0x05,
    ServerAuth = 0x06,
    HandshakeComplete = 0x07,
    
    // QKD messages
    QkdCapability = 0x10,
    QkdKeyRequest = 0x11,
    QkdKeyResponse = 0x12,
    QkdError = 0x13,
    
    // Data messages
    ChannelOpen = 0x20,
    ChannelAccept = 0x21,
    ChannelData = 0x22,
    ChannelClose = 0x23,
    
    // Control messages
    Disconnect = 0x30,
    Ping = 0x31,
    Pong = 0x32,
    Rekey = 0x33,
}
```

## 5. Handshake Sequence

### 5.1 Standard Handshake (Post-Quantum Only)

```
Client                                          Server
  |                                               |
  |------------- ClientHello ------------------->|
  |   - Protocol version                          |
  |   - Supported PQ algorithms                   |
  |   - Client random (32 bytes)                  |
  |                                               |
  |<------------ ServerHello --------------------|
  |   - Selected PQ algorithm                     |
  |   - Server random (32 bytes)                  |
  |   - Server Falcon public key                  |
  |                                               |
  |----------- ClientKeyExchange --------------->|
  |   - Client key share + Falcon signature       |
  |   - Client SPHINCS+ public key                |
  |                                               |
  |<---------- ServerKeyExchange ----------------|
  |   - Server SPHINCS+ public key                |
  |   - Server SPHINCS+ signature                 |
  |                                               |
  |------------- ClientAuth -------------------->|
  |   - Client SPHINCS+ signature                 |
  |   - Username                                  |
  |                                               |
  |<------------ ServerAuth ---------------------|
  |   - Authentication result                     |
  |                                               |
  |<--------- HandshakeComplete ---------------->|
  |   - Switch to encrypted transport             |
  |                                               |
```

### 5.2 QKD-Enhanced Handshake

```
Client                                          Server
  |                                               |
  |------------ QkdCapability ------------------>|
  |   - QKD endpoints available                   |
  |   - Supported QKD protocols                   |
  |                                               |
  |<----------- QkdCapability -------------------|
  |   - QKD endpoints available                   |
  |   - Selected QKD protocol                     |
  |                                               |
  |------------ QkdKeyRequest ------------------>|
  |   - Key ID for QKD system                     |
  |   - Requested key length                      |
  |                                               |
  |<----------- QkdKeyResponse ------------------|
  |   - Key retrieval confirmation                |
  |                                               |
  | [Continue with standard handshake using       |
  |  QKD-derived entropy mixed with PQ crypto]    |
  |                                               |
```

## 6. Key Management

### 6.1 Key Derivation

Session keys are derived using HKDF with SHA3-256:

```
master_secret = Falcon_derived_secret || QKD_key (if available)
salt = client_random || server_random

client_write_key = HKDF(master_secret, salt, "client write", 32)
server_write_key = HKDF(master_secret, salt, "server write", 32)
client_write_iv = HKDF(master_secret, salt, "client iv", 12)
server_write_iv = HKDF(master_secret, salt, "server iv", 12)
```

### 6.2 Key Rotation

Keys must be rotated:
- Every 2^32 messages
- Every 1 GB of data
- Every hour of connection time
- When requested by either party

### 6.3 QKD Integration

When QKD is available:
1. Retrieve 256-bit key from QKD system
2. XOR with Falcon derived secret
3. Use result as master_secret
4. Delete QKD key after use (no-cloning principle)

## 7. Transport Layer

### 7.1 Encryption

After handshake, all messages are encrypted using:
- **Algorithm**: AES-256-GCM (NIST SP 800-38D)
- **Key Size**: 256 bits
- **Nonce**: 96 bits (incremented per message)
- **AAD**: Message type and length

### 7.2 Channel Multiplexing

QSSH supports multiple channels over a single connection:
- Shell sessions
- Port forwarding
- File transfer
- Each channel has independent flow control

## 8. Security Properties

### 8.1 Post-Quantum Security

- **Falcon-512**: Lattice-based signatures (NIST Level 1)
- **SPHINCS+**: Stateless hash-based signatures (NIST Level 1)
- **AES-256-GCM**: NIST-approved quantum-resistant symmetric encryption

### 8.2 Information-Theoretic Security (with QKD)

When QKD is used:
- Keys are information-theoretically secure
- Security based on laws of physics, not computational assumptions
- Immune to all computational attacks (including quantum)

### 8.3 Forward Secrecy

- Ephemeral Falcon keys per session
- QKD keys deleted after use
- Past sessions secure even if long-term keys compromised

## 9. Implementation Requirements

### 9.1 Mandatory Algorithms

All implementations MUST support:
- Falcon-512 for key agreement
- SPHINCS+-SHAKE-128s for signatures
- AES-256-GCM for encryption
- SHA3-256 for hashing
- HKDF for key derivation

### 9.2 Optional Features

Implementations MAY support:
- QKD integration via ETSI GS QKD 014 API
- Alternative PQ algorithms (Falcon, Dilithium)
- Compression before encryption
- Hardware security module integration

### 9.3 Security Considerations

Implementations MUST:
- Use constant-time operations for cryptographic code
- Zeroize sensitive key material after use
- Validate all inputs before processing
- Implement rate limiting for authentication attempts
- Support only TLS 1.3 for QKD API connections

## References

1. NIST Post-Quantum Cryptography Standardization
2. ETSI GS QKD 014: Quantum Key Distribution; Protocol and data format of REST-based key delivery API
3. RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
4. RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
5. The SPHINCS+ Signature Scheme
6. Falcon Algorithm Specification