# QSSH Documentation Index

## 📚 Core Documentation

### Whitepaper
- **[QSSH Whitepaper (PDF)](whitepaper/QSSH_Whitepaper.pdf)** - Complete technical paper
- **[QSSH Whitepaper (Markdown)](whitepaper/QSSH_WHITEPAPER.md)** - Web-friendly version
- **[LaTeX Source](whitepaper/QSSH_Whitepaper.tex)** - Academic source

### Architecture
- **[Protocol Design](architecture/protocol-design.md)** - QSSH protocol specification
- **[Quantum Architecture](architecture/quantum-architecture.md)** - PQC implementation details
- **[Quantum OSI Model](architecture/quantum-osi-model.md)** - Quantum networking stack
- **[Ecosystem Comparison](architecture/ecosystem-comparison.md)** - QSSH vs alternatives

### Visual Documentation
- **[Architecture Diagram](whitepaper/diagrams/architecture.png)** - System architecture
- **[Protocol Flow](whitepaper/diagrams/protocol_flow.png)** - Connection sequence
- **[Security Model](whitepaper/diagrams/security_model.png)** - Threat model

## 🔒 Security Documentation

### Specifications
- **[Full Specification](SPECIFICATION.md)** - Complete protocol specification
- **[Security Analysis](security/)** - Threat models and mitigations

### Quantum Security
- **[QKD Integration](QKD_INTEGRATION.md)** - Quantum Key Distribution plans
- **[QKD Status](QKD_STATUS.md)** - Current QKD implementation status
- **[Zero-Knowledge Proof](ZKP_TECHNICAL_DEBT_PROOF.md)** - ZKP for technical debt

## 🚀 Implementation

### Getting Started
- **[Main README](README.md)** - Quick start guide
- **[Implementation Details](implementation/)** - Code structure

### Development
- **[P2P Implementation](architecture/p2p-implementation.md)** - Peer-to-peer features

## 📊 Key Highlights

### Post-Quantum Algorithms
- **Falcon-512**: NIST-approved digital signatures
- **SPHINCS+**: Stateless hash-based signatures
- **Kyber**: Key encapsulation (future integration)

### Security Features
- 99% quantum-safe with PQC alone
- 100% quantum-safe with QKD layer
- Side-channel resistant implementation
- Memory-safe Rust codebase

### Performance
- Comparable to classical SSH for most operations
- ~690 byte signatures (Falcon-512)
- Fast key generation and verification

## 🎯 For Reviewers

Start with:
1. **[Whitepaper](whitepaper/QSSH_WHITEPAPER.md)** - Understanding the problem and solution
2. **[Architecture Diagram](whitepaper/diagrams/architecture.png)** - Visual overview
3. **[Protocol Design](architecture/protocol-design.md)** - Technical details
4. **[Main README](../README.md)** - How to use QSSH

## 📬 Contact

For security reviews, questions, or collaboration:
- GitHub Issues: [QuantumVerseProtocols/qssh](https://github.com/QuantumVerseProtocols/qssh)
- Security: See [SECURITY.md](../SECURITY.md)