# QSSH Documentation

This directory contains extended documentation for QSSH.

## Documentation Structure

### `/architecture/`
Technical architecture and design documents:
- `quantum-osi-model.md` - How QSSH fits in the OSI model with quantum enhancements
- `protocol-design.md` - Detailed protocol specification and message formats
- `quantum-architecture.md` - Overall quantum security architecture
- `p2p-implementation.md` - Peer-to-peer networking design

### `/implementation/`
Implementation status and requirements:
- `implementation-status.md` - Current implementation progress and QKD optional status
- `kirq-operator-requirements.md` - Requirements for KIRQ network operators
- `falcon-redesign.md` - Falcon algorithm implementation notes

### `/security/`
Security analysis and advisories:
- `security-analysis.md` - Comprehensive security analysis
- `qkd-tls-vulnerability.md` - QKD API security considerations

### `/whitepaper/`
Academic whitepaper and diagrams:
- `QSSH_Whitepaper.pdf` - Full academic paper
- `QSSH_WHITEPAPER.md` - Markdown version
- `diagrams/` - Architecture and protocol diagrams

### `/`
- `SPECIFICATION.md` - Complete protocol specification
- `README.md` - This file

## For Developers

Start with:
1. The main [README.md](../README.md) for overview
2. [architecture/protocol-design.md](architecture/protocol-design.md) for protocol details
3. [SPECIFICATION.md](SPECIFICATION.md) for implementation requirements

## For Security Researchers

See:
1. [security/security-analysis.md](security/security-analysis.md) for threat model
2. [SECURITY.md](../SECURITY.md) for vulnerability reporting
3. [whitepaper/QSSH_Whitepaper.pdf](whitepaper/QSSH_Whitepaper.pdf) for academic analysis