# QSSH v0.0.1-alpha - Known Limitations and Status

## Production Readiness

**⚠️ EXPERIMENTAL SOFTWARE - NOT FOR PRODUCTION USE**

This is v1.0.0 of an experimental quantum-safe SSH implementation. While core functionality works, this software has not been:
- Security audited by professionals
- Tested at scale in production environments
- Validated for compliance (FIPS, Common Criteria, etc.)

## Feature Status

### ✅ Working Features
These features are implemented and functional:
- Basic SSH connections with post-quantum cryptography
- Interactive shell sessions with full PTY support
- SFTP file transfer subsystem
- Port forwarding (local, remote, dynamic/SOCKS)
- X11 forwarding
- Public key authentication
- Password authentication
- SSH agent support (qssh-agent)
- Known hosts verification
- Config file parsing (~/.qssh/config)
- Compression (zlib, zstd, lz4)
- Session resumption

### ⚠️ Partial Implementations
These features exist but have limitations:
- **Multiplexing**: Code exists but returns "not implemented" errors to prevent security issues
- **ProxyJump**: Basic support, not all edge cases handled
- **GSSAPI/Kerberos**: Stubs return proper errors instead of dummy data

### ❌ Not Implemented
These features are not available:
- SSH agent forwarding
- Certificate-based authentication (code exists but not integrated)
- Host-based authentication
- Keyboard-interactive authentication
- SSH-1 protocol support (by design - only SSH-2)

## Security Considerations

### Cryptographic Status
- **Post-quantum algorithms**: Using NIST-approved candidates (Kyber, Falcon, SPHINCS+)
- **Not independently audited**: Crypto implementations from pqcrypto crates
- **Side-channel resistance**: Not evaluated

### Known Security Limitations
1. **No formal verification** of protocol implementation
2. **Limited fuzzing** - basic tests only
3. **Timing attacks** - not systematically mitigated
4. **Memory safety** - Rust helps but unsafe blocks exist

## Platform Support

### Tested Platforms
- Linux (x86_64, aarch64)
- macOS (Intel, Apple Silicon)

### Untested/Unsupported
- Windows (may work via WSL)
- BSD variants
- Mobile platforms (iOS, Android)
- Embedded systems

## Performance Limitations

### Known Issues
1. **Handshake latency**: ~100ms due to PQC operations
2. **Memory usage**: Higher than OpenSSH due to PQC key sizes
3. **CPU usage**: Falcon signatures are compute-intensive

### Not Optimized
- No hardware acceleration (AES-NI, etc.)
- Single-threaded crypto operations
- No connection pooling optimizations

## Interoperability

### Cannot Connect To
- OpenSSH servers (incompatible protocol)
- PuTTY or other SSH clients
- Commercial SSH implementations

### Works Only With
- Other QSSH instances
- Future quantum-safe SSH implementations using same algorithms

## Error Handling

### Improved in v1.0.0
- All placeholder implementations replaced with proper errors
- No dummy data or zero-filled buffers
- Debug output through logging framework only

### Still Basic
- Error messages may not be user-friendly
- Limited retry logic
- No automatic fallback mechanisms

## Configuration Limitations

### Not Supported
- All OpenSSH config options (only subset implemented)
- Match blocks in config files
- Include directives
- Canonicalization options

## Testing Coverage

### What's Tested
- Basic connection flows
- Crypto primitives
- Key generation
- File transfer basics

### Not Well Tested
- Edge cases and error conditions
- Performance under load
- Network interruption recovery
- Concurrent connections at scale

## Recommendations

### Use QSSH If
- You're researching post-quantum cryptography
- Testing quantum-safe protocols in lab environment
- Building experimental quantum networks
- Learning about PQC implementations

### Don't Use QSSH If
- You need production-grade SSH
- Compliance requirements (FIPS, etc.)
- Interoperability with existing SSH infrastructure
- Mission-critical systems

## Getting Help

### For Issues
- GitHub Issues: https://github.com/yourname/qssh/issues
- Include version, platform, and full error output

### For Security Issues
- DO NOT use in production where security matters
- Report security concerns privately via GitHub Security tab
- This is experimental software - expect vulnerabilities

## Future Roadmap

### v2.0 Goals
- Security audit
- Certificate authentication
- Better error messages
- Performance optimizations

### Long Term
- OpenSSH compatibility mode
- Hardware security module support
- Formal verification of core protocol
- Production hardening

---

**Remember**: QSSH is an experimental research project exploring post-quantum SSH. For production use, stick with OpenSSH until quantum threats are imminent and QSSH has matured.