# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously in QSSH, especially given its role in secure communications.

### How to Report

Please report security vulnerabilities through one of these channels:

1. **Email**: security@quantumverseprotocols.com
2. **GitHub Security Advisories**: Use the Security tab in this repository
3. **Encrypted Communication**: Use our PGP key (available in the repository)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Response Time

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 30 days for critical issues

### Disclosure Policy

We follow responsible disclosure:
1. Reporter submits vulnerability privately
2. We acknowledge and investigate
3. We develop and test a fix
4. We release the fix
5. We publicly disclose the vulnerability after users have had time to update

## Security Considerations

### Post-Quantum Cryptography
QSSH uses NIST-approved post-quantum algorithms:
- **Falcon-512**: Digital signatures
- **SPHINCS+**: Alternative signatures (stateless)
- **Kyber**: Key encapsulation

### Implementation Security
- Written in Rust for memory safety
- No unsafe code in cryptographic operations
- Regular dependency updates
- Continuous security testing

### Known Limitations
- This is a new implementation - use with appropriate caution
- Not yet externally audited
- Should be used alongside defense-in-depth strategies

## Bug Bounty

We currently don't offer a formal bug bounty program, but we deeply appreciate security researchers who help improve QSSH. Contributors will be acknowledged (unless they prefer to remain anonymous).

## Contact

For any security concerns, please reach out. We appreciate your help in keeping QSSH secure.