# Security Policy

## Reporting a vulnerability

Please do **not** open public GitHub issues for suspected vulnerabilities.

Report privately via one of these channels:

1. **Email:** sylvain@paraxiom.org
2. **GitHub Security Advisories:** use the Security tab of this repository

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Response timeframe

- **Initial acknowledgement:** within 48 hours
- **Status update:** within 7 days
- **Resolution target:** within 30 days for critical issues

### Disclosure process

We follow coordinated disclosure:

1. Reporter submits privately
2. We acknowledge and investigate
3. We develop and test a fix
4. We release the fix
5. We publicly disclose after users have had reasonable time to update

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Security properties

QSSH uses NIST-approved post-quantum algorithms:

- **Kyber (ML-KEM)** for key encapsulation
- **Falcon-512** for digital signatures
- **SPHINCS+** as an alternative stateless signature scheme

Implementation hardening:

- Written in Rust for memory safety
- No `unsafe` in cryptographic code paths
- Formal verification via Lean 4 (67 theorems), kani proofs, and verus proofs
- See [docs/SECURITY.md](docs/SECURITY.md) and [docs/AUDIT_CERTIFICATE.md](docs/AUDIT_CERTIFICATE.md) for full detail

## Known limitations

- New implementation — use with appropriate caution
- Not yet externally audited beyond the Paraxiom internal audit
