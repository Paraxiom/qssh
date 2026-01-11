# Paraxiom QSSH Onboarding Methodology (WSL2)

### 1. Environment Setup
- **OS:** Windows Subsystem for Linux (Ubuntu 24.04 recommended).
- **Toolchain:** Rust (latest stable), cargo.

### 2. Dependency Alignment
- Synchronize version parity for pqcrypto-falcon (standardize on v0.3 for 690-byte signatures).
- Import necessary signing traits (PublicKey, SecretKey) to resolve scope errors in test helpers.

### 3. Authentication Protocol
- Use detached_sign() for Falcon-512 handshake to ensure server-side compatibility.
- Standardize QSSH port to 42 to avoid classical SSH conflicts.

### 4. Validator Audit
- Live verification of Bob (quantumharmony2) performed.
- Block production stable at height #125,000+.
