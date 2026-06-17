# qssh

**Post-Quantum SSH. Drop-in replacement. Formally verified.**

qssh is a pure Rust implementation of SSH with post-quantum cryptography. It replaces OpenSSH's classical key exchange and authentication with quantum-resistant algorithms while maintaining full protocol compatibility.

---

## What It Does

| Capability | Detail |
|---|---|
| **Key exchange** | ML-KEM-1024 (NIST FIPS 203) |
| **Authentication** | Falcon-1024, SPHINCS+-256s |
| **Encryption** | AES-256-GCM, ChaCha20-Poly1305 |
| **Tests** | 132 automated tests |
| **Formal proofs** | 67 Lean 4 theorems, zero sorries, Mathlib v4.27.0 |
| **Patents** | None. Patent-free by design. |
| **Dependencies** | Pure Rust. No OpenSSH fork, no C bindings. |
| **3-tier verification** | Kani (panic-free), Verus (functional correctness), Lean 4 (mathematical foundations) |

## The Problem qssh Solves

Every SSH connection today uses RSA or ECDSA — both broken by Shor's algorithm on a sufficiently powerful quantum computer. The NIST deadline for PQC migration is 2035, but "harvest now, decrypt later" attacks mean data captured today can be decrypted retroactively.

qssh provides quantum-resistant SSH today. Not a patch on OpenSSH — a ground-up implementation with formal proofs that the cryptographic properties hold.

## Formal Verification

Three levels of verification — no other SSH implementation offers this:

| Level | Tool | What It Proves |
|---|---|---|
| **Panic-free** | Kani (AWS) | No execution path causes a crash |
| **Functional correctness** | Verus (Microsoft Research) | Code does exactly what it claims |
| **Mathematical foundations** | Lean 4 + Mathlib | Cryptographic properties are proven |

Published on Zenodo: [DOI 10.5281/zenodo.18663125](https://doi.org/10.5281/zenodo.18663125)

## Related Work

qssh is part of the Paraxiom post-quantum infrastructure stack:

| Project | Description | Theorems |
|---|---|---|
| [qssl](https://github.com/Paraxiom/qssl) | PQ TLS — 12 cipher suites | 100 |
| [PQTG](https://doi.org/10.5281/zenodo.18786526) | PQ Transport Gateway for QKD control channels | 99 |
| Drista | PQ encrypted chat (ML-KEM-1024, STARK, Nostr+IPFS) | 100 |
| QuantumHarmony | PQ L1 blockchain, live on 3 validators | 76 |
| Coherence Shield | AI trust proxy with toroidal logit bias | 115 |

Total: **909+ theorems** across 10 systems. All Lean 4, all zero sorries.

## Install

### Debian / Ubuntu (APT)

```bash
curl -fsSL https://apt.paraxiom.org/paraxiom.gpg | sudo tee /usr/share/keyrings/paraxiom.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/paraxiom.gpg] https://apt.paraxiom.org stable main" \
  | sudo tee /etc/apt/sources.list.d/paraxiom.list
sudo apt-get update
sudo apt-get install qssh
```

This installs the `qssh` client, the `qsshd` daemon and the supporting tools,
plus a systemd service for `qsshd`:

```bash
sudoedit /etc/qssh/qsshd.env     # set listen address / port
sudo systemctl start qsshd       # generates a Falcon-512 host key on first start
```

### Standalone `.deb`

Download the `.deb` from [Releases](https://github.com/Paraxiom/qssh/releases) and:

```bash
sudo apt install ./qssh_*.deb
```

Building the package yourself and the APT-repo setup are documented in
[docs/PACKAGING.md](docs/PACKAGING.md) and [docs/APT-REPO.md](docs/APT-REPO.md).

## Releases

Pre-built binaries are available under [Releases](https://github.com/Paraxiom/qssh/releases).

## Source Access

Source code is available under the [Paraxiom Source Collaboration License](LICENSE.md).

**We choose collaboration over extraction.** If you're working on post-quantum infrastructure — whether in research, government, defence, or industry — reach out. We grant access to people who want to build together.

To request access:

1. Email **sylvain@paraxiom.org** with a brief description of your work
2. We'll set up a collaboration agreement (NDA if required by your context)
3. You get full source access to the private development repository

That door opens when you knock.

## Citation

```bibtex
@misc{cormier2025qssh,
  author    = {Cormier, Sylvain},
  title     = {qssh: Post-Quantum SSH with 3-Tier Formal Verification},
  year      = {2025},
  publisher = {Paraxiom Technologies Inc.},
  url       = {https://github.com/Paraxiom/qssh}
}
```

## Contact

**Sylvain Cormier**
Paraxiom Technologies Inc. — Montreal
sylvain@paraxiom.org | [paraxiom.org](https://paraxiom.org)
