# qssh

**A post-quantum remote shell in pure Rust. Its own protocol, not an OpenSSH replacement.**

qssh is a remote shell, file copy and key agent written in pure Rust around
post-quantum primitives: ML-KEM-1024 key exchange, Falcon and SPHINCS+
authentication. It speaks its own protocol. It is **not** wire compatible with
OpenSSH: a qssh client talks to a qsshd server, and neither interoperates with
OpenSSH peers.

---

## Security notice (2026-09-13)

**Every release before 0.4.2 defaults to a key exchange that provides no
confidentiality.** The `FalconSignedShares` exchange authenticates the peers,
but derives the session key from values sent in cleartext, so a passive
observer can reconstruct it. An ML-KEM exchange existed in the code, but the
client hardcoded the default algorithm and never selected it. Found
2026-07-15, fixed on `main` 2026-07-16 (PR #5), released as **0.4.2** on
2026-09-13: ML-KEM-1024 is the default and the configured algorithm is
honoured. Earlier crates.io versions are yanked; the v0.4.1 release, the
Homebrew formula and the APT package built from the June tag are superseded.
Upgrade, and treat any session made under an earlier default configuration as
having had no confidentiality against a passive attacker. Details in
[CHANGELOG.md](CHANGELOG.md) and [SECURITY.md](SECURITY.md).

## What It Does

| Capability | Detail |
|---|---|
| **Key exchange** | ML-KEM-1024 (NIST FIPS 203) |
| **Authentication** | Falcon-1024, SPHINCS+-256s |
| **Encryption** | AES-256-GCM, ChaCha20-Poly1305 |
| **Tests** | 164 automated tests in the library crate, all run in CI |
| **Lean 4** | 71 lemmas on parameter and structural conformance, zero sorries, Mathlib v4.27.0. Not proofs of protocol security. |
| **Patents** | None. Patent-free by design. |
| **Dependencies** | Pure Rust. No OpenSSH fork, no C bindings. |
| **Other harnesses** | Kani and Verus harnesses exist in `kani-proofs/` and `verus-proofs/`; they are not run in CI and no claim rests on them. |

## Where qssh Stands

OpenSSH already ships a hybrid post-quantum key exchange by default:
`sntrup761x25519` since 9.0 (2022) and `mlkem768x25519` since 10.0 (2025).
For most users, "harvest now, decrypt later" on the SSH key exchange is
addressed upstream, in audited, interoperable software. If that is your
problem, use OpenSSH.

What qssh adds is post-quantum **authentication**: Falcon-1024 and SPHINCS+
host and user keys, which OpenSSH does not ship yet, in a small pure Rust
codebase you can read end to end. What it costs: no OpenSSH interoperability,
no external audit, and one serious default-configuration bug that we found
and fixed ourselves (see the notice above). Treat it as a research and
experimentation tool, not as infrastructure.

## What Is Verified, and What Is Not

| Layer | Status |
|---|---|
| Parameter and structure conformance (key and ciphertext sizes, framing, encodings) | 71 Lean 4 lemmas, `lake build` reproduces them with zero sorries |
| Panic freedom, functional correctness | Kani and Verus harnesses in the repository; not run in CI; unverified as of this release |
| Protocol security (handshake, key derivation) | Not verified. No symbolic or computational model of the qssh handshake exists. The July 2026 default key exchange bug was found by inspection, not by a proof. |

The Lean development is on Zenodo: [DOI 10.5281/zenodo.18663125](https://doi.org/10.5281/zenodo.18663125)

## Related Work

qssh is part of the Paraxiom post-quantum infrastructure stack:

| Project | Description | Lean 4 lemmas (build-reproduced, 2026-09-07) |
|---|---|---|
| [qssl](https://github.com/Paraxiom/qssl) | PQ TLS, 12 cipher suites | 100 |
| [PQTG](https://github.com/Paraxiom/pq-transport-gateway) | PQ transport gateway for QKD key delivery (ETSI GS QKD 014), validated on a commercial QKD link | 111 |
| [QuantumHarmony](https://github.com/Paraxiom/quantum-harmony-node-public) | PQ L1 blockchain, live testnet | 142 |

The counts above are what `lake build` reproduces today. Earlier published
portfolio totals were never reproduced by a build and have been withdrawn.

## Install

### macOS / Linux (Homebrew)

```bash
brew tap paraxiom/tap
brew trust paraxiom/tap     # one-time: clears Homebrew's third-party-tap check
brew install qssh
```

Builds from source (Homebrew pulls in the Rust toolchain automatically). Works
on macOS and on Linux via Homebrew — including ARM, where the `.deb` below is
not yet published.

### Debian / Ubuntu (APT)

```bash
curl -fsSL https://paraxiom.github.io/apt/paraxiom.gpg | sudo tee /usr/share/keyrings/paraxiom.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/paraxiom.gpg] https://paraxiom.github.io/apt stable main" \
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

## Licence

Two regimes, at the recipient's choice: **GPL-3.0-only** (the default,
reciprocal) or a **Paraxiom commercial licence** for products that cannot
carry the GPL. See [LICENSE.md](LICENSE.md).

**We choose collaboration over extraction.** If you're working on post-quantum
infrastructure — whether in research, government, defence, or industry — write
to **sylvain@paraxiom.org** with a brief description of your work. That door
opens when you knock.

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
