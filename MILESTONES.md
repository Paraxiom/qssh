# QSSH Milestones & Roadmap

**Last updated**: 2026-02-23 (commit `6854fe2`)
**Current version**: 0.3.1 (published on crates.io)
**Tests**: 128 unit passing + integration tests, 0 ignored, 0 failed
**Warnings**: 0 (enforced in CI)
**Deployed**: Alice (51.79.26.123), Docker container `qsshd-server` on port 22222
**Crypto backend**: Pure Rust (fn-dsa 0.3 + slh-dsa 0.0.3) — zero C FFI

---

## M0 — Core Protocol (COMPLETE)

Everything needed for a working PQ SSH replacement over TCP.

| Feature | Status | Commit/Notes |
|---------|--------|--------------|
| PQC handshake (Falcon-512 + SPHINCS+) | DONE | `a09bb0d` |
| ML-KEM (FIPS 203) key exchange | DONE | `ec6d9ab` (v0.2.0) |
| AES-256-GCM symmetric encryption | DONE | HKDF-SHA256 key derivation |
| 768-byte quantum frames (traffic analysis resistance) | DONE | `1e97208` |
| Replay protection (sequence numbers) | DONE | u64 per frame |
| Interactive shell + PTY | DONE | `ShellSessionThread` + SIGWINCH |
| Command exec (`-c`) | DONE | `ExecRequest` handler |
| Public key auth (PQ-only) | DONE | `AuthorizedKeysManager` |
| Password auth (SHA3-256) | DONE | `PasswordAuthManager` |
| Known hosts / TOFU | DONE | Hashed hostname matching (HMAC-SHA1) |
| Config file (`~/.qssh/config`) | DONE | Host stanza parsing |
| Security tiers T0-T5 | DONE | `c593ca4` |
| Key generation (`qssh-keygen`) | DONE | Falcon-512 + SPHINCS+ |
| Host key persistence | DONE | `0fe9dbb` (v0.3.1) |

## M0.1 — Signing & Node Tools (COMPLETE)

Specialized binaries for QuantumHarmony operators.

| Feature | Status | Commit/Notes |
|---------|--------|--------------|
| `qssh-sign` (Lamport OTS vault) | DONE | `950a958` (v0.3.0) |
| `qssh-node` (auto-tunnel to QH nodes) | DONE | `950a958` |
| `qssh-agent` + `qssh-add` | DONE | Agent socket impl |
| `qscp` (SFTP-based file copy) | DONE | `bc8ecde` |
| `qsshpass` (test-only password helper) | DONE | Security warnings included |

## M0.2 — Port Forwarding (COMPLETE)

Full SSH-style port forwarding over PQ tunnel.

| Feature | Status | Commit/Notes |
|---------|--------|--------------|
| Local forwarding (`-L`) | DONE | `3795052` |
| Remote forwarding (`-R`) | DONE | `ee2502e` |
| Dynamic/SOCKS5 (`-D`) | DONE | `b197b25` |
| Cancel remote forward | DONE | `GlobalRequestType::CancelTcpipForward` |

## M0.3 — Server Hardening (COMPLETE)

Production server features.

| Feature | Status | Commit/Notes |
|---------|--------|--------------|
| Daemonization (`--daemon`) | DONE | `c4ed47c` (v0.3.1) |
| PID file | DONE | `--pid-file` flag |
| Auto-reconnect (`--persistent`) | DONE | `d3c73fd` (v0.3.0) |
| Rekey (key rotation) | DONE | `d3c73fd` + `c4ed47c` (timer) |
| Keepalive (Ping/Pong) | DONE | Server message loop |
| Max connections (default 100) | DONE | Configurable |
| Docker deployment | DONE | `39bddd2` + fixes |
| Docker HEALTHCHECK | DONE | `2d9a893` (TCP probe) |

## M0.4 — SFTP (COMPLETE)

Full SFTPv3 subsystem.

| Feature | Status | Commit/Notes |
|---------|--------|--------------|
| SFTP server subsystem | DONE | `src/subsystems/sftp/` |
| SFTP client (`qscp`) | DONE | `bc8ecde` |
| File handles + sessions | DONE | SFTPv3 protocol |
| Absolute path resolution | DONE | `0b4d1bd` |

## M0.5 — ProxyJump (COMPLETE)

SSH jump host / proxy support.

| Feature | Status | Commit/Notes |
|---------|--------|--------------|
| ProxyJump (`-J user@host`) | DONE | `2d9a893` |
| ProxyCommand (process stdio) | DONE | `%h`/`%p` substitution |
| `connect_via_stream()` API | DONE | `src/client.rs` |
| Multi-hop ProxyJump | PARTIAL | First hop only; logs warning for >1 hop |

## M0.6 — Formal Verification (COMPLETE)

3-tier formal verification.

| Tier | Tool | Count | Status |
|------|------|-------|--------|
| Tier 1 | Kani | 30 harnesses | DONE — panic-freedom, integer safety |
| Tier 2 | Verus | 20 proofs | DONE — functional correctness |
| Tier 3 | Lean 4 | 67 theorems | DONE — zero sorries, Mathlib v4.27.0 |

## M0.7 — CI & Quality (COMPLETE)

| Feature | Status | Commit/Notes |
|---------|--------|--------------|
| GitHub Actions CI | DONE | `169f172` |
| Zero warnings (cargo build) | DONE | `a42dbd5` + `9a83260` |
| Zero warnings (cargo build --tests) | DONE | `9a83260` |
| crates.io publish (v0.3.1) | DONE | `qssh` crate |

---

## M0.8 — Pure-Rust Crypto Migration (COMPLETE)

Replaced all C-FFI pqcrypto dependencies with pure-Rust implementations.

| Feature | Status | Commit/Notes |
|---------|--------|--------------|
| Replace pqcrypto-falcon with fn-dsa 0.3 | DONE | `6854fe2` — Thomas Pornin's pure Rust impl |
| Replace pqcrypto-sphincsplus with slh-dsa 0.0.3 | DONE | `6854fe2` — RustCrypto |
| Remove pqcrypto, pqcrypto-traits, pqcrypto-dilithium | DONE | `6854fe2` — dead deps |
| Un-ignore all 44 macOS segfault tests | DONE | `6854fe2` — all now pass |
| Zero C-FFI crypto dependencies | DONE | fn-dsa + slh-dsa + ml-kem all pure Rust |

## M1 — Production Cleanup (IN PROGRESS)

Fix issues from `PRODUCTION_ISSUES.md` before wider release.

| Feature | Status | Priority |
|---------|--------|----------|
| Replace `println!` with `log::debug!` in SFTP subsystem | DONE (already clean) | Critical |
| Replace `println!` in `crypto/quantum_kem.rs` | DONE (already clean) | Critical |
| Replace `println!` in `transport/quantum_resistant.rs` | DONE (test-only) | Critical |
| Remove GSSAPI module or make it return clear errors | DONE (already returns errors) | Critical |
| Fix multiplex channel creation (returns dummy ID) | DONE (IDs were correct, clarified naming) | High |
| Fix multiplex data forwarding (not implemented) | DONE (split into bidirectional channels) | High |
| Remove hardcoded "secret123" from agent tests | DONE (was `test_passphrase_only_for_unit_tests`) | Medium |
| Replace `eprintln!` with structured logging | DONE (only in CLI bins, appropriate) | Medium |
| Remove `src/qkd.disabled/` or document as experimental | DONE (dir doesn't exist) | Medium |
| Update `PRODUCTION_ISSUES.md` (stale entries) | TODO | Low |

## M2 — Incomplete Features

Finish partially implemented features.

| Feature | Status | Notes |
|---------|--------|-------|
| Connection multiplexing (full) | PARTIAL | Bidirectional data forwarding fixed; needs end-to-end integration test |
| X11 forwarding | PARTIAL | Listener works, server-side channel not wired |
| Multi-hop ProxyJump | PARTIAL | First hop only |
| Session resumption (ticket encryption) | PARTIAL | Encryption key may be placeholder |
| Compression wired to transport | PARTIAL | Algorithms implemented, not in default transport |
| SSH agent forwarding (`-A`) | NOT STARTED | Security review pending |
| Certificate-based auth | NOT STARTED | Data model exists, not in handshake |

## M3 — Quantum Hardware Integration

Features requiring quantum hardware or HSM.

| Feature | Status | Notes |
|---------|--------|-------|
| QKD integration (ETSI API) | PLACEHOLDER | Returns random bytes, needs real QKD endpoint |
| QRNG entropy (T3+) | PARTIAL | Crypto4A HSM endpoint defined, not wired |
| HSM key storage | NOT STARTED | Roadmap only |
| BB84 protocol | PARTIAL | `src/qkd/bb84.rs` exists |

## M4 — Enterprise & Compliance

Long-term goals for enterprise adoption.

| Feature | Status | Notes |
|---------|--------|-------|
| FIPS 140-3 validation | NOT STARTED | Requires formal process |
| Audit logging (structured) | PARTIAL | Hash chain in `qssh-sign`, not in core |
| P2P discovery | STUB | `src/p2p/mod.rs` scaffolding only |
| Blockchain-based key registry | STUB | QuantumHarmony integration planned |
| Password hardening (Argon2) | NOT STARTED | Currently SHA3-256 |
| Exit status propagation | NOT STARTED | Remote command exit codes not forwarded |
| Secure password input masking | NOT STARTED | Terminal echo not suppressed |

---

## Architecture Quick Reference

```
src/
  bin/              9 binaries (qssh, qsshd, qscp, qssh-keygen, qssh-passwd,
                    qssh-agent, qssh-add, qssh-sign, qssh-node) + qsshpass
  agent/            SSH agent socket
  auth.rs           Public key + password auth
  certificate.rs    Certificate data model (not in handshake yet)
  client.rs         QsshClient (connect, connect_via_stream, shell session)
  compression.rs    zlib/zstd/lz4
  config.rs         ~/.qssh/config parsing
  crypto/           PQC (Falcon, SPHINCS+, ML-KEM), AES-256-GCM, QRNG
  gssapi.rs         STUB (feature-gated)
  handshake.rs      PQ handshake (client + server)
  known_hosts.rs    TOFU + hashed hostnames
  multiplex/        ControlMaster (partial)
  p2p/              P2P mode (stub)
  port_forward.rs   -L / -R / -D forwarding
  proxy/mod.rs      ProxyJump (-J) + ProxyCommand
  pty.rs            PTY allocation
  qkd/              QKD client (placeholder)
  security_tiers.rs T0-T5 threat model tiers
  server.rs         QsshServer
  session.rs        Session cache + resumption
  sftp_client.rs    SFTP client
  shell_handler_thread.rs  Real shell with PTY
  subsystems/sftp/  SFTPv3 server
  transport/        Encrypted transport, 768-byte quantum frames, protocol
  vault/            Key vault for qssh-sign
  x11/              X11 forwarding (partial)
```

## Deployment

- **Alice** (51.79.26.123): `docker compose up -d` in `/home/ubuntu/paraxiom-qssh/`
- **Port**: 22222 (not drop-in for port 22)
- **Docker image**: Rust 1.85 / Debian Bookworm, multi-stage build
- **Volumes**: `/etc/qssh` (host keys), `/home` (user dirs + authorized_keys)

## Key Constraints

1. **Not wire-compatible with OpenSSH** — custom binary protocol over TCP
2. **PQ-only auth** — no RSA/ECDSA acceptance (by design)
3. ~~**macOS pqcrypto segfault**~~ — RESOLVED in M0.8 (pure Rust, zero C FFI)
4. **Default port 22222** — avoids conflict with system sshd

## Commit History Summary (77 commits)

| Version | Key commits |
|---------|-------------|
| v0.3.1 | `c4ed47c`..`9a83260` — rekey timer, daemonize, host keys, ProxyJump, warnings cleanup |
| v0.3.0 | `d3c73fd`..`950a958` — auto-reconnect, mux, rekey, signing, node CLI, SOCKS5, -R |
| v0.2.0 | `ec6d9ab`..`631c3bc` — ML-KEM, security tiers, quantum transport KEM |
| v0.1.0 | `995ed9a`..`142551f` — initial release, Falcon/SPHINCS+, basic shell/auth |
