# Changelog

All notable changes to QSSH are documented in this file.

## [0.4.0] - 2026-02-23

### Changed (BREAKING)

- **Pure-Rust crypto backend**: Replaced all C-FFI pqcrypto dependencies with pure-Rust implementations. Zero C code, zero `unsafe` in crypto paths.
  - Falcon-512: `pqcrypto-falcon` → `fn-dsa 0.3` (Thomas Pornin, Falcon co-designer)
  - SPHINCS+: `pqcrypto-sphincsplus` → `slh-dsa 0.0.3` (RustCrypto)
  - Removed: `pqcrypto`, `pqcrypto-traits`, `pqcrypto-dilithium` (dead deps)
- FN-DSA signature encoding differs from original Falcon (666 vs ~690 bytes) — wire-incompatible with v0.3.x

### Added

- **SSH agent forwarding** (`-A`): Client bridges to `QSSH_AUTH_SOCK`, server creates per-session socket
- **Certificate-based authentication**: `AuthMethod::Certificate`, client loads `~/.qssh/id_qssh-cert`
- **Compression wired to transport**: `CompressionContext` in send/receive path (zlib, zstd, lz4)
- **Session resumption**: Server master secret + HMAC-SHA256 integrity + constant-time verification
- **X11 forwarding**: Server-side handler — listener, X11 channel bridging, DISPLAY state
- **Multi-hop ProxyJump**: Iterative hop chaining via `open_channel_bridge()` + `connect_via_stream()`
- **Audit logging**: Hash-chained JSONL (`AuditLogger`), wired into server (connect/auth/exec/disconnect)
- **Argon2id password hashing**: PHC string format, random salt, auto-upgrade from SHA3-256
- **Exit status propagation**: `ExitStatus` variant in protocol, client `exec_with_status()`
- **Password zeroization**: `zeroize` crate on client config, server handshake, `qssh-passwd` binary
- **Quantum hardware interfaces**: QKD (ETSI API), QRNG entropy (multi-source), HSM key storage, BB84 protocol

### Fixed

- All 44 previously-ignored macOS tests now pass (pure Rust eliminates C FFI segfaults)
- 229 tests passing (154 unit + 75 integration), 0 ignored, 0 warnings

## [0.3.1] - 2026-02-22

### Added

- **ProxyJump** (`-J user@jumphost`): Connect through intermediate hosts via DirectTcpip channel tunneling. Opens a PQ-encrypted channel through the jump host and bridges it to a local TCP socket pair for the final connection's handshake. Supports ProxyCommand (`%h`/`%p` substitution) via process stdio bridging.
- **Automatic Rekey Timer**: Periodic key rotation fires every `key_rotation_interval` seconds (default 3600). Uses Falcon-signed ephemeral shares + HKDF-SHA3-256 derivation. Transport crypto swapped atomically via RwLock with sequence number reset.
- **qsshd Daemonization**: Proper Unix double-fork daemon (`--daemon` flag). Runs fork/setsid before tokio runtime starts (thread-safe). PID file via `--pid-file` (default `/var/run/qsshd.pid`), stdio redirect to /dev/null.
- **Host Key Persistence**: `qsshd --generate-keys` now serializes SPHINCS+ and Falcon keys to binary file (QSSH v1 format with length-prefixed fields). Server loads keys on startup. Public key fingerprint (SHA-256) written to `.pub` file. File permissions set to 0600.
- `PqKeyExchange::to_bytes()` / `PqKeyExchange::from_bytes()` for key serialization
- `QsshClient::connect_via_stream()` for pre-established TCP connections
- 3 new unit tests for host key round-trip, invalid magic, and truncation

### Changed

- GSSAPI module gated behind `gssapi` feature flag (was always compiled, all operations return errors)
- Docker HEALTHCHECK: replaced non-functional qssh client probe with TCP port check
- Dockerfile: added qssh-sign and qssh-node binaries to Docker image
- Version bump to 0.3.1

## [0.3.0] - 2026-02-20

### Added

- **Auto-Reconnect** (`--persistent`): Exponential backoff reconnection with configurable max retries. `ReconnectConfig` struct with initial_delay (500ms), max_delay (30s), 2x multiplier.
- **Connection Multiplexing** (`-S <path>`): SSH-style ControlMaster/ControlClient. Auto-detects: if master exists, connect as client; otherwise become master. Unix socket for IPC.
- **Key Rotation (Rekey)**: Full Falcon key exchange over encrypted channel. Both sides generate new PqKeyExchange, exchange signed shares, derive new AES-256-GCM keys via HKDF-SHA3-256, atomically swap transport crypto. Sequence numbers reset to prevent nonce reuse.
- **Signing Service** (`qssh-sign`): Vault-based key management for QuantumHarmony node operators. Lamport OTS for one-time signatures, rate limiting, audit log with hash chain.
- **`qssh-node` CLI**: One-liner PQ tunnel to QuantumHarmony nodes. Auto-binds standard ports (9944, 8080, 8085, 9955, 3080), vault unlock, persistent reconnect by default.
- **SOCKS5 Proxy** (`-D`): Dynamic port forwarding via SOCKS5 proxy with CONNECT support
- **Remote Port Forwarding** (`-R`): Full implementation — client sends GlobalRequest(TcpipForward), server binds listener, opens ForwardedTcpip channels back to client for bidirectional bridging
- **PTY Dimension Tracking**: Sends terminal dimensions on connect, handles SIGWINCH resize

### Changed

- Transport crypto uses `Arc<RwLock<SymmetricCrypto>>` instead of `Arc<SymmetricCrypto>` for atomic rekey
- Default transport is quantum-native (768-byte frames)

### Fixed

- Removed dead code (unused imports, unreachable branches)
- Cleaned up unused `AsyncReadExt`, `KeyType` imports

## [0.2.0] - 2026-02-14

### Added

- **Security Tiers (T0-T5)**: Configurable security levels based on threat model
- **Connection Multiplexing**: Full SSH-style ControlMaster implementation
- **Quantum Transport KEM**: Complete bidirectional key exchange
- **Session Encryption**: HKDF-based session key derivation + AES-256-GCM

### Fixed

- DirectTcpipChannel::into_stream() returns Result instead of panic!
- Session keys no longer use placeholder zeros

### Security

- Removed vulnerable Kyber algorithms (KyberSlash)
- Added replay attack protection with sequence numbers
- Fixed frame sizes (768 bytes) for traffic analysis resistance

### Known Issues (resolved in v0.4.0)

- ~~Falcon algorithm segfaults on macOS~~ — resolved (pure Rust crypto backend)
- ~~ProxyJump/ProxyCommand incomplete~~ — resolved (multi-hop chaining)
