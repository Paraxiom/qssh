# Changelog

## 0.5.0 (2026-09-14), protocol 0.2: the in-band rekey rewritten

Fixes the July 2026 rekey desync (busy forward tunnels dying with
`failed to read frame length: early eof` at every hourly rotation; the
Transparence anchoring sidecar was its first casualty).

- **One reader.** Rekey control frames (`RekeyInit`, `RekeyReply`,
  `NewKeys`) are consumed inside `Transport::receive_message` by whichever
  task owns the reader. The timer task no longer reads from the transport,
  so it can no longer steal data frames or lose the reply.
- **Two-phase key switch.** Each side switches its send key right after
  writing its own `NewKeys` (under the writer lock) and its receive key
  right after reading the peer's. Frames are strictly ordered per
  direction, so no frame is decrypted under the wrong epoch. `send_message`
  now takes the writer lock before sequencing and encrypting, which is what
  makes the switch atomic against concurrent senders.
- **ML-KEM-1024 per rotation.** The old rekey derived the new keys from
  Falcon-signed cleartext shares (no forward secrecy across rotations).
  Each rotation now encapsulates to a fresh ML-KEM-1024 key, chained to the
  previous epoch through an HKDF-SHA3-256 salt seeded from the handshake.
- **Protocol 0.2.** 0.1 peers are refused at the version check; a legacy
  `Rekey` message is refused with a protocol error. Both ends must run 0.5.0.
- Tests: `tests/rekey_transport.rs` drives 3000 frames each way with four
  rotations initiated from both sides, checks nothing is lost or reordered,
  and covers the idle, double-initiation and stray-`NewKeys` cases.
- The `key_rotation_interval` default (3600 s) is unchanged and is now safe
  on busy tunnels; the `0` workaround from July is no longer needed.


## 0.4.4 (2026-09-14), documentation only

- README reframed: qssh is its own protocol *by design* (pure Rust, no
  OpenSSH or OpenSSL code, no GSSAPI), not a defect; the 0.4.3 wording read
  as a limitation. Comparison with OpenSSH kept factual: OpenSSH ships hybrid
  post-quantum key exchange; qssh adds post-quantum authentication and a
  single auditable codebase. No code change from 0.4.2.

## 0.4.3 (2026-09-13), documentation only

- README rewritten to state what qssh is and is not: its own protocol, not
  wire compatible with OpenSSH; OpenSSH already ships hybrid post-quantum key
  exchange by default; qssh adds post-quantum authentication. Verification
  claims reduced to what is reproduced (71 Lean conformance lemmas; Kani and
  Verus harnesses not run in CI; protocol security not verified). No code
  change from 0.4.2.

## 0.4.2 (2026-09-13), security release

- **Default key exchange is now ML-KEM-1024.** Before this release the default,
  `FalconSignedShares`, derived the session key from values exchanged in
  cleartext: authentication only, no confidentiality against a passive
  observer. (`e4bc533`)
- **The client honours the configured `KexAlgorithm`.** It previously hardcoded
  the default, so ML-KEM could not be selected from the command line even
  though the exchange existed in the crate. (`d0da415`)
- Regression test guarding the default against falling back to a
  non-confidential exchange. (`583d132`)
- Licence: GPL-3.0-only, or a Paraxiom commercial licence (`fe89b16`); Debian
  package metadata aligned with it.
- Distribution: every crates.io version before 0.4.2 is yanked. The v0.4.1
  GitHub release, the Homebrew formula and the APT package were built from the
  2026-06-19 tag, which predates the fix; they carry the old default and are
  superseded by 0.4.2.

## 0.4.1 (2026-06-19)

- Debian packaging (`cargo deb`), APT repository and Homebrew tap. Same default
  key exchange as 0.4.0, so affected by the issue above. Never published to
  crates.io.

## 0.4.0 (2026-02-23) and earlier

- See the git tags. All affected by the default key exchange issue above;
  0.1.0 and the 0.0.x alphas have no ML-KEM exchange at all.
