# Changelog

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
