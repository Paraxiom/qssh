# Security policy

## Supported versions

| Version | Status |
|---|---|
| 0.4.2 and later | supported |
| 0.4.1 and earlier | not supported; default key exchange has no confidentiality, upgrade |

## Reporting a vulnerability

Write to **sylvain@paraxiom.org** with a description and, if you have one, a
reproduction. Please give us a reasonable window before public disclosure; we
are a very small team and will answer as soon as we can. We publish fixes as
crates.io releases and record them in [CHANGELOG.md](CHANGELOG.md).

## Known issues

| Date found | Affected | Issue | Fixed in |
|---|---|---|---|
| 2026-07-15 | < 0.4.2 | Default `FalconSignedShares` key exchange derives the session key from cleartext values; passive observers can reconstruct it. The client ignored the configured algorithm. | 0.4.2 (PR #5, 2026-07-16) |

Sessions established under the old default should be treated as having had no
confidentiality against a passive attacker. Authentication was not affected.
