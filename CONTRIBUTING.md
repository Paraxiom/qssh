# Contributing to QSSH

Thank you for your interest in QSSH. This project implements post-quantum SSH, so contribution quality and security hygiene matter.

## Getting started

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-change`
3. Make your changes with tests
4. Ensure CI passes locally (see [Testing](#testing))
5. Open a pull request against `main`

## Legal: Developer Certificate of Origin (DCO)

All commits must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/). This certifies that you wrote the code or have the right to submit it under the project's dual MIT/Apache-2.0 license.

Sign off your commits with `-s`:

```
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <your@email>` line. Commits without a sign-off will be rejected by CI.

## Code standards

- **Formatting:** `cargo fmt --all` must produce no changes
- **Linting:** `cargo clippy --all-targets -- -D warnings` must pass (no advisory escapes)
- **Unsafe code:** Avoid `unsafe` blocks in cryptographic paths. If unavoidable, include a safety comment explaining the invariant
- **No generated artifacts:** Do not commit binaries, build output, or generated code
- **Dependencies:** Prefer the minimum necessary. Justify new deps in the PR description

## Testing

All changes must include or update tests.

- Unit tests live alongside the code: `cargo test --lib`
- Integration tests in `tests/`: `cargo test --test <name>`
- Formal proofs (Lean, kani, verus) in their respective directories — update if you change the proven surface

Run the full suite before opening a PR:

```
make test
```

## Security-sensitive changes

If your change touches cryptographic primitives, key handling, authentication, or transport framing, tag the PR with `security-review` and expect a longer review cycle. Do not open public issues for suspected vulnerabilities — see [SECURITY.md](SECURITY.md).

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add ML-KEM-768 support
fix: prevent race in port forwarding
docs: clarify QKD integration
test: add MockTransport for X11
```

## Review process

- One non-author maintainer must approve before merge
- All required CI checks must pass (build, test, clippy, DCO)
- Maintainers may request changes, additional tests, or design discussion
- Substantial changes should be discussed in an issue first

## Where to ask questions

- Usage questions: open a [GitHub issue](https://github.com/Paraxiom/qssh/issues) with the `question` label
- Design discussions: open an issue with the `rfc` label
- Security: email sylvain@paraxiom.org (do not open public issues)

## License

By contributing, you agree that your contributions are licensed under the terms of both [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
