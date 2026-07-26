# Maintainers

This document lists the people with access to sensitive resources in the QSSH project and describes their roles.

## Active maintainers

| Name | GitHub | Email | Role | Scope |
|------|--------|-------|------|-------|
| Sylvain Cormier | [@Silvereau](https://github.com/Silvereau) | sylvain@paraxiom.org | Lead maintainer | All — code, releases, secrets, infra |

## Roles

### Lead maintainer
- Merges pull requests to `main`
- Cuts releases and signs release artifacts
- Holds repository admin permissions
- Manages security disclosures (see [SECURITY.md](SECURITY.md))
- Sets project direction and roadmap

### Reviewer (future role)
- Reviews and approves pull requests
- Triages issues
- Does not hold admin permissions or release signing keys

## Becoming a maintainer

Contributors who demonstrate sustained, high-quality contributions over time may be invited to join as reviewers, and later as maintainers. Escalation to any role with sensitive access requires:

1. A public track record of merged contributions
2. Review and approval by the lead maintainer
3. Agreement to the responsibilities in this document
4. Establishment of verifiable identity (e.g., GPG-signed commits or equivalent)

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution process.

## Sensitive resource access

The following resources require maintainer-level access:

- Repository admin settings (branch protection, secrets, collaborators)
- Release signing keys (cosign / Sigstore / GPG)
- CI/CD secrets
- Vulnerability disclosure intake (sylvain@paraxiom.org)

All access changes are logged via GitHub's audit log.

## Emeritus maintainers

None at this time.
