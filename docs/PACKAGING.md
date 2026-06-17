# Packaging QSSH for Linux (.deb)

QSSH ships a Debian/Ubuntu package built with
[`cargo-deb`](https://github.com/kornelski/cargo-deb) directly from the
`[package.metadata.deb]` section of `Cargo.toml`. No hand-maintained `debian/`
tree is required.

## What's in the package

| Path | Contents |
|------|----------|
| `/usr/bin/qssh`, `qsshd`, `qscp`, `qssh-keygen`, `qssh-passwd`, `qssh-agent`, `qssh-sign`, `qssh-add`, `qssh-node` | the 9 binaries |
| `/etc/qssh/qsshd.config` | production config (conffile) |
| `/etc/qssh/qsshd.env` | systemd runtime options — listen address, extra flags (conffile) |
| `/lib/systemd/system/qsshd.service` | systemd unit for the daemon |
| `/usr/share/doc/qssh/` | README + this file |

`depends = "$auto"` lets cargo-deb compute the shared-library dependencies from
the compiled binaries (e.g. `libssl`, `libc6`) — no manual dependency list to
keep in sync.

## Build it

> **Must be built on Linux** (or for a Linux cross-target). Building on macOS
> would produce Mach-O binaries inside the `.deb`. Use a Debian/Ubuntu host, a
> container, or the CI workflow below.

```bash
# one-time
cargo install cargo-deb

# build (compiles --release, then packages)
cargo deb            # or: make deb

# output:
#   target/debian/qssh_0.4.0-1_amd64.deb
```

Cross-build for amd64 from another Linux arch:

```bash
rustup target add x86_64-unknown-linux-gnu
cargo deb --target x86_64-unknown-linux-gnu   # or: make deb-cross TARGET=x86_64-unknown-linux-gnu
```

## Install & run

```bash
sudo apt install ./qssh_0.4.0-1_amd64.deb

# the service is ENABLED on install but NOT started, so you can review config first.
sudoedit /etc/qssh/qsshd.env       # set listen address / port
sudo systemctl start qsshd         # generates a Falcon-512 host key on first start
systemctl status qsshd
journalctl -u qsshd -f
```

The unit's `ExecStartPre` auto-creates `/etc/qssh/host_key` (Falcon-512) on the
first start if it does not already exist — analogous to OpenSSH host-key
generation. Add client public keys to `/etc/qssh/authorized_keys`.

## Notes

- The daemon runs as **root** (like `sshd`) because it spawns login sessions for
  other users; `DynamicUser`/`ProtectHome` are intentionally not set.
- `qsshd.config` and `qsshd.env` are registered as **conffiles**, so your edits
  survive package upgrades.
- To produce an `.rpm` as well, add `cargo-generate-rpm` and a
  `[package.metadata.generate-rpm]` section — not configured yet.
