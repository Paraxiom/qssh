# Paraxiom APT repository (apt.paraxiom.org)

Self-hosted, GPG-signed APT repository served from the OVH VPS
(`148.113.197.101`), built with `reprepro`. The signing key lives **only on the
VPS** — it is never copied into CI.

```
build host / CI            OVH VPS (apt.paraxiom.org)
-----------------          --------------------------------
cargo deb  ──► .deb ──scp──► /srv/apt/incoming/
                           reprepro includedeb stable  (signs Release)
                           nginx serves /srv/apt over HTTPS
end user ◄── apt-get install qssh ◄────────────────────┘
```

## 1. One-time server setup (on the VPS)

Prereqs (do these first):
- DNS: `apt.paraxiom.org` → `148.113.197.101`
- copy `scripts/apt-repo-bootstrap.sh` to the VPS

```bash
sudo bash apt-repo-bootstrap.sh          # installs reprepro/gnupg/nginx,
                                         # generates the signing key,
                                         # creates /srv/apt, configures nginx
sudo certbot --nginx -d apt.paraxiom.org # TLS
```

The bootstrap prints the signing **key id** and exports the public key to
`/srv/apt/paraxiom.gpg` (served at `https://apt.paraxiom.org/paraxiom.gpg`).

## 2. Publish a package (from your build host)

```bash
# on a Linux build host:
cargo deb                                  # -> target/debian/qssh_0.4.0-1_amd64.deb
./scripts/publish-apt.sh target/debian/qssh_*.deb
```

`publish-apt.sh` scp's the `.deb` to `/srv/apt/incoming/` and runs
`reprepro includedeb stable …` over SSH (reprepro signs the `Release` with the
on-VPS key). Override targets with `APT_VPS`, `APT_REPO_DIR`, `APT_CODENAME`.

## 3. End-user install

```bash
curl -fsSL https://apt.paraxiom.org/paraxiom.gpg | sudo tee /usr/share/keyrings/paraxiom.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/paraxiom.gpg] https://apt.paraxiom.org stable main" \
  | sudo tee /etc/apt/sources.list.d/paraxiom.list
sudo apt-get update
sudo apt-get install qssh
```

## Maintenance

```bash
# list what's published
reprepro -b /srv/apt list stable

# remove a package
reprepro -b /srv/apt remove stable qssh

# the repo is plain files under /srv/apt — back that dir up (and the
# /srv/apt-gnupg keyring, which is the irreplaceable signing key)
```

## Optional: publish from CI instead of a laptop

Add an SSH **deploy key** for the VPS, store its private half as the
`APT_DEPLOY_KEY` GitHub secret, and append a job to `.github/workflows/` that,
after `cargo deb`, runs `scripts/publish-apt.sh`. Keep the *signing* key on the
VPS regardless — CI only needs SSH to trigger `reprepro`.

## arm64

`cargo deb --target aarch64-unknown-linux-gnu` (or `make deb-cross
TARGET=aarch64-unknown-linux-gnu`) produces an arm64 `.deb`; publish it the same
way — the repo already lists `arm64` in `conf/distributions`.
