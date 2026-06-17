#!/usr/bin/env bash
#
# One-time bootstrap of the Paraxiom APT repository ON the OVH VPS.
# Run as a sudo-capable user on the VPS (148.113.197.101).
#
#   curl -fsSL <raw-url>/apt-repo-bootstrap.sh | sudo bash
#   (or copy it over and: sudo bash apt-repo-bootstrap.sh)
#
# Prereqs you must handle out-of-band:
#   - DNS A record:  apt.paraxiom.org -> 148.113.197.101
#   - TLS cert:      sudo certbot --nginx -d apt.paraxiom.org   (run after this)
#
set -euo pipefail

REPO_DIR=/srv/apt
SERVER_NAME=apt.paraxiom.org
KEY_NAME="Paraxiom APT Signing Key"
KEY_EMAIL="apt@paraxiom.org"
GNUPGHOME=/srv/apt-gnupg          # dedicated keyring, root-owned

echo "==> Installing reprepro, gnupg, nginx"
apt-get update -y
apt-get install -y reprepro gnupg nginx

echo "==> Preparing GPG keyring at $GNUPGHOME"
mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
export GNUPGHOME

if ! gpg --list-secret-keys "$KEY_EMAIL" >/dev/null 2>&1; then
  echo "==> Generating passphraseless signing key (for unattended reprepro signing)"
  cat >/tmp/key.params <<EOF
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: $KEY_NAME
Name-Email: $KEY_EMAIL
Expire-Date: 0
%no-protection
%commit
EOF
  gpg --batch --gen-key /tmp/key.params
  rm -f /tmp/key.params
fi

KEYID=$(gpg --list-keys --with-colons "$KEY_EMAIL" | awk -F: '/^pub:/{print $5; exit}')
echo "==> Signing key id: $KEYID"

echo "==> Laying down repo skeleton at $REPO_DIR"
mkdir -p "$REPO_DIR/conf" "$REPO_DIR/incoming"
cat >"$REPO_DIR/conf/distributions" <<EOF
Origin: Paraxiom
Label: Paraxiom
Suite: stable
Codename: stable
Architectures: amd64 arm64
Components: main
Description: Paraxiom APT repository (post-quantum tooling)
SignWith: $KEYID
EOF
cat >"$REPO_DIR/conf/options" <<EOF
verbose
basedir $REPO_DIR
EOF

echo "==> Exporting public key to $REPO_DIR/paraxiom.gpg"
gpg --export "$KEYID" > "$REPO_DIR/paraxiom.gpg"

echo "==> Initialising the (empty) repo"
reprepro -b "$REPO_DIR" export

echo "==> nginx site for $SERVER_NAME"
cat >/etc/nginx/sites-available/apt-paraxiom <<EOF
server {
    listen 80;
    server_name $SERVER_NAME;
    root $REPO_DIR;
    autoindex on;
    # Never serve the conf/ (distributions, signing config) or the keyring dir
    location ~ ^/(conf|incoming)/ { deny all; }
}
EOF
ln -sf /etc/nginx/sites-available/apt-paraxiom /etc/nginx/sites-enabled/apt-paraxiom
nginx -t && systemctl reload nginx

# Let reprepro write the repo as the deploy user (so CI/scp publish works).
# Adjust 'ubuntu' if you publish as a different user.
chown -R ubuntu:ubuntu "$REPO_DIR"

cat <<EOF

==> DONE.
Next:
  1. Point DNS:   apt.paraxiom.org -> 148.113.197.101
  2. Get TLS:     sudo certbot --nginx -d $SERVER_NAME
  3. Publish a package from your build host:
        ./scripts/publish-apt.sh target/debian/qssh_*.deb
  4. End users install with the snippet in README.md / docs/APT-REPO.md

Signing key id: $KEYID
Public key served at: https://$SERVER_NAME/paraxiom.gpg
EOF
