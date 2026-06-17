#!/usr/bin/env bash
#
# Publish a built .deb to the Paraxiom APT repo on the OVH VPS.
# reprepro (which holds the signing key) runs ON the VPS, so the key never
# leaves the server.
#
# Usage:
#   ./scripts/publish-apt.sh target/debian/qssh_0.4.0-1_amd64.deb
#
# Env overrides:
#   APT_VPS=ubuntu@148.113.197.101   APT_REPO_DIR=/srv/apt   APT_CODENAME=stable
#
set -euo pipefail

DEB="${1:?usage: publish-apt.sh <path-to-.deb>}"
[ -f "$DEB" ] || { echo "no such file: $DEB" >&2; exit 1; }

VPS="${APT_VPS:-ubuntu@148.113.197.101}"
REPO_DIR="${APT_REPO_DIR:-/srv/apt}"
CODENAME="${APT_CODENAME:-stable}"
base="$(basename "$DEB")"

echo "==> Uploading $base to $VPS:$REPO_DIR/incoming/"
scp "$DEB" "$VPS:$REPO_DIR/incoming/$base"

echo "==> reprepro includedeb $CODENAME ($base)"
ssh "$VPS" "reprepro -b '$REPO_DIR' includedeb '$CODENAME' '$REPO_DIR/incoming/$base' && rm -f '$REPO_DIR/incoming/$base'"

echo "==> Published. Verify:  apt-get update && apt-cache policy qssh"
