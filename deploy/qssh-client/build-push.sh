#!/usr/bin/env bash
# Build the qssh-client image for the OVH MKS target (linux/amd64) and push it
# to the Transparence Harbor. Run from the qssh source-tree root the moment you
# have the Harbor robot credentials.
#
#   HARBOR_USER='robot$transparence+paraxiom' \
#   HARBOR_TOKEN='<robot-secret>' \
#   TAG='1.0.0' \
#     bash deploy/qssh-client/build-push.sh
#
# Then set in the chart:  services.trust.qhTunnel.image=<printed ref>
set -euo pipefail

REGISTRY="${REGISTRY:-7c03mk74.c1.bhs5.container-registry.ovh.net}"
PROJECT="${PROJECT:-transparence}"
IMAGE="${IMAGE:-paraxiom-qssh-client}"
PLATFORM="${PLATFORM:-linux/amd64}"          # MKS nodes are amd64; the Mac is arm64
DOCKERFILE="deploy/qssh-client/Dockerfile"
TAG="${TAG:?set TAG, e.g. TAG=1.0.0}"
REF="${REGISTRY}/${PROJECT}/${IMAGE}:${TAG}"

: "${HARBOR_USER:?set HARBOR_USER (Harbor robot account)}"
: "${HARBOR_TOKEN:?set HARBOR_TOKEN (Harbor robot secret)}"

# Dedicated buildx builder (created once, reused thereafter).
docker buildx inspect qssh-builder >/dev/null 2>&1 || docker buildx create --name qssh-builder
docker buildx use qssh-builder

printf '%s' "$HARBOR_TOKEN" | docker login "$REGISTRY" -u "$HARBOR_USER" --password-stdin

docker buildx build \
  --platform "$PLATFORM" \
  -f "$DOCKERFILE" \
  -t "$REF" \
  --provenance=false \
  --push \
  .

echo
echo "pushed: $REF"
echo "next:   set services.trust.qhTunnel.image=\"$REF\" in the chart values"
