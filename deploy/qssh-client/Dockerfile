# qssh client image — used as the QH tunnel sidecar in trust-services
# (Transparence). Builds the `qssh` binary (+ keygen) and ships a minimal,
# non-root runtime that matches the chart's pod securityContext (uid 65532).
#
# Build context = the qssh source tree root:
#   docker build -t paraxiom-qssh-client -f deploy/qssh-client/Dockerfile .
#
# Tag + push to the Transparence Harbor project, then set
# services.trust.qhTunnel.image in the chart:
#   7c03mk74.c1.bhs5.container-registry.ovh.net/transparence/paraxiom-qssh-client:<tag>

# ---- builder ----------------------------------------------------------------
# rust:1-slim-bookworm (latest stable on Debian bookworm). MUST stay on
# bookworm so the binary's glibc matches the bookworm-slim runtime below
# (a trixie builder links glibc 2.39 and fails on bookworm's 2.36).
# A transitive dep requires edition2024 (Rust 1.85) — do NOT pin below 1.85.
FROM rust:1-slim-bookworm AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
# Client only. qssh-keygen is included so the image can mint a key offline
# if ever needed; the tunnel itself uses the key provisioned via OKMS.
RUN cargo build --release --locked --bin qssh --bin qssh-keygen

# ---- runtime ----------------------------------------------------------------
FROM debian:bookworm-slim
# libssl3 is required at runtime: qssh links system OpenSSL via
# reqwest(native-tls). ca-certificates for any TLS-fronted QKD endpoint.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 65532 --create-home --home-dir /home/nonroot \
            --shell /usr/sbin/nologin nonroot

COPY --from=builder /build/target/release/qssh        /usr/local/bin/qssh
COPY --from=builder /build/target/release/qssh-keygen  /usr/local/bin/qssh-keygen

# qssh resolves ~/.qssh/{id_qssh,known_hosts,config}. The chart mounts the
# OKMS-provisioned key dir over /home/nonroot/.qssh, so HOME must point here.
ENV HOME=/home/nonroot
USER 65532:65532

ENTRYPOINT ["qssh"]
CMD ["--help"]
