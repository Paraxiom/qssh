# QSSH - Post-Quantum Secure Shell
# Multi-stage build with custom compile-time security policy
#
# Build args for per-user/org customization:
#   SECURITY_TIER   - minimum tier compiled in (t0|t1|t2|t3|t4|t5, default: all)
#   FEATURES        - cargo features to enable (default: sftp,hybrid-kex)
#   STRIP           - strip debug symbols (default: true)
#
# Examples:
#   docker build -t qssh .
#   docker build -t qssh-hardened --build-arg SECURITY_TIER=t3 --build-arg FEATURES=sftp,quantum-native .

# ── Stage 1: Build ────────────────────────────────────────────────
FROM rust:1.85-slim-bookworm AS builder

ARG FEATURES="sftp,hybrid-kex"
ARG STRIP="true"

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libgmp-dev \
    libc6-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy sources to cache dependency compilation
RUN mkdir -p src/bin examples && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs && \
    for bin in qssh qsshd qscp qssh-add qssh-agent qssh-keygen qssh-passwd qsshpass qssh-sign qssh-node test_pqcrypto; do \
      echo "fn main() {}" > src/bin/${bin}.rs; \
    done && \
    echo "fn main() {}" > examples/quantum_harmony_validator.rs && \
    cargo build --release --features "${FEATURES}" \
      --bin qssh --bin qsshd --bin qscp --bin qssh-keygen --bin qssh-sign 2>/dev/null || true && \
    rm -rf src examples

# Copy real source
COPY src/ src/
COPY examples/ examples/

# Build with selected features
RUN cargo build --release --features "${FEATURES}" \
    --bin qssh --bin qsshd --bin qscp --bin qssh-keygen --bin qssh-sign

# Strip binaries if requested
RUN if [ "$STRIP" = "true" ]; then \
      strip target/release/qssh \
            target/release/qsshd \
            target/release/qscp \
            target/release/qssh-keygen \
            target/release/qssh-sign; \
    fi

# ── Stage 2: Runtime ──────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libgmp10 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for runtime
RUN groupadd -r qssh && useradd -r -g qssh -d /home/qssh -s /bin/bash qssh && \
    mkdir -p /home/qssh/.qssh /etc/qssh /var/log/qssh && \
    chown -R qssh:qssh /home/qssh /var/log/qssh

# Copy binaries
COPY --from=builder /build/target/release/qssh /usr/local/bin/
COPY --from=builder /build/target/release/qsshd /usr/local/bin/
COPY --from=builder /build/target/release/qscp /usr/local/bin/
COPY --from=builder /build/target/release/qssh-keygen /usr/local/bin/
COPY --from=builder /build/target/release/qssh-sign /usr/local/bin/

# Copy config and entrypoint
COPY qsshd.config.production /etc/qssh/qsshd.conf
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Labels
LABEL org.opencontainers.image.title="QSSH - Post-Quantum Secure Shell" \
      org.opencontainers.image.description="SSH with NIST PQC (Falcon, SPHINCS+, ML-KEM), 909 Lean 4 formal proofs" \
      org.opencontainers.image.vendor="Paraxiom Technologies Inc." \
      org.opencontainers.image.source="https://github.com/Paraxiom/qssh" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

EXPOSE 22222

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD bash -c 'echo > /dev/tcp/localhost/22222' 2>/dev/null || exit 1

# Entrypoint runs as root to provision users, then drops to qssh for server
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--listen", "0.0.0.0:22222", "--quantum-native"]
