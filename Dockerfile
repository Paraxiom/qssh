# QSSH - Quantum Secure Shell Docker Image
FROM rust:1.85-slim-bookworm AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libgmp-dev \
    libc6-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files first (for better caching)
COPY Cargo.toml ./
COPY Cargo.lock* ./

# Create dummy sources to cache dependencies (must match all bins/examples Cargo discovers)
RUN mkdir -p src/bin examples && \
    echo "fn main() {}" > src/main.rs && \
    for bin in qssh qsshd qscp qssh-add qssh-agent qssh-keygen qssh-passwd qsshpass qssh-sign qssh-node test_pqcrypto; do \
      echo "fn main() {}" > src/bin/${bin}.rs; \
    done && \
    echo "fn main() {}" > examples/quantum_harmony_validator.rs && \
    cargo build --release --bin qssh --bin qsshd --bin qscp --bin qssh-keygen --bin qssh-sign --bin qssh-node && \
    rm -rf src examples

# Copy source code
COPY src/ src/
COPY examples/ examples/
COPY docs/ docs/

# Build the actual binaries
RUN cargo build --release --bin qssh --bin qsshd --bin qscp --bin qssh-keygen --bin qssh-sign --bin qssh-node

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libgmp10 \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries
COPY --from=builder /app/target/release/qssh /usr/local/bin/
COPY --from=builder /app/target/release/qsshd /usr/local/bin/
COPY --from=builder /app/target/release/qscp /usr/local/bin/
COPY --from=builder /app/target/release/qssh-keygen /usr/local/bin/
COPY --from=builder /app/target/release/qssh-sign /usr/local/bin/
COPY --from=builder /app/target/release/qssh-node /usr/local/bin/

# Create directories
RUN mkdir -p /etc/qssh /var/log/qssh /home

# Copy configuration and entrypoint
COPY qsshd.config.production /etc/qssh/qsshd.conf
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose port
EXPOSE 22222

# Health check — verify qsshd is listening on port 22222
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD bash -c 'echo > /dev/tcp/localhost/22222' 2>/dev/null || exit 1

# Entrypoint provisions users and generates keys, then starts qsshd
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--listen", "0.0.0.0:22222", "--quantum-native"]