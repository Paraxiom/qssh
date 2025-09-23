# QSSH - Quantum Secure Shell Docker Image
FROM rust:1.70-slim-bullseye AS builder

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
COPY Cargo.toml Cargo.lock ./

# Create dummy source to cache dependencies
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/qssh.rs && \
    echo "fn main() {}" > src/bin/qsshd.rs && \
    echo "fn main() {}" > src/bin/qscp.rs && \
    cargo build --release --bin qssh --bin qsshd --bin qscp && \
    rm -rf src

# Copy source code
COPY src/ src/
COPY examples/ examples/
COPY docs/ docs/

# Build the actual binaries
RUN cargo build --release --bin qssh --bin qsshd --bin qscp

# Runtime image
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl1.1 \
    libgmp10 \
    && rm -rf /var/lib/apt/lists/*

# Create qssh user
RUN useradd -r -s /bin/false qssh

# Copy binaries
COPY --from=builder /app/target/release/qssh /usr/local/bin/
COPY --from=builder /app/target/release/qsshd /usr/local/bin/
COPY --from=builder /app/target/release/qscp /usr/local/bin/

# Create directories
RUN mkdir -p /etc/qssh /var/log/qssh /home/qssh/.qssh && \
    chown -R qssh:qssh /home/qssh /var/log/qssh

# Copy configuration
COPY qsshd.config.production /etc/qssh/qsshd.conf

# Expose port
EXPOSE 22222

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD qssh -c "echo 'health check'" localhost || exit 1

# Default user
USER qssh

# Default command
CMD ["/usr/local/bin/qsshd", "--config", "/etc/qssh/qsshd.conf"]