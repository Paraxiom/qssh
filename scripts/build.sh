#!/bin/bash
# Build QSSH for release

set -e

echo "Building QSSH..."

# Check Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Rust not installed. Visit https://rustup.rs"
    exit 1
fi

# Build in release mode
cargo build --release

# Create binary directory
mkdir -p dist

# Copy binaries
cp target/release/qssh dist/
cp target/release/qsshd dist/
cp target/release/qssh-keygen dist/
cp target/release/qssh-agent dist/
cp target/release/qssh-add dist/

echo "Build complete! Binaries in dist/"
echo ""
echo "To install system-wide:"
echo "  sudo cp dist/* /usr/local/bin/"
echo ""
echo "To test:"
echo "  ./dist/qssh --help"