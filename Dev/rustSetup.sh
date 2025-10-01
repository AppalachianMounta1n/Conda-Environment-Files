#!/bin/bash
# Post-installation script to complete Rust toolchain setup
# Run this after creating your conda environment with: bash setup-rust-tools.sh

set -e

echo "Setting up complete Rust toolchain..."

# Verify conda environment is activated
if [ -z "$CONDA_DEFAULT_ENV" ] || [ "$CONDA_DEFAULT_ENV" = "base" ]; then
    echo "ERROR: Please activate your 'dev' conda environment first:"
    echo "  conda activate dev"
    exit 1
fi

# Check if rustc is available
if ! command -v rustc &> /dev/null; then
    echo "ERROR: rustc not found. Please ensure the conda environment was created successfully."
    exit 1
fi

echo "Found Rust $(rustc --version)"

# Install rustup if not already installed (for component management)
if ! command -v rustup &> /dev/null; then
    echo "Installing rustup for component management..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain none
    source "$HOME/.cargo/env"
fi

# Get the Rust version from conda
RUST_VERSION=$(rustc --version | awk '{print $2}')
echo "Configuring rustup to use Rust $RUST_VERSION from conda..."

# Link conda's rust to rustup's toolchain
CONDA_PREFIX_PATH="${CONDA_PREFIX:-$HOME/miniconda3/envs/dev}"
rustup toolchain link conda-rust "$CONDA_PREFIX_PATH"
rustup default conda-rust

# Install additional components
echo "Installing rustfmt..."
rustup component add rustfmt 2>/dev/null || echo "rustfmt already installed or using conda version"

echo "Installing clippy..."
rustup component add clippy 2>/dev/null || echo "clippy already installed or using conda version"

# Verify installations
echo ""
echo "Verification:"
echo "  rustc: $(rustc --version)"
echo "  cargo: $(cargo --version)"
echo "  rustfmt: $(rustfmt --version 2>/dev/null || echo 'Not available via component')"
echo "  clippy: $(cargo clippy --version 2>/dev/null || echo 'Not available via component')"

echo ""
echo "✓ Rust toolchain setup complete!"
echo ""
echo "Note: The conda-forge rust package includes rustc and cargo."
echo "If rustfmt/clippy aren't available, they're bundled with cargo and can be used via:"
echo "  cargo fmt"
echo "  cargo clippy"