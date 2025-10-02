#!/bin/bash
# Complete setup script for CTF environment (Linux/macOS)
# This script will:
# 1. Create/update the conda environment
# 2. Run tests for key CTF tools

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_NAME="ctf"

echo "=========================================="
echo "CTF Environment Setup Script"
echo "=========================================="
echo ""

# Step 1: Create or update conda environment
echo "Step 1: Creating/updating conda environment..."
echo "This may take 10-20 minutes depending on your connection..."
if conda env list | grep -q "^${ENV_NAME} "; then
    echo "Environment '${ENV_NAME}' exists. Updating..."
    conda env update -f "${SCRIPT_DIR}/linux-ctf.yml" --prune
else
    echo "Creating new environment '${ENV_NAME}'..."
    conda env create -f "${SCRIPT_DIR}/linux-ctf.yml"
fi

echo ""
echo "Step 2: Activating environment..."
# Activate the environment
eval "$(conda shell.bash hook)"
conda activate ${ENV_NAME}

if [ "$CONDA_DEFAULT_ENV" != "${ENV_NAME}" ]; then
    echo "ERROR: Failed to activate environment"
    exit 1
fi

echo "Environment activated: ${CONDA_DEFAULT_ENV}"
echo ""

echo "=========================================="
echo "Running Tool Tests"
echo "=========================================="
echo ""

# Test Python
echo "Testing Python..."
python --version || echo "✗ Python FAILED"
echo ""

# Test pwntools
echo "Testing pwntools..."
python -c "from pwn import *; print('✓ pwntools version:', pwntools.version.version)" || echo "✗ pwntools FAILED"
echo ""

# Test angr
echo "Testing angr..."
python -c "import angr; print('✓ angr OK')" || echo "✗ angr FAILED"
echo ""

# Test scapy
echo "Testing scapy..."
python -c "from scapy.all import *; print('✓ scapy OK')" || echo "✗ scapy FAILED"
echo ""

# Test cryptography
echo "Testing pycryptodome..."
python -c "from Crypto.Cipher import AES; print('✓ pycryptodome OK')" || echo "✗ pycryptodome FAILED"
echo ""

# Test z3
echo "Testing z3-solver..."
python -c "from z3 import *; x = Int('x'); print('✓ z3-solver OK')" || echo "✗ z3-solver FAILED"
echo ""

# Test capstone
echo "Testing capstone..."
python -c "import capstone; print('✓ capstone OK')" || echo "✗ capstone FAILED"
echo ""

# Test keystone
echo "Testing keystone..."
python -c "import keystone; print('✓ keystone OK')" || echo "✗ keystone FAILED"
echo ""

# Test unicorn
echo "Testing unicorn..."
python -c "import unicorn; print('✓ unicorn OK')" || echo "✗ unicorn FAILED"
echo ""

# Test ROPgadget
echo "Testing ROPgadget..."
ROPgadget --version > /dev/null 2>&1 && echo "✓ ROPgadget OK" || echo "✗ ROPgadget FAILED"
echo ""

# Test binwalk
echo "Testing binwalk..."
binwalk --help > /dev/null 2>&1 && echo "✓ binwalk OK" || echo "✗ binwalk FAILED"
echo ""

# Test requests
echo "Testing requests..."
python -c "import requests; print('✓ requests OK')" || echo "✗ requests FAILED"
echo ""

echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Environment '${ENV_NAME}' is ready for CTF competitions."
echo ""
echo "To activate the environment in a new terminal, run:"
echo "  conda activate ${ENV_NAME}"
echo ""
echo "Quick test - Generate cyclic pattern:"
python -c "from pwn import *; print(cyclic(20))" 2>/dev/null || echo "Run 'conda activate ctf' first"
echo ""
echo "For detailed tool usage, see CTF/README.md"
echo ""