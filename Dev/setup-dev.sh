#!/bin/bash
# Complete setup script for Dev environment (Linux/macOS)
# This script will:
# 1. Create/update the conda environment
# 2. Set up the complete Rust toolchain
# 3. Run tests for all languages

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_NAME="dev"

echo "=========================================="
echo "Dev Environment Setup Script"
echo "=========================================="
echo ""

# Step 1: Create or update conda environment
echo "Step 1: Creating/updating conda environment..."
if conda env list | grep -q "^${ENV_NAME} "; then
    echo "Environment '${ENV_NAME}' exists. Updating..."
    conda env update -f "${SCRIPT_DIR}/linux-dev.yml" --prune
else
    echo "Creating new environment '${ENV_NAME}'..."
    conda env create -f "${SCRIPT_DIR}/linux-dev.yml"
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

# Step 3: Setup Rust toolchain
echo "Step 3: Setting up Rust toolchain..."
if [ -f "${SCRIPT_DIR}/setup-rust-tools.sh" ]; then
    bash "${SCRIPT_DIR}/setup-rust-tools.sh"
else
    echo "Warning: setup-rust-tools.sh not found, skipping Rust toolchain setup"
fi

echo ""
echo "=========================================="
echo "Running Language Tests"
echo "=========================================="
echo ""

# Create temp directory for tests
TEST_DIR=$(mktemp -d)
cd "${TEST_DIR}"

# Test Python
echo "Testing Python..."
python -c "import numpy; import pandas; import matplotlib; print('✓ Python OK')" || echo "✗ Python FAILED"
echo ""

# Test Go
echo "Testing Go..."
cat > test.go << 'EOF'
package main
import "fmt"
func main() {
    fmt.Println("✓ Go OK")
}
EOF
go run test.go || echo "✗ Go FAILED"
echo ""

# Test Rust
echo "Testing Rust..."
cat > test.rs << 'EOF'
fn main() {
    println!("✓ Rust OK");
}
EOF
rustc test.rs && ./test || echo "✗ Rust FAILED"
echo ""

# Test Zig
echo "Testing Zig..."
cat > test.zig << 'EOF'
const std = @import("std");
pub fn main() !void {
    std.debug.print("✓ Zig OK\n", .{});
}
EOF
zig run test.zig || echo "✗ Zig FAILED"
echo ""

# Test Java
echo "Testing Java..."
cat > Test.java << 'EOF'
public class Test {
    public static void main(String[] args) {
        System.out.println("✓ Java OK");
    }
}
EOF
javac Test.java && java Test || echo "✗ Java FAILED"
echo ""

# Test C
echo "Testing C..."
cat > test.c << 'EOF'
#include <stdio.h>
int main() {
    printf("✓ C OK\n");
    return 0;
}
EOF
gcc test.c -o test_c && ./test_c || echo "✗ C FAILED"
echo ""

# Test C++
echo "Testing C++..."
cat > test.cpp << 'EOF'
#include <iostream>
int main() {
    std::cout << "✓ C++ OK" << std::endl;
    return 0;
}
EOF
g++ test.cpp -o test_cpp && ./test_cpp || echo "✗ C++ FAILED"
echo ""

# Test Fortran
echo "Testing Fortran..."
cat > test.f90 << 'EOF'
program test
    print *, "✓ Fortran OK"
end program test
EOF
gfortran test.f90 -o test_fortran && ./test_fortran || echo "✗ Fortran FAILED"
echo ""

# Test COBOL (Linux/macOS only)
if command -v cobc &> /dev/null; then
    echo "Testing COBOL..."
    cat > test.cob << 'EOF'
       IDENTIFICATION DIVISION.
       PROGRAM-ID. TEST.
       PROCEDURE DIVISION.
           DISPLAY "✓ COBOL OK".
           STOP RUN.
EOF
    cobc -x test.cob -o test_cobol && ./test_cobol || echo "✗ COBOL FAILED"
    echo ""
else
    echo "COBOL not available (expected on macOS)"
    echo ""
fi

# Cleanup
cd - > /dev/null
rm -rf "${TEST_DIR}"

echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Environment '${ENV_NAME}' is ready to use."
echo ""
echo "To activate the environment in a new terminal, run:"
echo "  conda activate ${ENV_NAME}"
echo ""
echo "Language versions:"
python --version 2>&1 | sed 's/^/  /'
go version 2>&1 | sed 's/^/  /'
rustc --version 2>&1 | sed 's/^/  /'
zig version 2>&1 | sed 's/^/  /'
javac -version 2>&1 | sed 's/^/  /'
gcc --version 2>&1 | head -n1 | sed 's/^/  /'
gfortran --version 2>&1 | head -n1 | sed 's/^/  /'
if command -v cobc &> /dev/null; then
    cobc --version 2>&1 | head -n1 | sed 's/^/  /'
fi
echo ""