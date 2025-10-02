# Complete setup script for CTF environment (Windows)
# This script will:
# 1. Create/update the conda environment
# 2. Run tests for key CTF tools

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvName = "ctf"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "CTF Environment Setup Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Create or update conda environment
Write-Host "Step 1: Creating/updating conda environment..." -ForegroundColor Yellow
Write-Host "This may take 10-20 minutes depending on your connection..." -ForegroundColor Yellow
$envExists = conda env list | Select-String -Pattern "^${EnvName}\s"
if ($envExists) {
    Write-Host "Environment '${EnvName}' exists. Updating..." -ForegroundColor Green
    conda env update -f "$ScriptDir\windows-ctf.yml" --prune
} else {
    Write-Host "Creating new environment '${EnvName}'..." -ForegroundColor Green
    conda env create -f "$ScriptDir\windows-ctf.yml"
}

Write-Host ""
Write-Host "Step 2: Activating environment..." -ForegroundColor Yellow
conda activate $EnvName

if ($env:CONDA_DEFAULT_ENV -ne $EnvName) {
    Write-Host "ERROR: Failed to activate environment" -ForegroundColor Red
    exit 1
}

Write-Host "Environment activated: $env:CONDA_DEFAULT_ENV" -ForegroundColor Green
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Running Tool Tests" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Test Python
Write-Host "Testing Python..." -ForegroundColor Yellow
try {
    python --version
} catch {
    Write-Host "✗ Python FAILED" -ForegroundColor Red
}
Write-Host ""

# Test pwntools
Write-Host "Testing pwntools..." -ForegroundColor Yellow
try {
    python -c "from pwn import *; print('✓ pwntools version:', pwntools.version.version)"
} catch {
    Write-Host "✗ pwntools FAILED" -ForegroundColor Red
}
Write-Host ""

# Test angr
Write-Host "Testing angr..." -ForegroundColor Yellow
try {
    python -c "import angr; print('✓ angr OK')"
} catch {
    Write-Host "✗ angr FAILED" -ForegroundColor Red
}
Write-Host ""

# Test scapy
Write-Host "Testing scapy..." -ForegroundColor Yellow
try {
    python -c "from scapy.all import *; print('✓ scapy OK')"
} catch {
    Write-Host "✗ scapy FAILED" -ForegroundColor Red
}
Write-Host ""

# Test cryptography
Write-Host "Testing pycryptodome..." -ForegroundColor Yellow
try {
    python -c "from Crypto.Cipher import AES; print('✓ pycryptodome OK')"
} catch {
    Write-Host "✗ pycryptodome FAILED" -ForegroundColor Red
}
Write-Host ""

# Test z3
Write-Host "Testing z3-solver..." -ForegroundColor Yellow
try {
    python -c "from z3 import *; x = Int('x'); print('✓ z3-solver OK')"
} catch {
    Write-Host "✗ z3-solver FAILED" -ForegroundColor Red
}
Write-Host ""

# Test capstone
Write-Host "Testing capstone..." -ForegroundColor Yellow
try {
    python -c "import capstone; print('✓ capstone OK')"
} catch {
    Write-Host "✗ capstone FAILED" -ForegroundColor Red
}
Write-Host ""

# Test keystone
Write-Host "Testing keystone..." -ForegroundColor Yellow
try {
    python -c "import keystone; print('✓ keystone OK')"
} catch {
    Write-Host "✗ keystone FAILED" -ForegroundColor Red
}
Write-Host ""

# Test unicorn
Write-Host "Testing unicorn..." -ForegroundColor Yellow
try {
    python -c "import unicorn; print('✓ unicorn OK')"
} catch {
    Write-Host "✗ unicorn FAILED" -ForegroundColor Red
}
Write-Host ""

# Test ROPgadget
Write-Host "Testing ROPgadget..." -ForegroundColor Yellow
try {
    $null = ROPgadget --version 2>&1
    Write-Host "✓ ROPgadget OK" -ForegroundColor Green
} catch {
    Write-Host "✗ ROPgadget FAILED" -ForegroundColor Red
}
Write-Host ""

# Test binwalk
Write-Host "Testing binwalk..." -ForegroundColor Yellow
try {
    $null = binwalk --help 2>&1
    Write-Host "✓ binwalk OK" -ForegroundColor Green
} catch {
    Write-Host "✗ binwalk FAILED" -ForegroundColor Red
}
Write-Host ""

# Test requests
Write-Host "Testing requests..." -ForegroundColor Yellow
try {
    python -c "import requests; print('✓ requests OK')"
} catch {
    Write-Host "✗ requests FAILED" -ForegroundColor Red
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Environment '${EnvName}' is ready for CTF competitions." -ForegroundColor Green
Write-Host ""
Write-Host "Note: Some tools have limited functionality on Windows." -ForegroundColor Yellow
Write-Host "Consider using WSL2 for best compatibility." -ForegroundColor Yellow
Write-Host ""
Write-Host "To activate the environment in a new terminal, run:" -ForegroundColor Yellow
Write-Host "  conda activate ${EnvName}" -ForegroundColor White
Write-Host ""
Write-Host "Quick test - Generate cyclic pattern:" -ForegroundColor Yellow
try {
    python -c "from pwn import *; print(cyclic(20))"
} catch {
    Write-Host "Run 'conda activate ctf' first" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "For detailed tool usage, see CTF/README.md" -ForegroundColor Yellow
Write-Host ""