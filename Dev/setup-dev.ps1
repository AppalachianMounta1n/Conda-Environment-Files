# Complete setup script for Dev environment (Windows)
# This script will:
# 1. Create/update the conda environment
# 2. Set up the complete Rust toolchain
# 3. Run tests for all languages

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvName = "dev"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Dev Environment Setup Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Create or update conda environment
Write-Host "Step 1: Creating/updating conda environment..." -ForegroundColor Yellow
$envExists = conda env list | Select-String -Pattern "^${EnvName}\s"
if ($envExists) {
    Write-Host "Environment '${EnvName}' exists. Updating..." -ForegroundColor Green
    conda env update -f "$ScriptDir\windows-dev.yml" --prune
} else {
    Write-Host "Creating new environment '${EnvName}'..." -ForegroundColor Green
    conda env create -f "$ScriptDir\windows-dev.yml"
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

# Step 3: Setup Rust toolchain
Write-Host "Step 3: Setting up Rust toolchain..." -ForegroundColor Yellow
if (Test-Path "$ScriptDir\setup-rust-tools.ps1") {
    & "$ScriptDir\setup-rust-tools.ps1"
} else {
    Write-Host "Warning: setup-rust-tools.ps1 not found, skipping Rust toolchain setup" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Running Language Tests" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Create temp directory for tests
$TestDir = New-Item -ItemType Directory -Path "$env:TEMP\dev-test-$(Get-Random)" -Force
Push-Location $TestDir.FullName

# Test Python
Write-Host "Testing Python..." -ForegroundColor Yellow
try {
    python -c "import numpy; import pandas; import matplotlib; print('✓ Python OK')"
} catch {
    Write-Host "✗ Python FAILED" -ForegroundColor Red
}
Write-Host ""

# Test Go
Write-Host "Testing Go..." -ForegroundColor Yellow
@"
package main
import "fmt"
func main() {
    fmt.Println("✓ Go OK")
}
"@ | Out-File -Encoding utf8 test.go
try {
    go run test.go
} catch {
    Write-Host "✗ Go FAILED" -ForegroundColor Red
}
Write-Host ""

# Test Rust
Write-Host "Testing Rust..." -ForegroundColor Yellow
@"
fn main() {
    println!("✓ Rust OK");
}
"@ | Out-File -Encoding utf8 test.rs
try {
    rustc test.rs
    .\test.exe
} catch {
    Write-Host "✗ Rust FAILED" -ForegroundColor Red
}
Write-Host ""

# Test Zig
Write-Host "Testing Zig..." -ForegroundColor Yellow
@"
const std = @import("std");
pub fn main() !void {
    std.debug.print("✓ Zig OK\n", .{});
}
"@ | Out-File -Encoding utf8 test.zig
try {
    zig run test.zig
} catch {
    Write-Host "✗ Zig FAILED" -ForegroundColor Red
}
Write-Host ""

# Test Java
Write-Host "Testing Java..." -ForegroundColor Yellow
@"
public class Test {
    public static void main(String[] args) {
        System.out.println("✓ Java OK");
    }
}
"@ | Out-File -Encoding utf8 Test.java
try {
    javac Test.java
    java Test
} catch {
    Write-Host "✗ Java FAILED" -ForegroundColor Red
}
Write-Host ""

# Test C
Write-Host "Testing C..." -ForegroundColor Yellow
@"
#include <stdio.h>
int main() {
    printf("✓ C OK\n");
    return 0;
}
"@ | Out-File -Encoding utf8 test.c
try {
    gcc test.c -o test_c.exe
    .\test_c.exe
} catch {
    Write-Host "✗ C FAILED" -ForegroundColor Red
}
Write-Host ""

# Test C++
Write-Host "Testing C++..." -ForegroundColor Yellow
@"
#include <iostream>
int main() {
    std::cout << "✓ C++ OK" << std::endl;
    return 0;
}
"@ | Out-File -Encoding utf8 test.cpp
try {
    clang++ test.cpp -o test_cpp.exe
    .\test_cpp.exe
} catch {
    Write-Host "✗ C++ FAILED" -ForegroundColor Red
}
Write-Host ""

# Test Fortran
Write-Host "Testing Fortran..." -ForegroundColor Yellow
@"
program test
    print *, "✓ Fortran OK"
end program test
"@ | Out-File -Encoding utf8 test.f90
try {
    gfortran test.f90 -o test_fortran.exe
    .\test_fortran.exe
} catch {
    Write-Host "✗ Fortran FAILED" -ForegroundColor Red
}
Write-Host ""

Write-Host "Note: COBOL is not available on Windows. Use WSL2 for COBOL development." -ForegroundColor Yellow
Write-Host ""

# Cleanup
Pop-Location
Remove-Item -Recurse -Force $TestDir -ErrorAction SilentlyContinue

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Environment '${EnvName}' is ready to use." -ForegroundColor Green
Write-Host ""
Write-Host "To activate the environment in a new terminal, run:" -ForegroundColor Yellow
Write-Host "  conda activate ${EnvName}" -ForegroundColor White
Write-Host ""
Write-Host "Language versions:" -ForegroundColor Yellow
python --version
go version
rustc --version
zig version
javac -version 2>&1 | Select-Object -First 1
gcc --version | Select-Object -First 1
gfortran --version | Select-Object -First 1
Write-Host ""