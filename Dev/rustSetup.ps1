# Post-installation script to complete Rust toolchain setup for Windows
# Run this after creating your conda environment with: .\setup-rust-tools.ps1

Write-Host "Setting up complete Rust toolchain..." -ForegroundColor Cyan

# Verify conda environment is activated
if (-not $env:CONDA_DEFAULT_ENV -or $env:CONDA_DEFAULT_ENV -eq "base") {
    Write-Host "ERROR: Please activate your 'dev' conda environment first:" -ForegroundColor Red
    Write-Host "  conda activate dev" -ForegroundColor Yellow
    exit 1
}

Write-Host "Active environment: $env:CONDA_DEFAULT_ENV" -ForegroundColor Green

# Check if rustc is available
$rustcPath = Get-Command rustc -ErrorAction SilentlyContinue
if (-not $rustcPath) {
    Write-Host "ERROR: rustc not found. Please ensure the conda environment was created successfully." -ForegroundColor Red
    exit 1
}

Write-Host "Found Rust: $(rustc --version)" -ForegroundColor Green

# Install rustup if not already installed (for component management)
$rustupPath = Get-Command rustup -ErrorAction SilentlyContinue
if (-not $rustupPath) {
    Write-Host "`nInstalling rustup for component management..." -ForegroundColor Yellow
    Write-Host "Downloading rustup-init.exe..." -ForegroundColor Yellow
    
    $rustupInitPath = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInitPath
    
    Write-Host "Running rustup-init..." -ForegroundColor Yellow
    & $rustupInitPath -y --no-modify-path --default-toolchain none
    
    # Add cargo to PATH for this session
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    
    Remove-Item $rustupInitPath -ErrorAction SilentlyContinue
}

# Verify rustup is now available
$rustupPath = Get-Command rustup -ErrorAction SilentlyContinue
if (-not $rustupPath) {
    Write-Host "ERROR: rustup installation failed or not in PATH" -ForegroundColor Red
    Write-Host "Please add $env:USERPROFILE\.cargo\bin to your PATH and run this script again" -ForegroundColor Yellow
    exit 1
}

Write-Host "`nConfiguring rustup to use Rust from conda..." -ForegroundColor Cyan

# Link conda's rust to rustup's toolchain
rustup toolchain link conda-rust $env:CONDA_PREFIX
rustup default conda-rust

# Install additional components
Write-Host "`nInstalling rustfmt..." -ForegroundColor Cyan
rustup component add rustfmt 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  rustfmt already installed or using conda version" -ForegroundColor Gray
}

Write-Host "Installing clippy..." -ForegroundColor Cyan
rustup component add clippy 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  clippy already installed or using conda version" -ForegroundColor Gray
}

# Verify installations
Write-Host "`n==== Verification ====" -ForegroundColor Cyan
Write-Host "rustc:   $(rustc --version)" -ForegroundColor White
Write-Host "cargo:   $(cargo --version)" -ForegroundColor White

$rustfmtVersion = rustfmt --version 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "rustfmt: $rustfmtVersion" -ForegroundColor White
} else {
    Write-Host "rustfmt: Not available via component (use 'cargo fmt')" -ForegroundColor Gray
}

$clippyVersion = cargo clippy --version 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "clippy:  $clippyVersion" -ForegroundColor White
} else {
    Write-Host "clippy:  Not available via component (use 'cargo clippy')" -ForegroundColor Gray
}

Write-Host "`n✓ Rust toolchain setup complete!" -ForegroundColor Green
Write-Host "`nNote: The conda-forge rust package includes rustc and cargo." -ForegroundColor Yellow
Write-Host "If rustfmt/clippy aren't available as standalone commands, use:" -ForegroundColor Yellow
Write-Host "  cargo fmt" -ForegroundColor White
Write-Host "  cargo clippy" -ForegroundColor White