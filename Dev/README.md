# Development Environment

A comprehensive multi-language development environment supporting nine programming languages.

## Supported Languages

- **Python 3.12** - Full scientific and web development stack
- **Go 1.21** - Modern concurrent programming
- **Rust** - Systems programming with memory safety
- **Zig** - Simple, fast systems programming
- **Java 17** - Enterprise development (Maven & Gradle)
- **C/C++** - Low-level systems programming
- **Fortran** - Scientific and numerical computing
- **COBOL** - Business and legacy systems (Linux/macOS only)

---

## Quick Setup

### Linux/macOS

```bash
chmod +x setup-dev.sh
./setup-dev.sh
```

### Windows

```powershell
.\setup-dev.ps1
```

The setup script will:
1. Create/update the conda environment named `dev`
2. Set up the complete Rust toolchain (rustc, cargo, rustfmt, clippy)
3. Test all language installations
4. Display version information

**Setup time:** 5-15 minutes depending on your internet connection.

---

## Usage

### Activate the Environment

```bash
conda activate dev
```

### Verify Installation

All languages are tested automatically during setup. To manually verify:

```bash
python --version
go version
rustc --version
zig version
javac --version
gcc --version
gfortran --version
cobc --version  # Linux/macOS only
```

---

## Development Workflows

### Python
```bash
# Create project with poetry
poetry init
poetry install

# Or use pip
pip install -r requirements.txt

# Format and lint
black .
ruff check .
mypy .
pytest
```

### Go
```bash
go mod init myproject
go build
go test ./...
go fmt ./...
```

### Rust
```bash
cargo new myproject
cd myproject
cargo build
cargo test
cargo fmt
cargo clippy
```

### Zig
```bash
zig init-exe
zig build
zig build test
```

### Java
```bash
# Maven
mvn clean install
mvn test

# Gradle
gradle build
gradle test
```

### C/C++
```bash
# With CMake
mkdir build && cd build
cmake ..
make

# Direct compilation
gcc program.c -o program
g++ program.cpp -o program
```

### Fortran
```bash
# Compile
gfortran program.f90 -o program

# With optimization
gfortran -O3 program.f90 -o program

# With OpenMP
gfortran -fopenmp parallel.f90 -o program
```

### COBOL (Linux/macOS only)
```bash
# Compile
cobc -x program.cob -o program

# Free format
cobc -x -free program.cob -o program

# Specific standard
cobc -x -std=cobol85 program.cob -o program
```

**Windows users:** Use WSL2, Docker, or a VM for COBOL development.

---

## Key Features

### Build Tools
- CMake, Ninja, Make
- GCC/Clang toolchains
- GDB debugger (Linux)

### Python Development
- Black, Ruff, mypy, pylint
- pytest with coverage
- IPython, Jupyter Lab
- Poetry, pipenv

### Code Quality
- Pre-commit hooks
- Static analysis (mypy, bandit)
- Security scanning (safety)

### Documentation
- Sphinx (Python)
- Doxygen (C/C++/Java)

---

## Troubleshooting

### Environment Issues

**Slow setup:**
```bash
# Use mamba for faster dependency resolution
conda install -n base mamba
cd Dev
# Edit setup script to replace 'conda' with 'mamba'
```

**Package conflicts:**
```bash
conda config --set channel_priority strict
# Then re-run setup script
```

**Out of disk space:**
```bash
conda clean --all
```

### Platform-Specific Issues

#### Linux

**Missing system libraries:**
```bash
# Ubuntu/Debian
sudo apt install build-essential libssl-dev libffi-dev

# Fedora/RHEL
sudo dnf groupinstall "Development Tools"

# Arch
sudo pacman -S base-devel
```

#### macOS

**Xcode Command Line Tools required:**
```bash
xcode-select --install
```

#### Windows

**PowerShell execution policy:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**COBOL not available:**
Use WSL2 for COBOL development:
```powershell
wsl --install -d Ubuntu
# Then use linux-dev.yml inside WSL2
```

### Language-Specific Issues

**Rust components not available:**
```bash
# Use cargo instead
cargo fmt
cargo clippy
```

**Fortran BLAS/LAPACK needed:**
```bash
conda install -c conda-forge openblas lapack
```

**COBOL column format errors:**
```bash
# Use free format
cobc -x -free program.cob
```

---

## Updating

### Update Environment
```bash
cd Dev
./setup-dev.sh  # Runs conda env update automatically
```

### Add Packages
```bash
conda activate dev
conda install <package-name>
# Or
pip install <package-name>
```

### Export Modified Environment
```bash
conda env export > my-custom-dev.yml
```

---

## Tips & Best Practices

### General
- Always activate the environment before working
- Keep environments separate - don't install in base
- Clean regularly: `conda clean --all`

### Python
- Use `poetry` or `pipenv` for project dependencies
- Run `black` and `ruff` before committing
- Use `mypy` for type checking

### Rust
- Use `cargo fmt` before committing
- Run `cargo clippy` to catch issues
- Use `cargo test` for comprehensive testing

### C/C++
- Use CMake for cross-platform builds
- Enable warnings: `-Wall -Wextra`
- Use sanitizers: `-fsanitize=address`

### Fortran
- Use free-format for new code (.f90)
- Enable warnings: `gfortran -Wall`
- Use `implicit none` in all programs

### COBOL
- Use free-format for new projects
- Check syntax: `cobc -fsyntax-only`
- Use COBOL-2014 standard for modern features

---

## Additional Resources

### Language Documentation
- **Python:** https://docs.python.org/3/
- **Go:** https://go.dev/doc/
- **Rust:** https://doc.rust-lang.org/
- **Zig:** https://ziglang.org/documentation/
- **Java:** https://docs.oracle.com/en/java/
- **C/C++:** https://en.cppreference.com/
- **Fortran:** https://fortran-lang.org/
- **COBOL:** https://gnucobol.sourceforge.io/

### Tools Documentation
- **CMake:** https://cmake.org/documentation/
- **Poetry:** https://python-poetry.org/docs/
- **Cargo:** https://doc.rust-lang.org/cargo/
- **Maven:** https://maven.apache.org/
- **Gradle:** https://docs.gradle.org/

### Learning Resources
- **Rust Book:** https://doc.rust-lang.org/book/
- **Go Tour:** https://go.dev/tour/
- **Modern Fortran:** https://fortran-lang.org/learn/
- **COBOL Course:** https://github.com/openmainframeproject/cobol-programming-course

---

## Manual Setup (Alternative)

If you prefer manual setup or the script fails:

### Linux/macOS
```bash
conda env create -f linux-dev.yml
conda activate dev
bash setup-rust-tools.sh
```

### Windows
```powershell
conda env create -f windows-dev.yml
conda activate dev
.\setup-rust-tools.ps1
```

---

[← Back to Main README](../README.md)