# Development Environment

A comprehensive multi-language development environment supporting seven programming languages and their ecosystems.

## Supported Languages

- **Python 3.12** - Full scientific and web development stack
- **Go 1.21** - Modern concurrent programming
- **Rust** - Systems programming with memory safety (includes rustc and cargo)
- **Zig** - Simple, fast systems programming
- **Java 17** - Enterprise development (with Maven and Gradle)
- **C/C++** - Low-level systems programming (GCC/Clang toolchains)
- **C** - Traditional systems programming
- **COBOL** - Business and legacy system development (GnuCOBOL)
- **Fortran** - Scientific and numerical computing (gfortran)

## Key Features

### Build Tools & Compilers
- CMake, Ninja, Make for cross-platform builds
- GCC/G++ and Clang/LLVM toolchains
- Platform-specific debuggers (GDB on Linux)
- ccache for faster recompilation

### Python Development
- Modern tooling: Black, Ruff, mypy, pylint
- Testing: pytest with coverage
- Package management: pip, poetry, pipenv
- Interactive development: IPython, Jupyter Lab

### Code Quality
- Linters and formatters for all languages
- Pre-commit hooks support
- Static analysis tools (mypy, bandit)
- Security scanning (safety)

### Version Control
- Git with Git LFS support
- Pre-commit framework integration

### Documentation
- Sphinx (Python)
- Doxygen (C/C++/Java)

### Utilities
- Performance profiling tools
- Common development utilities (jq, tree, htop, tmux)
- Scientific computing stack (NumPy, Pandas, Matplotlib)

---

## Complete Setup Instructions

### Linux/macOS Setup

#### 1. Create the Environment

```bash
conda env create -f linux-dev.yml
```

This will take several minutes as it downloads and installs all packages.

#### 2. Activate the Environment

```bash
conda activate dev
```

You should see `(dev)` appear in your terminal prompt.

#### 3. Verify Base Installations

Test that all languages are properly installed:

```bash
python --version    # Python 3.12.x
go version          # go1.21.x
rustc --version     # rustc x.xx.x
cargo --version     # cargo x.xx.x
zig version         # x.xx.x
javac --version     # openjdk 17.x.x
gcc --version       # gcc x.x.x
clang --version     # clang version x.x.x
gfortran --version  # GNU Fortran x.x.x
cobc --version      # cobc (GnuCOBOL) x.x.x
```

#### 4. Complete Rust Toolchain Setup (Optional but Recommended)

The conda environment includes rustc and cargo, but for the complete Rust experience with rustfmt and clippy:

```bash
chmod +x setup-rust-tools.sh
./setup-rust-tools.sh
```

This script will:
- Install rustup if not present
- Link conda's Rust to rustup
- Install rustfmt and clippy components
- Verify the complete installation

#### 5. Test the Environment

Run these tests to ensure everything works:

##### Python Test
```bash
python -c "import numpy; import pandas; import matplotlib; print('Python OK')"
```

##### Go Test
```bash
echo 'package main
import "fmt"
func main() {
    fmt.Println("Go OK")
}' > test.go
go run test.go
rm test.go
```

##### Rust Test
```bash
echo 'fn main() {
    println!("Rust OK");
}' > test.rs
rustc test.rs && ./test
rm test test.rs
```

##### Zig Test
```bash
echo 'const std = @import("std");
pub fn main() !void {
    std.debug.print("Zig OK\n", .{});
}' > test.zig
zig run test.zig
rm test.zig
```

##### Java Test
```bash
echo 'public class Test {
    public static void main(String[] args) {
        System.out.println("Java OK");
    }
}' > Test.java
javac Test.java && java Test
rm Test.java Test.class
```

##### C Test
```bash
echo '#include <stdio.h>
int main() {
    printf("C OK\n");
    return 0;
}' > test.c
gcc test.c -o test && ./test
rm test test.c
```

##### C++ Test
```bash
echo '#include <iostream>
int main() {
    std::cout << "C++ OK" << std::endl;
    return 0;
}' > test.cpp
g++ test.cpp -o test && ./test
rm test test.cpp
```

##### Fortran Test
```bash
echo 'program test
    print *, "Fortran OK"
end program test' > test.f90
gfortran test.f90 -o test && ./test
rm test test.f90
```

##### COBOL Test
```bash
echo '       IDENTIFICATION DIVISION.
       PROGRAM-ID. TEST.
       PROCEDURE DIVISION.
           DISPLAY "COBOL OK".
           STOP RUN.' > test.cob
cobc -x test.cob -o test && ./test
rm test test.cob
```

---

### Windows Setup

#### 1. Create the Environment

```powershell
conda env create -f windows-dev.yml
```

This will take several minutes as it downloads and installs all packages.

#### 2. Activate the Environment

```powershell
conda activate dev
```

You should see `(dev)` appear in your terminal prompt.

#### 3. Verify Base Installations

Test that all languages are properly installed:

```powershell
python --version
go version
rustc --version
cargo --version
zig version
javac --version
gcc --version
clang --version
gfortran --version
cobc --version
```

#### 4. Complete Rust Toolchain Setup (Optional but Recommended)

The conda environment includes rustc and cargo, but for the complete Rust experience with rustfmt and clippy:

```powershell
# Set execution policy if needed (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Run the setup script
.\setup-rust-tools.ps1
```

This script will:
- Download and install rustup if not present
- Link conda's Rust to rustup
- Install rustfmt and clippy components
- Verify the complete installation

#### 5. Test the Environment

Run these tests to ensure everything works:

##### Python Test
```powershell
python -c "import numpy; import pandas; import matplotlib; print('Python OK')"
```

##### Go Test
```powershell
@"
package main
import "fmt"
func main() {
    fmt.Println("Go OK")
}
"@ | Out-File -Encoding utf8 test.go
go run test.go
Remove-Item test.go
```

##### Rust Test
```powershell
@"
fn main() {
    println!("Rust OK");
}
"@ | Out-File -Encoding utf8 test.rs
rustc test.rs
.\test.exe
Remove-Item test.rs, test.exe, test.pdb
```

##### Zig Test
```powershell
@"
const std = @import("std");
pub fn main() !void {
    std.debug.print("Zig OK\n", .{});
}
"@ | Out-File -Encoding utf8 test.zig
zig run test.zig
Remove-Item test.zig
```

##### Java Test
```powershell
@"
public class Test {
    public static void main(String[] args) {
        System.out.println("Java OK");
    }
}
"@ | Out-File -Encoding utf8 Test.java
javac Test.java
java Test
Remove-Item Test.java, Test.class
```

##### C Test (with MinGW GCC)
```powershell
@"
#include <stdio.h>
int main() {
    printf("C OK\n");
    return 0;
}
"@ | Out-File -Encoding utf8 test.c
gcc test.c -o test.exe
.\test.exe
Remove-Item test.c, test.exe
```

##### C++ Test
```powershell
@"
#include <iostream>
int main() {
    std::cout << "C++ OK" << std::endl;
    return 0;
}
"@ | Out-File -Encoding utf8 test.cpp
clang++ test.cpp -o test.exe
.\test.exe
Remove-Item test.cpp, test.exe
```

##### Fortran Test
```powershell
@"
program test
    print *, "Fortran OK"
end program test
"@ | Out-File -Encoding utf8 test.f90
gfortran test.f90 -o test.exe
.\test.exe
Remove-Item test.f90, test.exe
```

##### COBOL Test
```powershell
@"
       IDENTIFICATION DIVISION.
       PROGRAM-ID. TEST.
       PROCEDURE DIVISION.
           DISPLAY "COBOL OK".
           STOP RUN.
"@ | Out-File -Encoding utf8 test.cob
cobc -x test.cob -o test.exe
.\test.exe
Remove-Item test.cob, test.exe
```

---

## Development Workflow

### Python Development

```bash
# Create a new project
mkdir my_project && cd my_project

# Initialize with poetry
poetry init

# Or use pip with virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate     # Windows

# Format code
black .
ruff check .

# Type checking
mypy .

# Run tests
pytest
```

### Go Development

```bash
# Create a new module
go mod init myproject

# Build
go build

# Run
go run main.go

# Test
go test ./...

# Format
go fmt ./...
```

### Rust Development

```bash
# Create a new project
cargo new myproject
cd myproject

# Build
cargo build

# Run
cargo run

# Test
cargo test

# Format
cargo fmt

# Lint
cargo clippy
```

### Zig Development

```bash
# Create a new project
zig init-exe

# Build
zig build

# Run
zig build run

# Test
zig build test

# Format
zig fmt .
```

### Java Development

```bash
# Using Maven
mvn archetype:generate -DgroupId=com.myapp -DartifactId=myapp
cd myapp
mvn clean install
mvn exec:java

# Using Gradle
gradle init
gradle build
gradle run
```

### C/C++ Development

```bash
# Using CMake
mkdir build && cd build
cmake ..
make

# Direct compilation
gcc myprogram.c -o myprogram
g++ myprogram.cpp -o myprogram
clang myprogram.c -o myprogram
```

### Fortran Development

```bash
# Compile Fortran 90/95/2003/2008
gfortran program.f90 -o program

# With optimization
gfortran -O3 program.f90 -o program

# With debugging symbols
gfortran -g program.f90 -o program

# Multiple source files
gfortran main.f90 module1.f90 module2.f90 -o program

# Using OpenMP for parallel computing
gfortran -fopenmp parallel_program.f90 -o program

# Link with BLAS/LAPACK for numerical computing
gfortran program.f90 -lblas -llapack -o program

# Check for common issues
gfortran -Wall -Wextra program.f90 -o program
```

#### Fortran Project Structure
```
fortran_project/
├── src/
│   ├── main.f90
│   ├── module1.f90
│   └── module2.f90
├── include/
├── lib/
└── Makefile
```

#### Sample Makefile for Fortran
```makefile
FC = gfortran
FFLAGS = -O3 -Wall
LDFLAGS = -lblas -llapack

SRCS = main.f90 module1.f90 module2.f90
OBJS = $(SRCS:.f90=.o)
TARGET = program

all: $(TARGET)

$(TARGET): $(OBJS)
	$(FC) $(FFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.f90
	$(FC) $(FFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET) *.mod

.PHONY: all clean
```

### COBOL Development

```bash
# Compile COBOL program
cobc -x program.cob -o program

# Compile with debugging
cobc -x -g program.cob -o program

# Compile to object file (for linking)
cobc -c program.cob

# Compile multiple files
cobc -x main.cob utilities.cob -o program

# Check syntax without compiling
cobc -fsyntax-only program.cob

# Generate listing file
cobc -x -t program.cob.lst program.cob -o program

# Free format COBOL (without column restrictions)
cobc -x -free program.cob -o program

# COBOL-85 standard
cobc -x -std=cobol85 program.cob -o program

# Fixed format (traditional COBOL with column restrictions)
cobc -x -fixed program.cob -o program
```

#### COBOL Program Structure
```cobol
       IDENTIFICATION DIVISION.
       PROGRAM-ID. SAMPLE-PROGRAM.
       AUTHOR. YOUR-NAME.
       DATE-WRITTEN. 2025-10-01.
       
       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.
       SOURCE-COMPUTER. PC.
       OBJECT-COMPUTER. PC.
       
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT INPUT-FILE ASSIGN TO "input.dat"
               ORGANIZATION IS LINE SEQUENTIAL.
       
       DATA DIVISION.
       FILE SECTION.
       FD  INPUT-FILE.
       01  INPUT-RECORD    PIC X(80).
       
       WORKING-STORAGE SECTION.
       01  WS-COUNTER      PIC 9(4) VALUE ZERO.
       01  WS-NAME         PIC X(30).
       
       PROCEDURE DIVISION.
       MAIN-PROCEDURE.
           DISPLAY "Hello from COBOL!"
           PERFORM PROCESS-DATA
           STOP RUN.
       
       PROCESS-DATA.
           MOVE 100 TO WS-COUNTER
           DISPLAY "Counter: " WS-COUNTER.
```

#### COBOL Project Structure
```
cobol_project/
├── src/
│   ├── MAIN.cob
│   ├── UTILITIES.cob
│   └── DATA-HANDLER.cob
├── copybooks/
│   └── COMMON-DATA.cpy
├── data/
│   ├── input.dat
│   └── config.dat
├── bin/
└── Makefile
```

#### Sample Makefile for COBOL
```makefile
COBC = cobc
COBFLAGS = -x -std=cobol2014 -Wall
COBCOPY = -I./copybooks

SRCS = src/MAIN.cob src/UTILITIES.cob
TARGET = bin/program

all: $(TARGET)

$(TARGET): $(SRCS)
	mkdir -p bin
	$(COBC) $(COBFLAGS) $(COBCOPY) -o $@ $^

check:
	$(COBC) -fsyntax-only $(COBCOPY) $(SRCS)

clean:
	rm -rf bin/*.exe bin/*.o

.PHONY: all check clean
```

### Using CMake with Multiple Languages

For projects using C/C++/Fortran together:

```cmake
cmake_minimum_required(VERSION 3.10)
project(MixedLanguageProject C CXX Fortran)

# Set standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# Fortran flags
set(CMAKE_Fortran_FLAGS "${CMAKE_Fortran_FLAGS} -O3")

# Mixed language executable
add_executable(myapp
    main.c
    utils.cpp
    numerics.f90
)

# Link libraries
target_link_libraries(myapp blas lapack)
```

---

## Troubleshooting

### General Issues

#### Slow Environment Creation

**Problem:** Environment creation is taking a very long time.

**Solutions:**
1. Use `mamba` for faster dependency resolution:
   ```bash
   conda install -n base mamba
   mamba env create -f linux-dev.yml
   ```

2. Enable libmamba solver:
   ```bash
   conda install -n base conda-libmamba-solver
   conda config --set solver libmamba
   ```

#### Package Conflicts

**Problem:** Conda reports package conflicts during creation.

**Solutions:**
1. Try with strict channel priority:
   ```bash
   conda config --set channel_priority strict
   conda env create -f linux-dev.yml
   ```

2. Create environment with fewer packages first, then install problematic ones:
   ```bash
   # Edit the yml file to comment out problematic packages
   conda env create -f linux-dev.yml
   conda activate dev
   conda install <problematic-package>
   ```

#### Out of Disk Space

**Problem:** Running out of disk space during installation.

**Solutions:**
```bash
# Clean conda cache
conda clean --all

# Remove unused environments
conda env list
conda env remove -n <unused-env>
```

### Platform-Specific Issues

#### C/C++ Issues

**Missing System Dependencies**

Some packages may require system libraries:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential libssl-dev libffi-dev python3-dev

# Fedora/RHEL
sudo dnf groupinstall "Development Tools"
sudo dnf install openssl-devel libffi-devel python3-devel

# Arch Linux
sudo pacman -S base-devel openssl libffi
```

**Permission Errors**

Don't use `sudo` with conda commands. Ensure conda is installed in your user directory.

**GDB Not Working**

You may need to adjust ptrace permissions:
```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

#### Fortran Issues

**Missing BLAS/LAPACK Libraries**

If you need BLAS/LAPACK for numerical computing:
```bash
# Ubuntu/Debian
sudo apt install libblas-dev liblapack-dev

# Fedora/RHEL
sudo dnf install blas-devel lapack-devel

# Arch Linux
sudo pacman -S blas lapack

# Or install via conda
conda install -c conda-forge openblas lapack
```

**Module File Issues**

Fortran creates .mod files during compilation. If you get "can't open module file" errors:
```bash
# Ensure proper compilation order (modules before programs that use them)
gfortran -c module.f90     # Compile module first
gfortran -c main.f90       # Then main program
gfortran module.o main.o -o program  # Link

# Or specify module directory
gfortran -J./modules -c module.f90
gfortran -I./modules main.f90 module.o -o program
```

**OpenMP Not Working**

If parallel Fortran programs don't work:
```bash
# Verify OpenMP support
gfortran -fopenmp --version

# Set number of threads
export OMP_NUM_THREADS=4

# Test OpenMP
echo 'program test
    use omp_lib
    !$omp parallel
    print *, "Thread", omp_get_thread_num()
    !$omp end parallel
end program' > test.f90
gfortran -fopenmp test.f90 -o test
./test
```

**Fixed vs Free Format Issues**

COBOL and older Fortran use column-based formatting:
```bash
# For free-format Fortran (modern, .f90 files)
gfortran program.f90 -o program

# For fixed-format Fortran (legacy, .f or .for files)
gfortran -ffixed-form program.f -o program

# If you get column-related errors, try:
gfortran -ffree-form program.f90  # Force free format
gfortran -ffixed-form program.f   # Force fixed format
```

#### COBOL Issues

**Column Format Errors**

Traditional COBOL uses strict column formatting:
- Columns 1-6: Sequence area (optional)
- Column 7: Indicator area (*, -, D, or space)
- Columns 8-11: Area A (division, section, paragraph names)
- Columns 12-72: Area B (statements)
- Columns 73-80: Identification area (optional)

```bash
# Use fixed format (traditional COBOL)
cobc -x -fixed program.cob

# Use free format (modern COBOL, no column restrictions)
cobc -x -free program.cob

# If you get "syntax error" check column alignment
```

**GnuCOBOL Standards**

Different COBOL standards are available:
```bash
# COBOL-85 (most compatible)
cobc -x -std=cobol85 program.cob

# COBOL-2002
cobc -x -std=cobol2002 program.cob

# COBOL-2014 (default, most features)
cobc -x -std=cobol2014 program.cob

# IBM COBOL dialect
cobc -x -std=ibm program.cob

# MVS/Enterprise COBOL
cobc -x -std=mvs program.cob
```

**File I/O Issues**

COBOL file operations are picky about formats:
```bash
# Ensure data files have proper line endings
# Unix/Linux: LF
# Windows: CRLF

# Convert if needed (Linux)
dos2unix datafile.dat
unix2dos datafile.dat

# Check file organization in SELECT statement matches actual file
```

**COPY Statement Issues**

If COPY statements don't work:
```bash
# Specify copybook directory
cobc -x -I./copybooks program.cob

# Or set environment variable
export COB_COPY_DIR=./copybooks
cobc -x program.cob
```

**Runtime Errors**

GnuCOBOL provides detailed runtime info:
```bash
# Enable runtime debugging
export COB_SET_DEBUG=Y

# Trace program execution
export COB_SET_TRACE=Y

# Run with debugging
./program
```

#### macOS Issues

**Xcode Command Line Tools Required**

```bash
xcode-select --install
```

**M1/M2 Mac Compatibility**

Some packages may need Rosetta:
```bash
arch -x86_64 conda env create -f linux-dev.yml
```

**Permission Issues with GDB**

Code signing is required for GDB on macOS. Consider using LLDB instead:
```bash
lldb ./myprogram
```

#### Windows Issues

**PowerShell Script Execution Error**

```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Missing Visual Studio Build Tools**

Some C/C++ packages require MSVC:
1. Download Visual Studio Build Tools from https://visualstudio.microsoft.com/downloads/
2. Install "Desktop development with C++" workload

**PATH Issues**

Ensure Anaconda/Miniconda is in your PATH:
1. Search for "Environment Variables" in Windows
2. Add conda installation directory to PATH
3. Restart terminal

**Long Path Issues**

Enable long paths in Windows:
```powershell
# Run as Administrator
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

**Fortran on Windows**

The m2w64-gcc-fortran package provides gfortran:
```powershell
# Verify installation
gfortran --version

# If not in PATH, activate conda environment first
conda activate dev
gfortran --version
```

**COBOL on Windows**

GnuCOBOL works well on Windows through conda:
```powershell
# Verify installation
cobc --version

# Compile with Windows paths
cobc -x "C:\path\to\program.cob" -o program.exe

# Note: Use forward slashes or escape backslashes in COBOL
# ASSIGN TO "data/input.dat" or "data\\input.dat"
```

**Line Ending Issues**

COBOL and Fortran can be sensitive to line endings:
```powershell
# Convert line endings if needed
# Use an editor like Notepad++ or VS Code
# Or install dos2unix via conda
conda install dos2unix
dos2unix program.cob
```

### Language-Specific Issues

#### Rust Issues

**Rustup Installation Failed**

Linux/macOS:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Windows:
- Download from https://rustup.rs/
- Run rustup-init.exe
- Restart terminal

**Rust Components Not Available**

If rustfmt/clippy aren't available as standalone commands:
```bash
# Use them via cargo
cargo fmt
cargo clippy
```

**Multiple Rust Installations Conflict**

Ensure rustup uses conda's toolchain:
```bash
rustup toolchain list
rustup default conda-rust
```

#### Go Issues

**GOPATH Issues**

The environment sets up Go properly, but if you have issues:
```bash
# Check Go environment
go env

# Set GOPATH manually if needed
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

#### Java Issues

**JAVA_HOME Not Set**

```bash
# Linux/macOS
export JAVA_HOME=$CONDA_PREFIX

# Windows (PowerShell)
$env:JAVA_HOME = $env:CONDA_PREFIX
```

**Maven/Gradle Issues**

Clear local repository cache:
```bash
# Maven
rm -rf ~/.m2/repository

# Gradle
rm -rf ~/.gradle/caches
```

#### Python Issues

**Import Errors**

Ensure you're using the conda environment's Python:
```bash
which python  # Linux/macOS
where python  # Windows
```

**Jupyter Kernel Issues**

Register the environment as a Jupyter kernel:
```bash
python -m ipykernel install --user --name=dev
```

---

## Updating the Environment

### Update All Packages

```bash
conda activate dev
conda update --all
```

### Update from YAML File

```bash
conda env update -f linux-dev.yml --prune
```

### Add New Packages

```bash
conda activate dev
conda install <package-name>

# Or via pip
pip install <package-name>
```

### Export Your Modified Environment

```bash
conda env export > my-custom-dev.yml
```

---

## Useful Commands

### Environment Management

```bash
# List all environments
conda env list

# Deactivate current environment
conda deactivate

# Remove environment
conda env remove -n dev

# Clone environment
conda create --name dev-backup --clone dev
```

### Package Management

```bash
# List installed packages
conda list

# Search for a package
conda search <package-name>

# Show package info
conda info <package-name>

# Remove a package
conda remove <package-name>
```

### Python-Specific

```bash
# List pip packages
pip list

# Show package details
pip show <package-name>

# Install from requirements.txt
pip install -r requirements.txt

# Generate requirements.txt
pip freeze > requirements.txt
```

---

## Tips and Best Practices

### General

1. **Always activate the environment** before working on projects
2. **Keep environments separate** - don't install everything in base
3. **Document dependencies** - export your environment periodically
4. **Clean regularly** - run `conda clean --all` monthly

### Python

1. Use virtual environments within conda for project isolation
2. Use `poetry` or `pipenv` for project dependency management
3. Run formatters (black, ruff) before committing code
4. Use `mypy` for type checking

### Rust

1. Use `cargo fmt` before committing
2. Run `cargo clippy` to catch common mistakes
3. Use `cargo test` for comprehensive testing
4. Consider `cargo-edit` for dependency management

### Go

1. Use `go mod` for dependency management
2. Run `go fmt` before committing
3. Use `go vet` to find suspicious code
4. Enable `golangci-lint` for comprehensive linting

### C/C++

1. Use CMake for cross-platform projects
2. Enable compiler warnings (`-Wall -Wextra`)
3. Use sanitizers for debugging (`-fsanitize=address`)
4. Consider using `clang-format` for code formatting

### Fortran

1. Use free-format for new code (.f90 extension)
2. Enable all warnings: `gfortran -Wall -Wextra`
3. Use implicit none in all programs and modules
4. Consider using submodules for large projects (Fortran 2008+)
5. Use OpenMP for easy parallelization
6. Profile before optimizing: `gfortran -pg` for gprof profiling

### COBOL

1. Use free-format for new projects (`cobc -free`)
2. Check syntax before full compilation: `cobc -fsyntax-only`
3. Use copybooks for shared data structures
4. Follow naming conventions (COBOL is case-insensitive)
5. Use COBOL-2014 standard for modern features
6. Test with various standards if targeting legacy systems
7. Use proper indentation even in free format for readability

---

## Additional Resources

### Language Documentation

- **Python:** https://docs.python.org/3/
- **Go:** https://go.dev/doc/
- **Rust:** https://doc.rust-lang.org/
- **Zig:** https://ziglang.org/documentation/
- **Java:** https://docs.oracle.com/en/java/
- **C/C++:** https://en.cppreference.com/
- **Fortran:** https://fortran-lang.org/learn/
- **COBOL:** https://gnucobol.sourceforge.io/

### Tools Documentation

- **CMake:** https://cmake.org/documentation/
- **Poetry:** https://python-poetry.org/docs/
- **Cargo:** https://doc.rust-lang.org/cargo/
- **Maven:** https://maven.apache.org/guides/
- **Gradle:** https://docs.gradle.org/
- **gfortran:** https://gcc.gnu.org/fortran/
- **GnuCOBOL:** https://gnucobol.sourceforge.io/doc/

### Learning Resources

- **Rust Book:** https://doc.rust-lang.org/book/
- **Go Tour:** https://go.dev/tour/
- **Zig Learn:** https://ziglearn.org/
- **Python Tutorial:** https://docs.python.org/3/tutorial/
- **Modern Fortran:** https://fortran-lang.org/learn/quickstart/
- **COBOL Programming Course:** https://github.com/openmainframeproject/cobol-programming-course

### Community Resources

- **Fortran Discourse:** https://fortran-lang.discourse.group/
- **COBOL Cowboys:** https://www.cobolcowboys.com/
- **r/fortran:** https://reddit.com/r/fortran
- **r/cobol:** https://reddit.com/r/cobol

---

[← Back to Main README](../README.md)