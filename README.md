# Conda Environment Files

Miscellaneous environment files for creating specialized Conda environments for development and security research.

## Available Environments

### 🛠️ Development Environment (`dev`)

**Files:** `Dev/linux-dev.yml`, `Dev/windows-dev.yml`

A comprehensive multi-language development environment supporting seven programming languages and their ecosystems.

**Supported Languages:** Python, Go, Rust, Zig, Java, C++, C, Fortran, COBOL (Linux only)

**[📖 Complete Setup Instructions →](Dev/README.md)**

---

### 🔐 CTF Environment (`ctf`)

**Files:** `CTF/linux-ctf.yml`, `CTF/windows-ctf.yml`

A specialized environment for Capture The Flag competitions and cybersecurity research, packed with tools for binary exploitation, reverse engineering, cryptography, forensics, and network analysis.

**[📖 Complete Setup Instructions →](CTF/README.md)**

---

## Quick Start

### Development Environment

**Linux/macOS:**
```bash
cd Dev
chmod +x setup-dev.sh
./setup-dev.sh
```

**Windows:**
```powershell
cd Dev
.\setup-dev.ps1
```

The setup script will automatically:
- Create/update the conda environment
- Set up the complete Rust toolchain
- Test all language installations

See [Dev/README.md](Dev/README.md) for details.

### CTF Environment

**Linux/macOS:**
```bash
cd CTF
chmod +x setup-ctf.sh
./setup-ctf.sh
```

**Windows:**
```powershell
cd CTF
.\setup-ctf.ps1
```

The setup script will automatically:
- Create/update the conda environment
- Test all CTF tools

See [CTF/README.md](CTF/README.md) for details.

---

## System Requirements

### Minimum Requirements
- **Conda or Miniconda** installed ([Download here](https://docs.conda.io/en/latest/miniconda.html))
- **Disk Space:** 
  - dev environment: ~5-8 GB
  - ctf environment: ~10-15 GB
- **Memory:** 4 GB RAM minimum, 8 GB recommended
- **OS:** Linux (preferred), macOS, or Windows 10/11

### Recommended Setup
- **Disk Space:** 20+ GB free space
- **Memory:** 16 GB RAM for optimal performance
- **Internet:** Stable connection for package downloads

---

## Environment Management

### Creating an Environment
```bash
conda env create -f <path-to-environment-file>.yml
```

### Activating an Environment
```bash
conda activate <environment-name>
```

### Updating an Environment
```bash
conda env update -f <path-to-environment-file>.yml --prune
```

### Removing an Environment
```bash
conda env remove -n <environment-name>
```

### Listing Environments
```bash
conda env list
```

### Exporting Your Environment
```bash
conda env export > my-environment.yml
```

### Deactivating Current Environment
```bash
conda deactivate
```

---

## Repository Structure

```
Conda-Environment-Files/
├── README.md                           # This file
├── LICENSE                             # AGPL-3.0 License
├── Dev/
│   ├── README.md                       # Development environment documentation
│   ├── linux-dev.yml                   # Linux development environment
│   ├── windows-dev.yml                 # Windows development environment
│   ├── setup-dev.sh                    # Automated setup script (Linux/macOS)
│   ├── setup-dev.ps1                   # Automated setup script (Windows)
│   ├── setup-rust-tools.sh             # Rust toolchain setup (Linux/macOS)
│   └── setup-rust-tools.ps1            # Rust toolchain setup (Windows)
└── CTF/
    ├── README.md                       # CTF environment documentation
    ├── linux-ctf.yml                   # Linux CTF environment
    ├── windows-ctf.yml                 # Windows CTF environment
    ├── setup-ctf.sh                    # Automated setup script (Linux/macOS)
    └── setup-ctf.ps1                   # Automated setup script (Windows)
```

---

## Platform Notes

### Linux
- Full toolchain support including GCC, GDB, Valgrind
- Better compatibility with security tools
- Native Unix utilities available
- **Recommended** for CTF and serious development work

### macOS
- Unix-based with good tool compatibility
- Native development tools available via Xcode
- May need Xcode Command Line Tools: `xcode-select --install`

### Windows
- Growing support for development tools
- Uses MSYS2 toolchain for Unix-like build tools
- **Highly Recommended:** Use WSL2 for best compatibility with CTF tools
- PowerShell execution policy may need adjustment for scripts

---

## Quick Troubleshooting

### Slow Environment Creation
Use `mamba` for faster dependency resolution:
```bash
conda install -n base mamba
mamba env create -f <environment-file>.yml
```

### Package Conflicts
Enable strict channel priority:
```bash
conda config --set channel_priority strict
```

### Out of Disk Space
Clean conda cache:
```bash
conda clean --all
```

For detailed troubleshooting, see:
- [Dev Environment Troubleshooting](Dev/README.md#troubleshooting)
- [CTF Environment Troubleshooting](CTF/README.md#troubleshooting)

---

## Contributing

Feel free to submit issues or pull requests to improve these environment configurations.

### Contribution Guidelines
- Test changes on your platform before submitting
- Update relevant README with any new packages or features
- Follow existing YAML formatting conventions
- Document any platform-specific requirements

---

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the LICENSE file for details.

---

## Useful Resources

- **Conda Documentation:** https://docs.conda.io/
- **Conda-Forge:** https://conda-forge.org/
- **Mamba (faster conda):** https://mamba.readthedocs.io/

---

**Last Updated:** October 1, 2025