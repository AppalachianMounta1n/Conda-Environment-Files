# CTF Environment

A specialized environment for Capture The Flag competitions and cybersecurity research, packed with tools for binary exploitation, reverse engineering, cryptography, forensics, and network analysis.

## Categories of Tools

### Binary Analysis & Reverse Engineering
- **angr** - Binary analysis framework for automated exploit generation
- **pwntools** - CTF exploitation framework with process interaction utilities
- **pyelftools** - ELF file format parsing and analysis
- **capstone** - Multi-architecture disassembly framework
- **keystone-engine** - Multi-architecture assembler framework
- **unicorn** - Lightweight CPU emulator framework
- **ROPgadget** - ROP gadget finder and chain generator
- **ropper** - Advanced ROP gadget finder
- **r2pipe** - Python bindings for Radare2

### Exploitation & Debugging
- **Frida** - Dynamic instrumentation toolkit for reverse engineering
- **pwntools** - Includes process debugging and exploitation helpers
- **GDB integration** - Through pwntools and other tools

### Cryptography
- **pycryptodome** - Comprehensive cryptographic primitives
- **cryptography** - High-level cryptography library
- **Sage** - Mathematical computation system (Linux only)
- **z3-solver** - Constraint solving for cryptanalysis

### Forensics
- **binwalk** - Firmware analysis and extraction tool
- **pyexiftool** - Metadata extraction from various file formats
- **stegano** - Steganography detection and extraction
- **stegcracker** - Stegocracker for brute-forcing steganography
- **ffmpeg** - Multimedia file analysis and manipulation

### Network Analysis
- **scapy** - Powerful packet manipulation and analysis
- **scapy-http** - HTTP layer support for Scapy
- **pyshark** - Python wrapper for Wireshark/tshark
- **mitmproxy** - Interactive HTTPS proxy for traffic inspection
- **paramiko** - SSH protocol implementation
- **pynetcat** - Python netcat implementation

### Web & API
- **requests** - HTTP library for Python
- **FastAPI** - Modern web framework for APIs
- **Streamlit** - Quick dashboard and tool creation

### Data Analysis & Visualization
- **Pandas** - Data manipulation and analysis
- **NumPy** - Numerical computing
- **Matplotlib** - Plotting and visualization
- **Plotly** - Interactive visualizations
- **Seaborn** - Statistical data visualization
- **TensorBoard** - Visualization toolkit

### Utilities
- **z3-solver** - Constraint solving and SAT solver
- **ffmpeg** - Multimedia processing
- **geoip2** - IP geolocation database
- **tqdm** - Progress bars for Python
- **fire** - Command-line interface generation
- **imaplib2** - Threaded IMAP client
- **keyring** - Password storage and retrieval

## Platform Differences

### Linux (linux-ctf.yml)
- **Python 3.12** - Latest Python version
- **Sage** - Full mathematical computation system
- Complete development toolchain (GCC, GDB)
- Better compatibility with most security tools
- **Recommended for CTF competitions**

### Windows (windows-ctf.yml)
- **Python 3.10** - For broader tool compatibility
- **python-magic-bin** - File type detection without libmagic
- **Pinned Frida** (16.2.3) - Stable version for Windows
- Limited tool compatibility compared to Linux
- **Consider using WSL2** for better experience

---

## Complete Setup Instructions

### Linux/macOS Setup

#### 1. Create the Environment

```bash
cd CTF
conda env create -f linux-ctf.yml
```

This will take 10-20 minutes depending on your internet connection.

#### 2. Activate the Environment

```bash
conda activate ctf
```

You should see `(ctf)` in your terminal prompt.

#### 3. Verify Key Tools

```bash
# Check Python version
python --version

# Test pwntools
python -c "from pwn import *; print('pwntools:', pwntools.version.version)"

# Test angr
python -c "import angr; print('angr: OK')"

# Test scapy
python -c "from scapy.all import *; print('scapy: OK')"

# Test cryptography
python -c "from Crypto.Cipher import AES; print('pycryptodome: OK')"

# Test z3
python -c "from z3 import *; print('z3: OK')"
```

#### 4. Test Binary Tools

```bash
# Test with a simple binary
echo -e '#include <stdio.h>\nint main() { printf("Hello\\n"); return 0; }' > test.c
gcc test.c -o test

# Use pwntools to interact
python3 << EOF
from pwn import *
p = process('./test')
print(p.recvline())
p.close()
EOF

rm test test.c
```

#### 5. Verify Network Tools

```bash
# Test Scapy (may require root for some operations)
python3 << EOF
from scapy.all import *
print("Scapy loaded successfully")
# List available interfaces (no root needed)
print(f"Available interfaces: {get_if_list()}")
EOF
```

---

### Windows Setup

#### 1. Create the Environment

```powershell
cd CTF
conda env create -f windows-ctf.yml
```

This will take 10-20 minutes depending on your internet connection.

#### 2. Activate the Environment

```powershell
conda activate ctf
```

You should see `(ctf)` in your PowerShell prompt.

#### 3. Verify Key Tools

```powershell
# Check Python version
python --version

# Test pwntools
python -c "from pwn import *; print('pwntools:', pwntools.version.version)"

# Test angr
python -c "import angr; print('angr: OK')"

# Test scapy (limited on Windows)
python -c "from scapy.all import *; print('scapy: OK')"

# Test cryptography
python -c "from Crypto.Cipher import AES; print('pycryptodome: OK')"

# Test z3
python -c "from z3 import *; print('z3: OK')"
```

#### 4. Important Windows Notes

**Administrator Privileges:** Some tools (like network sniffers) require administrator privileges.

**Windows Firewall:** May block some network tools. You may need to allow Python through the firewall.

**WSL2 Recommended:** For best compatibility with CTF tools, consider using Windows Subsystem for Linux 2 (WSL2):

```powershell
# Install WSL2 (requires Windows 10 version 2004+ or Windows 11)
wsl --install

# Then use the Linux instructions within WSL2
```

---

## Common CTF Workflows

### Binary Exploitation

#### Using pwntools

```python
from pwn import *

# Connect to a service
conn = remote('target.com', 1337)
# Or start a local process
# conn = process('./vulnerable_binary')

# Send payload
payload = b'A' * 64 + p64(0xdeadbeef)
conn.sendline(payload)

# Receive response
response = conn.recvline()
print(response)

conn.close()
```

#### Finding ROP Gadgets

```bash
# Using ROPgadget
ROPgadget --binary ./binary --rop

# Using ropper
ropper --file ./binary --search "pop rdi"
```

#### Using angr for Symbolic Execution

```python
import angr

# Load binary
project = angr.Project('./binary', auto_load_libs=False)

# Create initial state
state = project.factory.entry_state()

# Create simulation manager
simgr = project.factory.simulation_manager(state)

# Explore to find winning path
simgr.explore(find=0x401234, avoid=0x401250)

# Get solution
if simgr.found:
    solution = simgr.found[0]
    print(solution.posix.dumps(0))  # Print stdin that leads to solution
```

### Cryptography Challenges

#### Basic Crypto Operations

```python
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import hashlib

# AES Encryption/Decryption
key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_ECB)
plaintext = pad(b'Secret message', AES.block_size)
ciphertext = cipher.encrypt(plaintext)

# Decryption
decipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)

# Hashing
sha256_hash = hashlib.sha256(b'data').hexdigest()
md5_hash = hashlib.md5(b'data').hexdigest()
```

#### Using z3 for Constraint Solving

```python
from z3 import *

# Define variables
x = Int('x')
y = Int('y')

# Create solver
solver = Solver()

# Add constraints
solver.add(x + y == 10)
solver.add(x * 2 == y)

# Solve
if solver.check() == sat:
    model = solver.model()
    print(f"x = {model[x]}, y = {model[y]}")
```

### Network Analysis

#### Packet Sniffing with Scapy

```python
from scapy.all import *

# Sniff packets (requires root/admin on most systems)
def packet_callback(packet):
    if packet.haslayer(TCP):
        print(f"TCP packet: {packet[IP].src} -> {packet[IP].dst}")

# Sniff for 10 packets
sniff(prn=packet_callback, count=10)

# Read from pcap file
packets = rdpcap('capture.pcap')
for pkt in packets:
    if pkt.haslayer(Raw):
        print(pkt[Raw].load)
```

#### Using mitmproxy

```bash
# Start mitmproxy
mitmproxy

# Or use mitmdump for scripting
mitmdump -s script.py

# Configure browser/application to use proxy at localhost:8080
```

### Forensics

#### File Analysis with binwalk

```bash
# Extract embedded files
binwalk -e firmware.bin

# Search for specific file signatures
binwalk --signature firmware.bin

# Extract with dd based on binwalk output
dd if=firmware.bin of=extracted.zip bs=1 skip=12345 count=67890
```

#### Metadata Extraction

```python
import pyexiftool

# Extract metadata
with pyexiftool.ExifTool() as et:
    metadata = et.get_metadata('image.jpg')
    for key, value in metadata.items():
        print(f"{key}: {value}")
```

#### Steganography

```python
from stegano import lsb

# Hide message in image
secret = lsb.hide("image.png", "Secret message")
secret.save("output.png")

# Reveal message
clear_message = lsb.reveal("output.png")
print(clear_message)
```

### Web Exploitation

#### Basic HTTP Requests

```python
import requests

# GET request
response = requests.get('http://target.com/api')
print(response.text)

# POST request with data
data = {'username': 'admin', 'password': 'password'}
response = requests.post('http://target.com/login', data=data)

# Session management
session = requests.Session()
session.post('http://target.com/login', data=data)
response = session.get('http://target.com/protected')
```

#### Using FastAPI for Quick Tools

```python
from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/decode/{data}")
def decode_base64(data: str):
    import base64
    return {"decoded": base64.b64decode(data).decode()}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### Reverse Engineering with Frida

```python
import frida
import sys

# Attach to process
session = frida.attach("target_process")

# Inject JavaScript
script = session.create_script("""
    Interceptor.attach(ptr("0x401000"), {
        onEnter: function(args) {
            console.log("Function called!");
            console.log("Arg1: " + args[0]);
        },
        onLeave: function(retval) {
            console.log("Return value: " + retval);
        }
    });
""")

script.load()
sys.stdin.read()
```

---

## Troubleshooting

### General Issues

#### Environment Creation Fails

**Problem:** Conda fails to resolve dependencies.

**Solutions:**

1. Use mamba for faster solving:
   ```bash
   conda install -n base mamba
   mamba env create -f linux-ctf.yml
   ```

2. Try creating with relaxed channel priority:
   ```bash
   conda config --set channel_priority flexible
   conda env create -f linux-ctf.yml
   ```

3. Install problematic packages separately:
   ```bash
   # Comment out failing packages in yml, create env, then:
   conda activate ctf
   pip install <package-name>
   ```

#### Out of Disk Space

**Problem:** Not enough space for the large CTF environment.

**Solutions:**
```bash
# Clean conda cache
conda clean --all

# Remove package tarballs
conda clean --tarballs

# Remove unused environments
conda env remove -n <old-env>
```

### Platform-Specific Issues

#### Linux Issues

**pwntools Requires Terminal**

Some pwntools features need a proper terminal:
```bash
# If running in IDE or script, set context
from pwn import *
context.log_level = 'error'  # Reduce verbosity
```

**Scapy Requires Root Privileges**

```bash
# Run Python scripts with sudo
sudo $(which python) script.py

# Or use scapy in non-privileged mode (limited functionality)
from scapy.all import *
conf.L3socket = L3RawSocket  # Use raw sockets
```

**GDB with pwntools**

Install gdb separately if needed:
```bash
# Ubuntu/Debian
sudo apt install gdb

# Fedora
sudo dnf install gdb

# Arch
sudo pacman -S gdb
```

Install pwndbg or GEF for enhanced debugging:
```bash
# pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# GEF
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

#### Windows Issues

**Limited Tool Functionality**

Many CTF tools are designed for Linux. Consider using WSL2:

```powershell
# Install WSL2
wsl --install

# Install Ubuntu or Debian
wsl --install -d Ubuntu

# Then use Linux instructions within WSL2
```

**Frida on Windows**

The pinned Frida version (16.2.3) is more stable on Windows. If you need a newer version:
```bash
pip install --upgrade frida frida-tools
```

**Scapy Limited on Windows**

Scapy requires Npcap for full functionality:
1. Download from https://npcap.com/
2. Install with WinPcap compatibility mode
3. Run Python as Administrator

**pwntools on Windows**

pwntools has limited Windows support. For full functionality:
- Use WSL2
- Or use a Linux VM

#### macOS Issues

**Scapy Permissions**

```bash
# Use sudo for packet sniffing
sudo python script.py

# Or adjust BPF device permissions (not recommended)
```

**Binary Tools**

Some binary exploitation tools expect ELF format, not Mach-O:
```bash
# Use Docker or VM for Linux binaries
docker run -it -v $(pwd):/work ubuntu:latest
```

### Tool-Specific Issues

#### angr Issues

**Long Analysis Times**

angr can be slow for large binaries:
```python
import angr

# Load without libraries for speed
proj = angr.Project('./binary', auto_load_libs=False)

# Limit exploration depth
simgr.explore(find=target_addr, avoid=bad_addr, num_find=1)

# Use unicorn engine for concrete execution
proj = angr.Project('./binary', 
                    use_sim_procedures=True,
                    default_analysis_mode='symbolic')
```

**Memory Issues**

```python
# Limit state memory
state = proj.factory.entry_state()
state.libc.max_memcpy_size = 0x100000
```

#### pwntools Issues

**Connection Timeouts**

```python
from pwn import *

# Increase timeout
conn = remote('target.com', 1337, timeout=30)

# Set context for debugging
context.log_level = 'debug'
```

**Process Won't Start**

```python
# Check binary permissions
import os
os.chmod('./binary', 0o755)

# Or specify full path
p = process('/full/path/to/binary')
```

#### z3 Issues

**Solver Takes Too Long**

```python
from z3 import *

# Set timeout (in milliseconds)
solver = Solver()
solver.set("timeout", 5000)

# Simplify before solving
constraints = simplify(And(constraint1, constraint2))
solver.add(constraints)
```

#### Frida Issues

**Cannot Attach to Process**

Linux:
```bash
# Disable ptrace restrictions temporarily
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

Windows:
- Run Python as Administrator
- Some anti-cheat/anti-debug may block Frida

**Script Injection Fails**

```python
import frida

# Wait for process to initialize
import time
session = frida.attach("process_name")
time.sleep(1)

# Load script with error handling
try:
    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()
except Exception as e:
    print(f"Error: {e}")
```

---

## Performance Tips

### Speed Up Environment Creation

1. **Use mamba:**
   ```bash
   conda install -n base mamba
   mamba env create -f linux-ctf.yml
   ```

2. **Use local package cache:**
   ```bash
   # After first creation, cache is used for subsequent envs
   conda clean --index-cache
   ```

3. **Disable automatic updates:**
   ```bash
   conda config --set auto_update_conda false
   ```

### Optimize Tool Performance

#### angr Optimization

```python
import angr

# Use concrete execution when possible
proj = angr.Project('./binary', 
                    auto_load_libs=False,
                    use_sim_procedures=True)

# Enable veritesting
simgr.use_technique(angr.exploration_techniques.Veritesting())
```

#### Scapy Optimization

```python
from scapy.all import *

# Disable DNS resolution
conf.noenum.add(IP)

# Use faster packet reading
packets = rdpcap('file.pcap', count=1000)  # Limit packet count
```

### Memory Management

```python
# Limit concurrent states in angr
simgr.move(from_stash='active', 
           to_stash='deferred', 
           filter_func=lambda s: len(simgr.active) > 100)

# Clear memory in loops
import gc
for i in range(1000):
    # Do work
    if i % 100 == 0:
        gc.collect()
```

---

## Creating Custom Tools

### Quick Dashboard with Streamlit

```python
import streamlit as st
import base64

st.title("CTF Decoder Tool")

# Input
encoded = st.text_input("Enter encoded string:")

# Decode options
decode_type = st.selectbox("Decoding:", ["Base64", "Hex", "URL"])

if st.button("Decode"):
    try:
        if decode_type == "Base64":
            result = base64.b64decode(encoded).decode()
        elif decode_type == "Hex":
            result = bytes.fromhex(encoded).decode()
        elif decode_type == "URL":
            import urllib.parse
            result = urllib.parse.unquote(encoded)
        
        st.success(f"Decoded: {result}")
    except Exception as e:
        st.error(f"Error: {e}")

# Run with: streamlit run tool.py
```

### Automation Script Template

```python
#!/usr/bin/env python3
from pwn import *
import fire

class CTFTool:
    def exploit(self, host, port):
        """Connect and exploit target"""
        conn = remote(host, int(port))
        
        # Your exploit here
        payload = b'A' * 64
        conn.sendline(payload)
        
        response = conn.recvall()
        print(response.decode())
        
        conn.close()
    
    def analyze(self, binary):
        """Analyze binary with angr"""
        import angr
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        print(f"Functions found: {len(cfg.kb.functions)}")

if __name__ == '__main__':
    fire.Fire(CTFTool)

# Usage: ./tool.py exploit --host target.com --port 1337
#        ./tool.py analyze --binary ./binary
```

---

## Useful Commands Reference

### pwntools

```python
from pwn import *

# Connection
r = remote('host', port)
r = process('./binary')

# Sending/Receiving
r.send(data)
r.sendline(data)
r.recv(n)
r.recvline()
r.recvuntil(delim)

# Packing/Unpacking
p32(0x41414141)  # Pack 32-bit
p64(0x4141414141414141)  # Pack 64-bit
u32(data)  # Unpack 32-bit
u64(data)  # Unpack 64-bit

# Shellcode
shellcraft.sh()  # Generate shellcode
asm(shellcraft.sh())  # Assemble it

# Cyclic patterns
cyclic(100)  # Generate pattern
cyclic_find(0x61616171)  # Find offset

# ELF utilities
elf = ELF('./binary')
elf.symbols['main']  # Get symbol address
elf.got['puts']  # Get GOT entry
elf.plt['puts']  # Get PLT entry
```

### Scapy

```python
from scapy.all import *

# Packet creation
pkt = IP(dst="8.8.8.8")/ICMP()

# Sending
send(pkt)  # Layer 3
sendp(pkt)  # Layer 2

# Sniffing
sniff(count=10, prn=lambda x: x.summary())

# Reading pcap
pkts = rdpcap('file.pcap')

# Filtering
pkts = sniff(filter="tcp port 80", count=10)
```

### Cryptography

```python
from Crypto.Cipher import AES, RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import hashlib

# AES
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

# RSA
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Hashing
h = SHA256.new(data)
h = hashlib.sha256(data).hexdigest()
```

---

## Additional Resources

### Learning Resources

- **CTF Writeups:** https://ctftime.org/writeups
- **CTF Tools Collection:** https://github.com/zardus/ctf-tools
- **pwntools Documentation:** https://docs.pwntools.com/
- **angr Documentation:** https://docs.angr.io/
- **Cryptopals Challenges:** https://cryptopals.com/

### Practice Platforms

- **picoCTF:** https://picoctf.org/
- **HackTheBox:** https://www.hackthebox.com/
- **TryHackMe:** https://tryhackme.com/
- **OverTheWire:** https://overthewire.org/
- **pwnable.kr:** http://pwnable.kr/
- **ROP Emporium:** https://ropemporium.com/

### Community

- **CTFtime:** https://ctftime.org/
- **r/securityCTF:** https://reddit.com/r/securityCTF
- **Discord Servers:** Many CTF teams have public Discord servers

---

## Updating the Environment

### Update All Packages

```bash
conda activate ctf
conda update --all
```

### Update from YAML

```bash
conda env update -f linux-ctf.yml --prune
```

### Add Tools

```bash
conda activate ctf
conda install <package>
pip install <tool>
```

### Export Modified Environment

```bash
conda env export > my-ctf-env.yml
```

---

[← Back to Main README](../README.md)