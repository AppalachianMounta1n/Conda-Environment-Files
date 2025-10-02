# CTF Environment

A specialized environment for Capture The Flag competitions and cybersecurity research.

## Tool Categories

### Binary Exploitation & Reverse Engineering
- **pwntools** - CTF exploitation framework
- **angr** - Binary analysis and symbolic execution
- **Frida** - Dynamic instrumentation
- **ROPgadget, ropper** - ROP chain generation
- **capstone, keystone, unicorn** - Disassembly, assembly, emulation
- **pyelftools, r2pipe** - Binary analysis

### Cryptography
- **pycryptodome** - Cryptographic primitives
- **z3-solver** - Constraint solving
- **Sage** - Mathematical computation (Linux only)

### Forensics
- **binwalk** - Firmware analysis
- **pyexiftool** - Metadata extraction
- **stegano, stegcracker** - Steganography
- **ffmpeg** - Multimedia analysis

### Network Analysis
- **scapy** - Packet manipulation
- **pyshark** - Wireshark integration
- **mitmproxy** - HTTPS proxy
- **paramiko** - SSH protocol

### Web & Development
- **requests** - HTTP library
- **FastAPI** - Web framework
- **Streamlit** - Quick dashboards

### Data Analysis
- **pandas, numpy, matplotlib** - Data manipulation
- **plotly, seaborn** - Visualization

---

## Quick Setup

### Linux/macOS

```bash
chmod +x setup-ctf.sh
./setup-ctf.sh
```

### Windows

```powershell
.\setup-ctf.ps1
```

The setup script will:
1. Create/update the conda environment named `ctf`
2. Test all key CTF tools
3. Verify the installation

**Setup time:** 10-20 minutes depending on your internet connection.

**Note:** Some tools have limited functionality on Windows. WSL2 is recommended for full compatibility.

---

## Usage

### Activate the Environment

```bash
conda activate ctf
```

### Quick Verification

The setup script tests all tools automatically. To manually verify key tools:

```bash
python -c "from pwn import *; print('pwntools:', pwntools.version.version)"
python -c "import angr; print('angr: OK')"
python -c "from scapy.all import *; print('scapy: OK')"
```

---

## Common Workflows

### Binary Exploitation

```python
from pwn import *

# Connect to target
conn = remote('target.com', 1337)

# Send payload
payload = b'A' * 64 + p64(0xdeadbeef)
conn.sendline(payload)

# Receive flag
flag = conn.recvline()
print(flag)
```

### Finding ROP Gadgets

```bash
ROPgadget --binary ./binary --rop
ropper --file ./binary --search "pop rdi"
```

### Symbolic Execution with angr

```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# Find winning path
simgr.explore(find=0x401234, avoid=0x401250)

if simgr.found:
    print(simgr.found[0].posix.dumps(0))
```

### Cryptography

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# AES
key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(b'message', AES.block_size))

# Hashing
sha256 = hashlib.sha256(b'data').hexdigest()
```

### Constraint Solving with z3

```python
from z3 import *

x = Int('x')
y = Int('y')
solver = Solver()
solver.add(x + y == 10)
solver.add(x * 2 == y)

if solver.check() == sat:
    model = solver.model()
    print(f"x = {model[x]}, y = {model[y]}")
```

### Network Analysis

```python
from scapy.all import *

# Sniff packets (requires root/admin)
def packet_callback(packet):
    if packet.haslayer(TCP):
        print(f"{packet[IP].src} -> {packet[IP].dst}")

sniff(prn=packet_callback, count=10)

# Read pcap
packets = rdpcap('capture.pcap')
for pkt in packets:
    if pkt.haslayer(Raw):
        print(pkt[Raw].load)
```

### Forensics

```bash
# Extract embedded files
binwalk -e firmware.bin

# Steganography
python -c "from stegano import lsb; print(lsb.reveal('image.png'))"
```

### Web Exploitation

```python
import requests

# Session management
session = requests.Session()
session.post('http://target.com/login', data={'user': 'admin', 'pass': 'pass'})
response = session.get('http://target.com/flag')
print(response.text)
```

### Dynamic Instrumentation with Frida

```python
import frida

session = frida.attach("target_process")
script = session.create_script("""
    Interceptor.attach(ptr("0x401000"), {
        onEnter: function(args) {
            console.log("Called with:", args[0]);
        }
    });
""")
script.load()
```

---

## Platform Differences

### Linux (Recommended)
- Python 3.12
- Full tool compatibility
- Sage mathematical software included
- Better performance for binary analysis

### Windows
- Python 3.10 (broader compatibility)
- Some tools have limited functionality
- **Strongly recommend using WSL2:**
  ```powershell
  wsl --install -d Ubuntu
  # Then use linux-ctf.yml inside WSL2
  ```

---

## Troubleshooting

### General Issues

**Slow environment creation:**
```bash
conda install -n base mamba
# Edit setup script to use mamba instead of conda
```

**Out of disk space:**
```bash
conda clean --all
```

### Platform-Specific

#### Linux

**pwntools needs terminal:**
```python
from pwn import *
context.log_level = 'error'  # Reduce verbosity
```

**Scapy needs root:**
```bash
sudo $(which python) script.py
```

**Install pwndbg/GEF for better debugging:**
```bash
# pwndbg
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# GEF
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

#### Windows

**Limited functionality:**
Use WSL2 for full compatibility:
```powershell
wsl --install -d Ubuntu
```

**Scapy needs Npcap:**
Download from https://npcap.com/ and install with WinPcap compatibility.

**Run as Administrator:**
Some tools require elevated privileges.

### Tool-Specific

**angr too slow:**
```python
proj = angr.Project('./binary', auto_load_libs=False)
# Limit exploration
simgr.explore(find=target, avoid=bad, num_find=1)
```

**z3 timeout:**
```python
solver = Solver()
solver.set("timeout", 5000)  # milliseconds
```

**Frida can't attach:**
```bash
# Linux - disable ptrace restrictions
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

---

## Quick Reference

### pwntools
```python
from pwn import *

# Connection
r = remote('host', port)
r = process('./binary')

# I/O
r.sendline(data)
r.recvuntil(delim)

# Packing
p32(0x41414141)
p64(0x4141414141414141)

# Shellcode
shellcraft.sh()
asm(shellcraft.sh())

# Cyclic
cyclic(100)
cyclic_find(0x61616171)
```

### Scapy
```python
from scapy.all import *

# Create packet
pkt = IP(dst="8.8.8.8")/ICMP()

# Send
send(pkt)

# Sniff
sniff(filter="tcp port 80", count=10)

# Read pcap
pkts = rdpcap('file.pcap')
```

### Crypto
```python
from Crypto.Cipher import AES, RSA
from Crypto.Hash import SHA256
import hashlib

# AES
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(pt, AES.block_size))

# Hashing
h = hashlib.sha256(data).hexdigest()
```

---

## Learning Resources

### Practice Platforms
- **picoCTF:** https://picoctf.org/
- **HackTheBox:** https://www.hackthebox.com/
- **TryHackMe:** https://tryhackme.com/
- **pwnable.kr:** http://pwnable.kr/
- **ROP Emporium:** https://ropemporium.com/

### Documentation
- **pwntools:** https://docs.pwntools.com/
- **angr:** https://docs.angr.io/
- **Cryptopals:** https://cryptopals.com/

### Community
- **CTFtime:** https://ctftime.org/
- **r/securityCTF:** https://reddit.com/r/securityCTF

---

## Creating Custom Tools

### Quick Dashboard with Streamlit

```python
import streamlit as st
import base64

st.title("CTF Decoder")
encoded = st.text_input("Enter encoded string:")
decode_type = st.selectbox("Decoding:", ["Base64", "Hex", "URL"])

if st.button("Decode"):
    if decode_type == "Base64":
        result = base64.b64decode(encoded).decode()
        st.success(f"Decoded: {result}")

# Run with: streamlit run tool.py
```

### Automation Script

```python
#!/usr/bin/env python3
from pwn import *
import fire

class CTFTool:
    def exploit(self, host, port):
        conn = remote(host, int(port))
        payload = b'A' * 64
        conn.sendline(payload)
        print(conn.recvall().decode())
        conn.close()

if __name__ == '__main__':
    fire.Fire(CTFTool)

# Usage: ./tool.py exploit --host target.com --port 1337
```

---

## Updating

### Update Environment
```bash
cd CTF
./setup-ctf.sh  # Runs conda env update automatically
```

### Add Tools
```bash
conda activate ctf
pip install <tool-name>
```

---

## Manual Setup (Alternative)

If the setup script fails:

### Linux/macOS
```bash
conda env create -f linux-ctf.yml
conda activate ctf
```

### Windows
```powershell
conda env create -f windows-ctf.yml
conda activate ctf
```

---

[← Back to Main README](../README.md)