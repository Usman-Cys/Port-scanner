# PyPortScanner — Usage Guide

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Scan Types](#scan-types)
4. [Output Options](#output-options)
5. [Advanced Usage](#advanced-usage)
6. [Safety Checks](#safety-checks)
7. [CLI Reference](#cli-reference)

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Usman-Cys/Port-scanner.git
cd Port-scanner

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Install scapy for SYN scan support
pip install scapy
```

---

## Quick Start

```bash
# Scan the top 1000 ports on a single host
python scanner.py -t 192.168.1.1

# Preview what WOULD be scanned (no packets sent)
python scanner.py -t 192.168.1.1 --dry-run
```

---

## Scan Types

### TCP Connect Scan (default)

The safest and most reliable scan type. Performs a full TCP three-way handshake.

```bash
python scanner.py -t 192.168.1.1 -p 1-1000
```

### TCP SYN (Stealth) Scan

Sends only a SYN packet and never completes the handshake. Requires root/admin.

```bash
sudo python scanner.py -t 192.168.1.1 -p 1-1000 --syn
```

### UDP Scan

Sends UDP probes and infers port state from responses or ICMP unreachable messages.

```bash
python scanner.py -t 192.168.1.1 -p 53,123,161 --udp
```

### Banner Grabbing

After finding open TCP ports, connect and read the service greeting.

```bash
python scanner.py -t 192.168.1.1 -p 1-1000 --banner
```

---

## Output Options

### Terminal Table (default)

Pretty, colourised table printed to stdout:
- 🟢 **OPEN** — port accepts connections
- 🔴 **CLOSED** — connection refused
- 🟡 **FILTERED** — no response (firewall/drop)

### JSON Export

```bash
python scanner.py -t 192.168.1.1 --json results.json
```

Output format:
```json
[
  {
    "host": "192.168.1.1",
    "port": 22,
    "protocol": "tcp",
    "status": "OPEN",
    "service": "ssh",
    "version": "OpenSSH_8.9",
    "banner": "SSH-2.0-OpenSSH_8.9p1",
    "scan_time": 0.0021
  }
]
```

### CSV Export

```bash
python scanner.py -t 192.168.1.0/24 -p 22,80,443 --csv network_scan.csv
```

---

## Advanced Usage

### CIDR Range Scan

```bash
# Scan all 254 hosts in a /24 subnet
python scanner.py -t 192.168.1.0/24 -p 22,80,443 --banner --csv out.csv
```

### Multiple Targets

```bash
python scanner.py -t 10.0.0.1,10.0.0.2,10.0.0.3 -p 22,80,443
```

### High-Speed Scan

```bash
# 500 threads, 0.5s timeout
python scanner.py -t 192.168.1.1 -p 1-65535 -T 500 --timeout 0.5
```

### Rate-Limited Scan

```bash
# Add 0.1 second delay between probes (stealthy / polite)
python scanner.py -t 192.168.1.1 -p 1-1000 --delay 0.1
```

### Full Workflow Example

```bash
# Enumerate a subnet, grab banners, export everything
python scanner.py \
  -t 192.168.10.0/24 \
  -p 21,22,23,25,80,110,143,443,445,3306,3389,8080 \
  --banner \
  -T 200 \
  --timeout 1.5 \
  --json full_scan.json \
  --csv full_scan.csv
```

---

## Safety Checks

PyPortScanner includes built-in safety features:

| Feature | Behaviour |
|---------|-----------|
| Public IP warning | Prints a warning when scanning non-RFC-1918 addresses |
| `--dry-run` | Shows scan parameters without sending any packets |
| `--no-safe-check` | Suppress the public IP warning (use responsibly) |

---

## CLI Reference

```
usage: scanner.py [-h] -t TARGET [-p PORTS] [--udp | --syn]
                  [-T N] [--timeout SECS] [--delay SECS]
                  [--banner] [--show-closed]
                  [--json FILE] [--csv FILE]
                  [--no-safe-check] [--dry-run] [-v] [--version]

Options:
  -t, --target TARGET     IP, CIDR, hostname, or comma-separated list
  -p, --ports PORTS       Port spec: 80, 1-1000, 22,80,443, mixed
  --udp                   UDP scan mode
  --syn                   SYN stealth scan (root required)
  -T, --threads N         Concurrent threads (default: 100)
  --timeout SECS          Socket timeout per probe (default: 1.0)
  --delay SECS            Inter-probe delay for rate limiting (default: 0)
  --banner                Grab service banners from open TCP ports
  --show-closed           Include CLOSED ports in output
  --json FILE             Export results to JSON
  --csv FILE              Export results to CSV
  --no-safe-check         Disable public IP warning
  --dry-run               Preview scan without sending packets
  -v, --verbose           Debug logging to console
  --version               Show version number
```

---

## Disclaimer

> ⚠️ **FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.**
> Scanning networks without explicit written permission from the network owner is
> illegal in many jurisdictions (e.g. Computer Fraud and Abuse Act in the USA,
> Computer Misuse Act in the UK). The authors accept no liability for misuse.
