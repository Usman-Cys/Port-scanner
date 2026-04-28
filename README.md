# PyPortScanner

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Code Style](https://img.shields.io/badge/code%20style-black-black)

> ⚠️ **FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.**
> Scanning networks without explicit written permission is illegal. The authors accept no liability for misuse.

---

A **production-ready Python port scanner** built for learning and ethical security testing.
PyPortScanner supports TCP connect scan, SYN stealth scan, UDP scan, banner grabbing, and service fingerprinting — all from a clean CLI.

---

## Features

| Feature | Description |
|---------|-------------|
| 🔍 TCP Connect Scan | Full three-way handshake scan (no root required) |
| 👻 SYN Stealth Scan | Half-open scan via raw sockets (`--syn`, requires root) |
| 📡 UDP Scan | Probe-based UDP scanning with ICMP inference |
| 🏷️ Banner Grabbing | Read service greetings from open ports (`--banner`) |
| 🧩 Service Detection | Match banners & port numbers to 99+ known services |
| 🎨 Rich Table Output | Colourised terminal table (green/red/yellow) |
| 📄 JSON / CSV Export | Machine-readable results for further analysis |
| ⚡ Multi-threaded | Configurable thread pool (default 100, up to 500+) |
| 🛡️ Safety Checks | Public IP warning, `--dry-run` preview mode |

---

## Installation

```bash
git clone https://github.com/Usman-Cys/Port-scanner.git
cd Port-scanner
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

For SYN scan support (requires root/admin):
```bash
pip install scapy
```

---

## Quick Examples

```bash
# Single target — top 1000 ports
python scanner.py -t 192.168.1.1

# Port range with banner grabbing, 200 threads
python scanner.py -t 192.168.1.1 -p 1-65535 --banner -T 200

# Multiple targets, specific ports, JSON output
python scanner.py -t 10.0.0.1,10.0.0.2 -p 22,80,443,8080 --json results.json

# UDP scan (DNS, SNMP, NTP)
python scanner.py -t 192.168.1.1 -p 53,161,123 --udp

# CIDR subnet scan → CSV report
python scanner.py -t 192.168.1.0/24 -p 22,80,443 --banner --csv network_scan.csv

# Stealth SYN scan (root required)
sudo python scanner.py -t 192.168.1.1 -p 1-1000 --syn

# Preview without sending packets
python scanner.py -t 192.168.1.1 -p 22,80,443 --dry-run
```

---

## Why PyPortScanner vs nmap?

| | PyPortScanner | nmap |
|---|---|---|
| **Language** | Pure Python | C |
| **Purpose** | Learning, portfolio, customisation | Production pen-testing |
| **Scripting** | Import as a Python library | NSE scripts (Lua) |
| **Dependencies** | Standard library + `rich` | System install |
| **Educational** | ✅ Commented source, explains TCP/UDP | ❌ Complex C codebase |
| **Performance** | Good (Python threads) | Excellent (C + async I/O) |

---

## Project Structure

```
Port-scanner/
├── scanner.py              # Main CLI entry point
├── config.py               # Constants (timeout, threads, etc.)
├── requirements.txt
├── core/
│   ├── tcp_scanner.py      # TCP connect / SYN scanning
│   ├── udp_scanner.py      # UDP scanning with service probes
│   ├── banner_grabber.py   # Banner grabbing & parsing
│   └── service_detector.py # Service fingerprinting
├── utils/
│   ├── network_utils.py    # IP/port parsing
│   ├── output_formatter.py # Table, JSON, CSV output
│   └── logger.py           # Rotating file logger
├── data/
│   └── common_services.json # 99 well-known port→service mappings
├── tests/
│   ├── test_tcp_scanner.py
│   ├── test_udp_scanner.py
│   ├── test_banner_grabber.py
│   └── test_network_utils.py
└── docs/
    └── USAGE.md
```

---

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v
pytest tests/ --cov=. --cov-report=term-missing
```

---

## Legal Disclaimer

This tool is provided for **educational and authorised security testing** purposes only.
Using this tool against systems you do not own or have explicit permission to test may violate
local, national, or international laws. The authors disclaim all liability for misuse.

**Never scan networks you don't own or have written permission to test.**

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/awesome-feature`)
3. Make your changes with tests
4. Run `pytest tests/ -v` to verify
5. Submit a pull request
