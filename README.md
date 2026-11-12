# Simple Port Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-brightgreen.svg)](https://www.python.org/downloads/)
[![Open Source](https://img.shields.io/badge/Open%20Source-Yes-brightgreen)](LICENSE)

A fast, lightweight, and open-source TCP port scanner and service banner grabber built with **Python's standard library**. It runs out-of-the-box on Linux, Windows, and macOS without requiring any third-party dependencies.

> **Disclaimer**: Only scan systems that you own or have explicit authorization to test.

---

## Features

- **Zero External Dependencies**: Runs entirely on Python's standard library.
- **Service Banner Grabbing**: Detects server software versions (e.g. OpenSSH, Apache, Nginx) on open ports (`-b`, `--banner`).
- **CIDR & Subnet Scanning**: Scan single targets, IP ranges, or entire subnets (`192.168.1.0/24`, `10.0.0.1-50`, or `-iL targets.txt`).
- **Export Formats**: Save clean output directly to **JSON**, **CSV**, or formatted text tables (`-o results.json`).
- **Live Output & ANSI Colors**: Instant terminal streaming of open ports with colored state indicators (`--no-color` supported).
- **High Concurrency**: Configurable multithreading via `ThreadPoolExecutor` (`-w`, `--workers`).
- **Graceful Interrupts**: Cleanly handles `Ctrl+C` without dumping tracebacks.
- **Open Source**: Licensed under the permissive **MIT License**.

---

## Installation & Setup

Clone the repository:

```bash
git clone https://github.com/KKMHARI/Simple-portscaner.git
cd Simple-portscaner
```

No package installation is necessary to run the scanner. If you wish to run unit tests or contribute, install development dependencies:

```bash
pip install -r requirements.txt
```

You can also install it as a command-line tool:

```bash
pip install .
```

---

## Quick Start

### 1. Basic Scan
Scan common ports on a single host:
```bash
python portscan.py 127.0.0.1
```

### 2. Custom Port Range
Scan specific ports or port ranges:
```bash
python portscan.py example.com -p 22,80,443,8000-8080
```

### 3. Banner Grabbing
Inspect service banners and software versions on open ports:
```bash
python portscan.py 192.168.1.1 -p 21,22,80,443 --banner
```

### 4. Subnet / CIDR Scan
Scan an entire subnet or IP range:
```bash
python portscan.py 192.168.1.0/24 -p 22,80,443
python portscan.py 10.0.0.1-50 -p 80,443
```

### 5. Multi-Target File & JSON Export
Read targets from a file and export the output to JSON:
```bash
python portscan.py -iL targets.txt -p 80,443,8080 -o results.json
```

---

## Command Options

```text
usage: portscan.py [-h] [-iL TARGETS_FILE] [-p PORTS] [-t TIMEOUT]
                   [-w WORKERS] [-b] [--show-closed] [-o OUTPUT]
                   [-f {json,csv,table}] [--no-color]
                   [hosts ...]
```

| Flag | Name | Description |
| :--- | :--- | :--- |
| `hosts` | Positional | One or more hostnames, IPs, CIDR blocks, or IP ranges |
| `-iL` | `--targets-file` | Load target list from a file (one host per line) |
| `-p` | `--ports` | Ports list (e.g. `22,80,443`) or range (`1-1024`) |
| `-t` | `--timeout` | Socket connection timeout in seconds (default: `0.75`) |
| `-w` | `--workers` | Maximum parallel threads (default: `64`) |
| `-b` | `--banner` | Attempt service banner grabbing on open ports |
| | `--show-closed` | Display closed and timed out ports in output |
| `-o` | `--output` | Save results to file (auto-detects `.json`, `.csv`, `.txt`) |
| `-f` | `--format` | Output format: `json`, `csv`, or `table` |
| | `--no-color` | Disable ANSI color highlighting in terminal |

---

## Running Tests

Run the built-in test suite:

```bash
python -m unittest discover -s tests
```

---

## License

This project is open-source and released under the [MIT License](LICENSE). Feel free to use, modify, and distribute it.
