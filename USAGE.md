# Port Scanner Detailed Usage Guide

## Basic Command Syntax

```bash
python portscan.py [HOSTS...] [OPTIONS]
```

Or when installed with `pip install .`:

```bash
portscan [HOSTS...] [OPTIONS]
```

---

## Specifying Targets

You can pass single hosts, hostnames, CIDR network blocks, IP ranges, or a file list:

### 1. Hostnames and Single IPs
```bash
python portscan.py 127.0.0.1
python portscan.py scanme.nmap.org
python portscan.py 192.168.1.1 192.168.1.254
```

### 2. CIDR Subnets
Scan all hosts in a subnet (e.g. `/24` or `/28`):
```bash
python portscan.py 192.168.1.0/24 -p 22,80,443
```

### 3. IP Ranges
Scan a continuous range of IP addresses:
```bash
python portscan.py 10.0.0.1-10.0.0.50 -p 80,443
# Or using suffix notation:
python portscan.py 192.168.1.10-50 -p 22,80
```

### 4. Reading Targets from a File (`-iL`)
Create a file, e.g., `targets.txt`:
```text
# Internal servers
192.168.1.1
192.168.1.100
# External web servers
example.com
```

Scan all targets in the file:
```bash
python portscan.py -iL targets.txt -p 80,443,8080
```

---

## Selecting Ports (`-p`, `--ports`)

If omitted, the scanner checks a default list of 22 standard services (SSH, HTTP, HTTPS, MySQL, RDP, etc.).

### Comma-separated list:
```bash
python portscan.py example.com -p 21,22,80,443,3306,8080
```

### Port ranges:
```bash
python portscan.py example.com -p 1-1024
```

### Combined syntax:
```bash
python portscan.py example.com -p 22,80,443,8000-8080
```

---

## Service Banner Grabbing (`-b`, `--banner`)

Add the `-b` or `--banner` flag to interrogate open ports and detect service versions:

```bash
python portscan.py 192.168.1.1 -p 21,22,80,443 --banner
```

Example output with banner grabbing:
```text
PORT    STATE     SERVICE       BANNER                      DETAIL
-------------------------------------------------------------------------
22      open      ssh           SSH-2.0-OpenSSH_8.9p1       0.8 ms
80      open      http          Server: nginx/1.18.0        1.2 ms
```

---

## Exporting Results (`-o`, `-f`)

### Export to JSON:
```bash
python portscan.py example.com -p 80,443 --banner -o results.json
```

Example `results.json`:
```json
[
  {
    "host": "example.com",
    "ip": "93.184.216.34",
    "port": 80,
    "state": "open",
    "service": "http",
    "banner": "Server: ECS (dcb/7F3E)",
    "elapsed_ms": 14.2,
    "reason": "connected"
  }
]
```

### Export to CSV:
```bash
python portscan.py 192.168.1.0/24 -p 22,80,443 -o results.csv
```

---

## Performance & Concurrency Tuning

### Timeout (`-t`, `--timeout`)
Connection timeout per port in seconds (default: `0.75`).
* For local / high-speed LAN networks: `-t 0.2`
* For high-latency or remote connections: `-t 1.5`

```bash
python portscan.py 192.168.1.1 -t 0.3
```

### Parallel Workers (`-w`, `--workers`)
Number of concurrent threads (default: `64`).
```bash
python portscan.py example.com -p 1-10000 -w 150
```

---

## Colors and Terminal Customization

Terminal output uses ANSI colors by default. To disable color highlighting (e.g. for piping or clean logs):

```bash
python portscan.py 127.0.0.1 --no-color
```
Or set the environment variable `NO_COLOR=1`.
