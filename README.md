# Simple Port Scanner

`portscan.py` is a small TCP port scanner that runs with Python’s standard
library on Linux, Windows CMD, and Windows PowerShell. It does not require
third-party packages.

Only scan systems that you own or have permission to test.

## Requirements

- Python 3.9 or newer

Check that Python is available:

```text
python --version
```

On some Linux installations, use `python3` instead of `python`.

## Usage

Linux:

```bash
python3 portscan.py 127.0.0.1
python3 portscan.py example.com --ports 22,80,443
python3 portscan.py 192.168.1.1 --ports 1-1024 --timeout 0.5
```

Windows CMD:

```bat
python portscan.py 127.0.0.1
python portscan.py example.com --ports 80,443
```

Windows PowerShell:

```powershell
python .\portscan.py 127.0.0.1
python .\portscan.py example.com --ports 1-1024 --workers 100
```

If the Windows Python launcher is installed, `py` can be used in place of
`python`.

## Options

```text
usage: portscan.py [-h] [-p PORTS] [-t TIMEOUT] [-w WORKERS]
                   [--show-closed]
                   host
```

- `host`: hostname or IP address to scan.
- `--ports`: comma-separated ports and/or ranges, for example
  `22,80,443,8000-8010`. If omitted, a short list of common ports is scanned.
- `--timeout`: TCP connection timeout in seconds. Default: `0.75`.
- `--workers`: number of simultaneous checks. Default: `64`.
- `--show-closed`: include ports that refused or timed out in the output.

## Example output

```text
Scanning 127.0.0.1 (127.0.0.1)
TCP ports: 3 | timeout: 0.75s

PORT    STATE     SERVICE         DETAIL
----------------------------------------------------------
22      open      ssh             0.4 ms
80      closed    http            0.3 ms (refused)
443     closed    https           0.3 ms (refused)

Finished: 1 open / 3 checked
```
