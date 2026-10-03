# Port Scanner Usage Help

## Basic command

```text
python portscan.py HOST [OPTIONS]
```

Replace `HOST` with a hostname or IP address. For example:

```text
python portscan.py 127.0.0.1
python portscan.py example.com
```

On Linux, use `python3` if `python` starts a different program:

```bash
python3 portscan.py 127.0.0.1
```

On Windows, the `py` launcher can also be used:

```powershell
py .\portscan.py 127.0.0.1
```

## Display built-in help

Linux:

```bash
python3 portscan.py --help
```

Windows CMD:

```bat
python portscan.py --help
```

Windows PowerShell:

```powershell
python .\portscan.py --help
```

## Options

### `-p`, `--ports`

Choose which TCP ports to scan. Use commas for separate ports and a hyphen
for a range.

```bash
python3 portscan.py 192.168.1.1 --ports 22,80,443
python3 portscan.py 192.168.1.1 --ports 1-1024
python3 portscan.py 192.168.1.1 --ports 22,80,8000-8010
```

If this option is omitted, the scanner checks a list of common ports.

### `-t`, `--timeout`

Set the connection timeout in seconds. The default is `0.75` seconds.

```bash
python3 portscan.py example.com --ports 80,443 --timeout 1
```

A lower value makes scans faster on responsive networks. A higher value can
help when the target or network is slow.

### `-w`, `--workers`

Set the number of simultaneous port checks. The default is `64`.

```bash
python3 portscan.py 192.168.1.1 --ports 1-1024 --workers 100
```

### `--show-closed`

Show ports that did not accept a connection, including refused and timed-out
connections.

```bash
python3 portscan.py 127.0.0.1 --ports 20-25 --show-closed
```

Without this option, only open ports are listed.

## Complete examples

Scan common ports on a local computer:

```bash
python3 portscan.py localhost
```

Scan web ports on Windows PowerShell:

```powershell
python .\portscan.py example.com --ports 80,443,8080
```

Scan the first 1024 ports and show every result in Windows CMD:

```bat
python portscan.py 192.168.1.1 --ports 1-1024 --show-closed
```

## Understanding the output

```text
PORT    STATE     SERVICE         DETAIL
----------------------------------------------------------
22      open      ssh             0.5 ms
80      closed    http            0.3 ms (refused)
```

- `PORT`: TCP port number.
- `STATE`: `open` means a TCP connection was accepted. `closed` means the
  connection was not accepted.
- `SERVICE`: common service name when known on the local system.
- `DETAIL`: connection time and, for closed ports, the failure reason.

## Common problems

### Python is not recognized

Install Python 3, then try `python`, `python3`, or `py` depending on your
operating system and installation.

### Host could not be resolved

Check the hostname or IP address and confirm that DNS or the network is
available.

### Permission or firewall errors

A firewall may block connections or make ports appear to time out. Scan only
systems you own or have explicit permission to test.
