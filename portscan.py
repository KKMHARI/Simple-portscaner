#!/usr/bin/env python3
"""Fast, lightweight cross-platform TCP port scanner and banner grabber.

This program uses only Python's standard library so it runs out-of-the-box
on Linux, macOS, and Windows without installing third-party packages.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Sequence

DEFAULT_PORTS = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    8080,
)


class Colors:
    """ANSI color codes with runtime enable/disable support."""

    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        cls.GREEN = ""
        cls.RED = ""
        cls.YELLOW = ""
        cls.CYAN = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RESET = ""


def init_colors(no_color: bool = False) -> None:
    """Initialize terminal color support."""
    if no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        Colors.disable()
        return

    if sys.platform == "win32":
        # Enable VT100 escape sequence processing on Windows console
        try:
            os.system("")
        except Exception:
            Colors.disable()


@dataclass(frozen=True)
class ScanResult:
    """Result for one TCP port on a target host."""

    host: str
    ip: str
    port: int
    is_open: bool
    elapsed_ms: float
    reason: str
    service: str
    banner: str = ""

    def to_dict(self) -> dict:
        data = asdict(self)
        data["state"] = "open" if self.is_open else "closed"
        return data


def parse_ports(value: str) -> list[int]:
    """Parse comma-separated ports and ranges (e.g. '80,443,8000-8010') into sorted unique ints."""
    ports: set[int] = set()
    for item in value.split(","):
        item = item.strip()
        if not item:
            raise ValueError("port list contains an empty item")

        if "-" in item:
            pieces = item.split("-")
            if len(pieces) != 2:
                raise ValueError(f"invalid port range: {item}")
            try:
                first, last = (int(piece.strip()) for piece in pieces)
            except ValueError as exc:
                raise ValueError(f"invalid port range: {item}") from exc
            if first > last:
                raise ValueError(f"port range must start at its lower value: {item}")
            ports.update(range(first, last + 1))
        else:
            try:
                ports.add(int(item))
            except ValueError as exc:
                raise ValueError(f"invalid port: {item}") from exc

    invalid = sorted(port for port in ports if not 1 <= port <= 65535)
    if invalid:
        raise ValueError(
            "ports must be between 1 and 65535: "
            + ", ".join(str(port) for port in invalid[:5])
        )

    return sorted(ports)


def expand_target(target: str) -> list[str]:
    """Expand a single target string (hostname, IP, CIDR subnet, or IP range)."""
    target = target.strip()
    if not target:
        return []

    # Check for CIDR notation (e.g. 192.168.1.0/24)
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses == 1:
                return [str(network.network_address)]
            hosts = list(network.hosts())
            if not hosts:
                return [str(ip) for ip in network]
            return [str(ip) for ip in hosts]
        except ValueError:
            pass  # Fall through to treat as domain/hostname if invalid CIDR

    # Check for IP ranges (e.g. 192.168.1.1-192.168.1.10 or 192.168.1.1-10)
    if "-" in target and not target.startswith("-"):
        parts = target.split("-", 1)
        start_str = parts[0].strip()
        end_str = parts[1].strip()
        try:
            start_ip = ipaddress.ip_address(start_str)
            if "." in end_str and not end_str.isdigit():
                end_ip = ipaddress.ip_address(end_str)
            else:
                prefix = start_str.rsplit(".", 1)[0]
                end_ip = ipaddress.ip_address(f"{prefix}.{end_str}")

            if int(start_ip) <= int(end_ip):
                if int(end_ip) - int(start_ip) > 65536:
                    raise ValueError(f"IP range too large: {target} (maximum 65536 hosts)")
                return [
                    str(ipaddress.ip_address(ip_num))
                    for ip_num in range(int(start_ip), int(end_ip) + 1)
                ]
        except ValueError:
            pass

    return [target]


def load_targets(targets: Sequence[str], targets_file: str | None = None) -> list[str]:
    """Combine positional targets and target file entries into an expanded target list."""
    resolved_list: list[str] = []
    seen: set[str] = set()

    def add_target(raw: str) -> None:
        for t in expand_target(raw):
            if t not in seen:
                seen.add(t)
                resolved_list.append(t)

    for target in targets:
        add_target(target)

    if targets_file:
        try:
            with open(targets_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        add_target(line)
        except OSError as exc:
            raise ValueError(f"Failed to read targets file {targets_file!r}: {exc}") from exc

    return resolved_list


def service_name(port: int) -> str:
    """Return local TCP service name when known."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def resolve_target(host: str) -> list[str]:
    """Resolve a target hostname and return sorted unique IP addresses."""
    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
        return sorted(addresses)
    except socket.gaierror:
        return []


def grab_banner(sock: socket.socket, host: str, port: int) -> str:
    """Retrieve service banner on an established TCP connection."""
    banner = ""
    sock.settimeout(0.8)

    # 1. Passive receive (SSH, FTP, SMTP, POP3 send banner immediately)
    try:
        data = sock.recv(1024)
        if data:
            banner = data.decode("utf-8", errors="replace").strip()
    except (socket.timeout, OSError):
        pass

    # 2. Active probe if passive receive was empty
    if not banner:
        try:
            if port in (80, 8080, 8000, 8888, 3000, 5000):
                probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: SimplePortScan/1.1\r\n\r\n"
                sock.sendall(probe.encode("utf-8"))
            else:
                sock.sendall(b"\r\n\r\n")

            data = sock.recv(1024)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
        except (socket.timeout, OSError):
            pass

    if banner:
        lines = [line.strip() for line in banner.splitlines() if line.strip()]
        for line in lines:
            if line.lower().startswith("server:"):
                return line
        if lines:
            return lines[0][:60]
    return ""


def scan_port(
    host: str,
    ip: str,
    port: int,
    timeout: float,
    do_banner: bool = False,
) -> ScanResult:
    """Attempt one TCP connection and optionally grab the service banner."""
    started = time.perf_counter()
    is_open = False
    reason = "closed"
    banner = ""
    service = service_name(port)

    target_addr = ip if ip else host
    try:
        with socket.create_connection((target_addr, port), timeout=timeout) as sock:
            is_open = True
            reason = "connected"
            if do_banner:
                banner = grab_banner(sock, host, port)
    except socket.timeout:
        reason = "timeout"
    except ConnectionRefusedError:
        reason = "refused"
    except OSError as exc:
        reason = exc.strerror or exc.__class__.__name__

    elapsed_ms = (time.perf_counter() - started) * 1000
    return ScanResult(
        host=host,
        ip=ip or host,
        port=port,
        is_open=is_open,
        elapsed_ms=elapsed_ms,
        reason=reason,
        service=service,
        banner=banner,
    )


def format_row(result: ScanResult, show_banner: bool = False) -> str:
    """Format a single ScanResult for terminal display with ANSI colors."""
    if result.is_open:
        state_color = f"{Colors.GREEN}{'open':<10}{Colors.RESET}"
    else:
        state_color = f"{Colors.RED}{'closed':<10}{Colors.RESET}"

    port_str = f"{Colors.CYAN}{result.port:<8}{Colors.RESET}"
    svc_str = f"{result.service:<14}"
    detail = f"{result.elapsed_ms:.1f} ms"
    if not result.is_open:
        detail += f" ({result.reason})"

    if show_banner:
        banner_display = f"{result.banner:<28}" if result.banner else f"{Colors.DIM}{'-':<28}{Colors.RESET}"
        return f"{port_str}{state_color}{svc_str}{banner_display}{detail}"
    return f"{port_str}{state_color}{svc_str}{detail}"


def export_results(
    results: list[ScanResult],
    output_path: str,
    fmt: str,
    show_banner: bool = False,
) -> None:
    """Export scan results to JSON, CSV, or formatted text."""
    if fmt == "json":
        data = [r.to_dict() for r in results]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    elif fmt == "csv":
        fieldnames = [
            "host",
            "ip",
            "port",
            "state",
            "service",
            "elapsed_ms",
            "reason",
        ]
        if show_banner:
            fieldnames.append("banner")

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                row = r.to_dict()
                filtered = {k: row.get(k, "") for k in fieldnames}
                writer.writerow(filtered)
    else:
        # Text table format
        with open(output_path, "w", encoding="utf-8") as f:
            header = f"{'PORT':<8}{'STATE':<10}{'SERVICE':<14}"
            if show_banner:
                header += f"{'BANNER':<28}"
            header += "DETAIL\n"
            f.write(header)
            f.write("-" * (len(header) + 5) + "\n")
            for r in results:
                state = "open" if r.is_open else "closed"
                detail = f"{r.elapsed_ms:.1f} ms"
                if not r.is_open:
                    detail += f" ({r.reason})"
                line = f"{r.port:<8}{state:<10}{r.service:<14}"
                if show_banner:
                    line += f"{(r.banner or '-'):<28}"
                line += f"{detail}\n"
                f.write(line)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fast, open-source TCP port scanner with banner grabbing and CIDR support.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python portscan.py 127.0.0.1
  python portscan.py 192.168.1.0/24 -p 22,80,443 --banner
  python portscan.py example.com -p 1-1024 -w 100 -o results.json
  python portscan.py -iL targets.txt -p 80,443,8080 --format csv -o out.csv
""",
    )
    parser.add_argument(
        "hosts",
        nargs="*",
        help="target IP(s), hostname(s), CIDR range (e.g. 192.168.1.0/24), or IP range",
    )
    parser.add_argument(
        "-iL",
        "--targets-file",
        help="path to file containing targets (one target per line)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=None,
        help="ports such as 22,80,443 or a range such as 1-1024 (default: common ports)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.75,
        help="connection timeout in seconds (default: 0.75)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=64,
        help="number of parallel checks (default: 64)",
    )
    parser.add_argument(
        "-b",
        "--banner",
        action="store_true",
        help="attempt service banner grabbing on open ports",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="also display closed and timed out ports",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="save results to file (auto-detects .json, .csv, or plain text)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv", "table"],
        default=None,
        help="output format when saving to file (default: inferred from filename)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable colored terminal output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    init_colors(no_color=args.no_color)

    if not args.hosts and not args.targets_file:
        parser.error("no target specified. Provide host(s) or use -iL <file>.")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.workers <= 0:
        parser.error("--workers must be greater than zero")

    try:
        ports = parse_ports(args.ports) if args.ports else list(DEFAULT_PORTS)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        targets = load_targets(args.hosts, args.targets_file)
    except ValueError as exc:
        print(f"{Colors.RED}Target error: {exc}{Colors.RESET}", file=sys.stderr)
        return 2

    if not targets:
        print(f"{Colors.RED}No targets to scan.{Colors.RESET}", file=sys.stderr)
        return 2

    # Determine export format
    fmt = args.format
    if args.output and not fmt:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".json":
            fmt = "json"
        elif ext == ".csv":
            fmt = "csv"
        else:
            fmt = "table"

    all_results: list[ScanResult] = []
    interrupted = False

    total_targets = len(targets)
    print(
        f"{Colors.BOLD}{Colors.CYAN}Simple Port Scanner v1.1.0{Colors.RESET} "
        f"| Targets: {total_targets} | Ports: {len(ports)} | Timeout: {args.timeout:g}s | Workers: {args.workers}"
    )

    for target_idx, host in enumerate(targets, start=1):
        if interrupted:
            break

        addresses = resolve_target(host)
        primary_ip = addresses[0] if addresses else host
        addr_str = f" ({', '.join(addresses)})" if addresses and addresses != [host] else ""

        print(
            f"\n{Colors.BOLD}[*] Target [{target_idx}/{total_targets}]: {host}{addr_str}{Colors.RESET}"
        )

        header = f"{'PORT':<8}{'STATE':<10}{'SERVICE':<14}"
        if args.banner:
            header += f"{'BANNER':<28}"
        header += "DETAIL"
        print(f"{Colors.BOLD}{header}{Colors.RESET}")
        print("-" * (len(header) + 12))

        worker_count = min(args.workers, len(ports))
        target_results: list[ScanResult] = []

        try:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                futures = {
                    executor.submit(
                        scan_port, host, primary_ip, port, args.timeout, args.banner
                    ): port
                    for port in ports
                }
                for future in as_completed(futures):
                    res = future.result()
                    target_results.append(res)
                    if res.is_open or args.show_closed:
                        print(format_row(res, show_banner=args.banner))
        except KeyboardInterrupt:
            print(
                f"\n{Colors.YELLOW}[!] Scan interrupted by user. Stopping gracefully...{Colors.RESET}",
                file=sys.stderr,
            )
            interrupted = True

        target_results.sort(key=lambda r: r.port)
        all_results.extend(target_results)

        open_target_count = sum(r.is_open for r in target_results)
        print(
            f"{Colors.DIM}Target summary: {open_target_count} open / {len(target_results)} scanned{Colors.RESET}"
        )

    # Global summary
    total_open = sum(r.is_open for r in all_results)
    print(
        f"\n{Colors.BOLD}{Colors.GREEN}Scan complete: {total_open} open ports discovered across {len(targets)} target(s).{Colors.RESET}"
    )

    if args.output:
        try:
            export_results(all_results, args.output, fmt=fmt or "table", show_banner=args.banner)
            print(f"{Colors.GREEN}[+] Results successfully saved to {args.output} ({fmt}){Colors.RESET}")
        except OSError as exc:
            print(f"{Colors.RED}Failed to write output file: {exc}{Colors.RESET}", file=sys.stderr)
            return 1

    return 0 if not interrupted else 130


if __name__ == "__main__":
    raise SystemExit(main())
