#!/usr/bin/env python3
"""Small cross-platform TCP port scanner.

This program intentionally uses only Python's standard library so it can run
on Linux, Windows CMD, and Windows PowerShell without installing packages.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


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


@dataclass(frozen=True)
class ScanResult:
    """Result for one TCP port."""

    port: int
    is_open: bool
    elapsed_ms: float
    reason: str


def parse_ports(value: str) -> list[int]:
    """Parse values such as ``80,443,8000-8010`` into sorted port numbers."""

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


def service_name(port: int) -> str:
    """Return the local TCP service name when one is known."""

    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(host: str, port: int, timeout: float) -> ScanResult:
    """Try to establish one TCP connection."""

    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            reason = "connected"
            is_open = True
    except socket.timeout:
        reason = "timeout"
        is_open = False
    except ConnectionRefusedError:
        reason = "refused"
        is_open = False
    except OSError as exc:
        # Keep the normal output compact while retaining a useful reason for
        # --show-closed output.
        reason = exc.strerror or exc.__class__.__name__
        is_open = False

    elapsed_ms = (time.perf_counter() - started) * 1000
    return ScanResult(port, is_open, elapsed_ms, reason)


def resolve_target(host: str) -> list[str]:
    """Resolve a target and return unique addresses for display."""

    addresses = {
        result[4][0]
        for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    }
    return sorted(addresses)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan TCP ports on a host you are authorized to test."
    )
    parser.add_argument("host", help="hostname or IP address to scan")
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
        "--show-closed",
        action="store_true",
        help="also print ports that did not accept a connection",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.workers <= 0:
        parser.error("--workers must be greater than zero")

    try:
        ports = parse_ports(args.ports) if args.ports else list(DEFAULT_PORTS)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        addresses = resolve_target(args.host)
    except socket.gaierror as exc:
        print(f"Could not resolve {args.host!r}: {exc}", file=sys.stderr)
        return 2

    address_text = ", ".join(addresses)
    print(f"Scanning {args.host} ({address_text})")
    print(f"TCP ports: {len(ports)} | timeout: {args.timeout:g}s")

    results: list[ScanResult] = []
    worker_count = min(args.workers, len(ports))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(scan_port, args.host, port, args.timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda result: result.port)
    displayed = [result for result in results if result.is_open or args.show_closed]

    if displayed:
        print()
        print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<16}{'DETAIL'}")
        print("-" * 58)
        for result in displayed:
            state = "open" if result.is_open else "closed"
            detail = f"{result.elapsed_ms:.1f} ms"
            if not result.is_open:
                detail += f" ({result.reason})"
            print(
                f"{result.port:<8}{state:<10}{service_name(result.port):<16}{detail}"
            )
    else:
        print("\nNo open TCP ports found.")

    open_count = sum(result.is_open for result in results)
    print(f"\nFinished: {open_count} open / {len(results)} checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
