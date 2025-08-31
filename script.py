from __future__ import annotations
import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Set

#!/usr/bin/env python3
"""
Simple, clean TCP port scanner with worker threads.

Usage:
    python script.py target [--ports 1-1024] [--workers 100] [--timeout 1.0]

Examples:
    python script.py example.com
    python script.py 192.168.1.10 --ports 22,80,443,8000-8100 --workers 200 --timeout 0.5
"""




def parse_ports(ports_arg: str) -> List[int]:
    """
    Parse a ports argument like "22,80,8000-8100" into a sorted list of unique ports.
    """
    ports: Set[int] = set()
    for part in ports_arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            begin_str, end_str = part.split("-", 1)
            begin, end = int(begin_str), int(end_str)
            if begin > end:
                begin, end = end, begin
            for p in range(max(1, begin), min(65535, end) + 1):
                ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def resolve_host(target: str) -> str:
    """
    Resolve a hostname to an IP address. If target is already an IP, return it.
    Raises socket.gaierror on failure.
    """
    return socket.gethostbyname(target)


def scan_port(ip: str, port: int, timeout: float) -> bool:
    """
    Attempt to connect to (ip, port) using TCP. Returns True if connection succeeded.
    Uses a short timeout.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            # connect_ex returns 0 on success
            return s.connect_ex((ip, port)) == 0
        except OSError:
            return False


def service_name_for_port(port: int) -> str:
    """
    Attempt to get the canonical service name for a TCP port. Fall back to '-' if unknown.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "-"


def print_summary(target: str, ip: str, open_ports: List[int], elapsed: float) -> None:
    """
    Print a concise human-friendly summary of results.
    """
    print()
    print("=" * 60)
    print(f"Scan target : {target} ({ip})")
    print(f"Open ports   : {len(open_ports)}")
    if open_ports:
        print("Ports        :")
        for p in open_ports:
            service = service_name_for_port(p)
            print(f"  - {p:5d}    {service}")
    print(f"Elapsed time : {elapsed:.2f} seconds")
    print("=" * 60)


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description="TCP port scanner with worker threads")
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument(
        "--ports",
        "-p",
        default="1-1024",
        help="Comma-separated list and ranges of ports, e.g. '22,80,8000-8100' (default: 1-1024)",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=100,
        help="Number of worker threads (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    args = parser.parse_args(list(argv))

    try:
        ports = parse_ports(args.ports)
    except Exception as e:
        print(f"Invalid ports specification: {e}", file=sys.stderr)
        return 2

    if not ports:
        print("No valid ports to scan.", file=sys.stderr)
        return 2

    try:
        ip = resolve_host(args.target)
    except socket.gaierror as e:
        print(f"Failed to resolve target '{args.target}': {e}", file=sys.stderr)
        return 3

    total = len(ports)
    print(f"Scanning {args.target} ({ip}) {total} ports with {args.workers} workers, timeout={args.timeout}s")
    start = time.time()

    open_ports: List[int] = []
    scanned = 0

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_port = {executor.submit(scan_port, ip, port, args.timeout): port for port in ports}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                scanned += 1
                try:
                    is_open = future.result()
                except Exception:
                    is_open = False
                if is_open:
                    open_ports.append(port)
                    # Print immediate feedback for discovered open ports
                    service = service_name_for_port(port)
                    print(f"[OPEN] {port:5d}   {service}")
                # Print progress on the same line (overwrites previous)
                print(f"Scanned: {scanned}/{total} ports", end="\r", flush=True)

    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        return 130

    elapsed = time.time() - start
    open_ports.sort()
    print_summary(args.target, ip, open_ports, elapsed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))