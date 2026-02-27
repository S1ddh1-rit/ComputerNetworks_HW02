#!/usr/bin/env python3
"""Minimal starter for a raw-socket ICMP ping tool."""

import argparse
import os
import socket
import struct
import time

ICMP_ECHO_REQUEST = 8
ICMP_CODE = 0


def checksum(data: bytes) -> int:
    """Compute Internet checksum for ICMP header+payload."""
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]

    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def build_icmp_packet(identifier: int, sequence: int, payload_size: int) -> bytes:
    """Build one ICMP echo request packet."""
    payload = b"A" * max(0, payload_size)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_CODE, 0, identifier, sequence)
    csum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, ICMP_CODE, csum, identifier, sequence)
    return header + payload


def send_ping(sock: socket.socket, target: str, identifier: int, sequence: int, size: int) -> float:
    packet = build_icmp_packet(identifier, sequence, size)
    start = time.time()
    sock.sendto(packet, (target, 0))
    return start


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Starter ICMP ping implementation")
    parser.add_argument("destination", help="Destination hostname or IPv4 address")
    parser.add_argument("-c", type=int, default=4, help="Number of packets to send")
    parser.add_argument("-i", type=float, default=1.0, help="Interval between packets (seconds)")
    parser.add_argument("-s", type=int, default=56, help="Payload size in bytes")
    parser.add_argument("-t", type=float, default=None, help="Overall timeout in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target_ip = socket.gethostbyname(args.destination)

    print(f"PING {args.destination} ({target_ip}) {args.s} data bytes")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Permission denied: run with sudo/admin privileges for raw sockets.")
        return 1

    sock.settimeout(1.0)
    pid = os.getpid() & 0xFFFF

    start_time = time.time()
    for seq in range(1, args.c + 1):
        if args.t is not None and (time.time() - start_time) >= args.t:
            print("Overall timeout reached. Exiting.")
            break

        sent_at = send_ping(sock, target_ip, pid, seq, args.s)
        print(f"sent icmp_seq={seq} at {sent_at:.6f}")

        # Starter behavior: receive path/RTT parsing comes next.
        try:
            _data, addr = sock.recvfrom(65535)
            elapsed_ms = (time.time() - sent_at) * 1000
            print(f"received packet from {addr[0]} in {elapsed_ms:.2f} ms")
        except socket.timeout:
            print(f"request timeout for icmp_seq {seq}")

        if seq < args.c:
            time.sleep(max(0.0, args.i))

    sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())