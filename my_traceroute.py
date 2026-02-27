"""
my_traceroute.py - Custom traceroute implementation using raw sockets.

Sends UDP packets with incrementing TTL values and listens for ICMP
time-exceeded and port-unreachable messages to discover the route.

Usage:
    sudo python my_traceroute.py [-n] [-q nqueries] [-S] <destination>

Requires root/administrator privileges to use raw sockets.
"""

import argparse
import socket
# import struct
import time
import select
import sys

MAX_HOPS = 30          # Maximum hops
DEST_PORT = 33434      
TIMEOUT = 3.0          # Timwout 
DEFAULT_PROBES = 3


def checksum(data: bytes) -> int:
    """Compute the Internet checksum (RFC 1071) over *data*.
       Addition, if carry then wrap around then do 1's complement

    Args:
        data: Raw bytes to checksum.

    Returns:
        16-bit checksum as an integer.
    """
    if len(data) % 2 != 0:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    # Fold 32-bit sum into 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF


def create_send_socket(ttl: int) -> socket.socket:
    """Create a UDP socket with the given TTL.

    Args:
        ttl: Time-to-live value for outgoing packets.

    Returns:
        Configured UDP socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    return sock


def create_recv_socket(timeout: float) -> socket.socket:
    """Create a raw ICMP socket for receiving error messages.

    Args:
        timeout: Socket receive timeout in seconds.

    Returns:
        Configured raw ICMP socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(timeout)
    return sock

def resolve_hostname(addr: str) -> str:
    """Attempt a reverse DNS lookup for *addr*.

    Args:
        addr: IP address string to look up.

    Returns:
        Hostname string, or the original *addr* if lookup fails.
    """
    try:
        return socket.gethostbyaddr(addr)[0]
    except socket.herror:
        return addr

def send_probe(
    recv_sock: socket.socket,
    dest_addr: str,
    ttl: int,
    port: int,
) -> tuple[str | None, float | None]:
    """Send a single UDP probe and wait for an ICMP response.

    Args:
        recv_sock: Raw ICMP socket to receive the reply on.
        dest_addr: Destination IP address string.
        ttl:       TTL value for this probe.
        port:      UDP destination port for this probe.

    Returns:
        A tuple ``(addr, rtt_ms)`` where *addr* is the responding router's
        IP address and *rtt_ms* is the round-trip time in milliseconds.
        Returns ``(None, None)`` if no reply is received within the timeout.
    """
    send_sock = create_send_socket(ttl)

    send_time = time.time()
    try:
        send_sock.sendto(b'', (dest_addr, port))
    finally:
        send_sock.close()

    ready = select.select([recv_sock], [], [], TIMEOUT)
    if not ready[0]:
        return None, None  # Timeout

    recv_time = time.time()
    try:
        packet, addr = recv_sock.recvfrom(512)
    except socket.error:
        return None, None

    rtt_ms = (recv_time - send_time) * 1000.0
    return addr[0], rtt_ms

def traceroute(
    destination: str,
    numeric: bool = False,
    nqueries: int = DEFAULT_PROBES,
    summary: bool = False,
) -> None:
    """Run traceroute to *destination* and print results.

    Args:
        destination: Hostname or IP address to trace the route to.
        numeric:     If ``True``, suppress reverse DNS lookups and print
                     addresses numerically only (``-n`` flag).
        nqueries:    Number of UDP probes to send per TTL hop (``-q`` flag).
        summary:     If ``True``, print a per-hop summary of unanswered
                     probes (``-S`` flag).
    """
    # Resolve destination to an IP address
    try:
        dest_addr = socket.gethostbyname(destination)
    except socket.gaierror as exc:
        print(f"my_traceroute: cannot resolve {destination}: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"traceroute to {destination} ({dest_addr}), {MAX_HOPS} hops max")

    try:
        recv_sock = create_recv_socket(TIMEOUT)
    except PermissionError:
        print(
            "my_traceroute: raw socket requires root privileges. "
            "Try running with sudo.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        for ttl in range(1, MAX_HOPS + 1):
            hop_results: list[tuple[str | None, float | None]] = []
            port = DEST_PORT + ttl  # Use a distinct port per TTL (optional)

            for _ in range(nqueries):
                addr, rtt = send_probe(recv_sock, dest_addr, ttl, port)
                hop_results.append((addr, rtt))

            _print_hop(ttl, hop_results, numeric, summary)

            responding_addrs = [a for a, _ in hop_results if a is not None]
            if responding_addrs and dest_addr in responding_addrs:
                break

    finally:
        recv_sock.close()

def _print_hop(
    ttl: int,
    results: list[tuple[str | None, float | None]],
    numeric: bool,
    summary: bool,
) -> None:
    """Format and print a single hop line.

    Args:
        ttl:     The current TTL / hop number.
        results: List of ``(addr, rtt_ms)`` tuples for each probe at this hop.
        numeric: Suppress reverse DNS lookups when ``True``.
        summary: Append unanswered-probe count when ``True``.
    """
    unanswered = sum(1 for addr, _ in results if addr is None)
    answered = [(addr, rtt) for addr, rtt in results if addr is not None]

    line = f"{ttl:2d}  "

    if not answered:
        # All probes unanswered
        line += "  ".join(["*"] * len(results))
    else:
        # Show the first responding router address
        first_addr = answered[0][0]
        if numeric:
            host_str = first_addr
        else:
            hostname = resolve_hostname(first_addr)
            host_str = (
                f"{hostname} ({first_addr})"
                if hostname != first_addr
                else first_addr
            )

        line += host_str + "  "

        # RTT values 
        rtt_parts: list[str] = []
        for addr, rtt in results:
            if rtt is None:
                rtt_parts.append("*")
            else:
                rtt_parts.append(f"{rtt:.3f} ms")
        line += "  ".join(rtt_parts)

    if summary and unanswered > 0:
        line += f"  ({unanswered}/{len(results)} probes unanswered)"

    print(line)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        prog="my_traceroute",
        description="Traceroute: discover the route to a network host.",
    )
    parser.add_argument(
        "destination",
        help="Hostname or IP address of the target host.",
    )
    parser.add_argument(
        "-n",
        dest="numeric",
        action="store_true",
        default=False,
        help=(
            "Print hop addresses numerically rather than symbolically "
            "and numerically."
        ),
    )
    parser.add_argument(
        "-q",
        dest="nqueries",
        type=int,
        default=DEFAULT_PROBES,
        metavar="nqueries",
        help="Set the number of probes per TTL (default: %(default)s).",
    )
    parser.add_argument(
        "-S",
        dest="summary",
        action="store_true",
        default=False,
        help="Print a summary of unanswered probes per hop.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for my_traceroute."""
    args = parse_args()
    traceroute(
        destination=args.destination,
        numeric=args.numeric,
        nqueries=args.nqueries,
        summary=args.summary,
    )


if __name__ == "__main__":
    main()