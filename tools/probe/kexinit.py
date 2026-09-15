#!/usr/bin/env python3
"""Print an SSH server's algorithm offer, without authenticating.

Read-only and strictly pre-auth: the script exchanges version strings, reads the
server's SSH_MSG_KEXINIT (RFC 4253, section 12) and exits. Credentials are never
sent, so a server that bans hosts after failed logins (wSSH ships with
AutoDenyHost=1) never registers an authentication attempt. This is the safe way
to fingerprint an SSH server you must not disturb.

Usage:
    kexinit.py [host] [port] [--json]

Defaults to 127.0.0.1:22. Exit status 0 on success, 1 on failure.
"""

import json
import socket
import sys

LISTS = [
    "kex_algorithms",
    "host_key_algorithms",
    "encryption_c2s",
    "encryption_s2c",
    "mac_c2s",
    "mac_s2c",
    "compression_c2s",
    "compression_s2c",
    "languages_c2s",
    "languages_s2c",
]

# The server must send its KEXINIT unprompted; sending our own version string is
# enough to make it proceed. We deliberately do not build a client KEXINIT.
CLIENT_ID = b"SSH-2.0-rossh-probe\r\n"

MAX_BANNER = 255
MAX_PACKET = 35000


def recv_exactly(sock, count):
    """Read exactly `count` bytes or raise."""
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise EOFError("closed after %d of %d bytes" % (len(buf), count))
        buf += chunk
    return buf


def read_banner(sock):
    """Read one line, one byte at a time.

    Byte-wise on purpose: a buffered reader would swallow the first bytes of the
    binary KEXINIT packet that follows the banner.
    """
    line = b""
    while not line.endswith(b"\n"):
        line += recv_exactly(sock, 1)
        if len(line) > MAX_BANNER:
            raise ValueError("no line ending within %d bytes" % MAX_BANNER)
    return line.decode("utf-8", "replace").strip()


def read_payload(sock):
    """Read one binary packet and return its payload with padding stripped."""
    length = int.from_bytes(recv_exactly(sock, 4), "big")
    if length < 8 or length > MAX_PACKET:
        raise ValueError("implausible packet length %d" % length)
    body = recv_exactly(sock, length)
    padding = body[0]
    if padding + 1 > length:
        raise ValueError("padding %d exceeds packet length %d" % (padding, length))
    return body[1:length - padding]


def parse_kexinit(payload):
    """Split an SSH_MSG_KEXINIT payload into its name-lists."""
    if not payload:
        raise ValueError("empty packet")
    if payload[0] != 20:
        raise ValueError("expected SSH_MSG_KEXINIT (20), got %d" % payload[0])
    offer = {}
    pos = 17  # 1 byte message type + 16 byte cookie
    for name in LISTS:
        size = int.from_bytes(payload[pos:pos + 4], "big")
        pos += 4
        offer[name] = payload[pos:pos + size].decode("utf-8", "replace")
        pos += size
    offer["first_kex_packet_follows"] = bool(payload[pos])
    return offer


def probe(host, port, timeout=10.0):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        banner = read_banner(sock)
        sock.sendall(CLIENT_ID)
        offer = parse_kexinit(read_payload(sock))
    return banner, offer


def main(argv):
    as_json = "--json" in argv
    positional = [a for a in argv[1:] if not a.startswith("-")]
    host = positional[0] if positional else "127.0.0.1"
    try:
        port = int(positional[1]) if len(positional) > 1 else 22
    except ValueError:
        print("port must be a number", file=sys.stderr)
        return 1

    try:
        banner, offer = probe(host, port)
    except (OSError, EOFError, ValueError) as err:
        print("%s:%d: %s" % (host, port, err), file=sys.stderr)
        return 1

    if as_json:
        json.dump({"host": host, "port": port, "banner": banner,
                   "kexinit": offer}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    print("%-19s: %s" % ("banner", banner))
    for name in LISTS:
        print("%-19s: %s" % (name, offer[name] or "(empty)"))
    print("%-19s: %s" % ("first_kex_follows", offer["first_kex_packet_follows"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
