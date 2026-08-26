#!/usr/bin/env python3
"""Probe a Nostr relay onion service through a Tor SOCKS5 proxy.

Answers the question the WASM client cannot answer yet: does this .onion
relay accept a WebSocket connection and serve a REQ over it? It speaks SOCKS5,
the WebSocket handshake and enough of RFC 6455 framing by hand, so it needs
nothing but the standard library and a running Tor.

    ./scripts/onion_ws_probe.py ws://<addr>.onion
    ./scripts/onion_ws_probe.py --proxy '[fdb8:...:102]:32050' ws://<addr>.onion

A ws:// URL carries no TLS: the onion protocol authenticates the service
against its own address and encrypts the circuit end to end, which is the
property that makes onion relays worth having.
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Tor answers a CONNECT it could not complete with one of these. The generic
# 0x04 covers "descriptor not found", "introduction failed" and "rendezvous
# failed" alike unless the SocksPort carries ExtendedErrors.
SOCKS_REPLY = {
    1: "general failure",
    2: "connection not allowed",
    3: "network unreachable",
    4: "host unreachable (onion service down, or its descriptor is missing)",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


class ProbeError(Exception):
    pass


def split_hostport(value, default_port):
    """Split host:port, tolerating a bracketed IPv6 literal."""
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        return host, int(rest.lstrip(":")) if rest.lstrip(":") else default_port
    host, _, port = value.rpartition(":")
    if not host:
        return value, default_port
    return host, int(port)


def socks5_connect(proxy, host, port, timeout):
    """Open a TCP stream to host:port through a SOCKS5 proxy.

    The hostname goes to the proxy unresolved (SOCKS5 ATYP=3, curl's
    socks5h): a .onion has no address to resolve, and Tor is the only party
    that can make sense of it.
    """
    proxy_host, proxy_port = proxy
    infos = socket.getaddrinfo(proxy_host, proxy_port, 0, socket.SOCK_STREAM)
    family, socktype, proto, _, sockaddr = infos[0]
    s = socket.socket(family, socktype, proto)
    s.settimeout(timeout)
    try:
        s.connect(sockaddr)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise ProbeError("proxy refused the no-auth method; is it SOCKS5?")
        name = host.encode()
        if len(name) > 255:
            raise ProbeError("hostname too long for SOCKS5")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", port))
        reply = recv_exact(s, 4)
        if reply[1] != 0:
            raise ProbeError(
                "SOCKS5 CONNECT failed: %s (0x%02x)"
                % (SOCKS_REPLY.get(reply[1], "unknown"), reply[1])
            )
        atyp = reply[3]
        if atyp == 1:
            recv_exact(s, 4)
        elif atyp == 4:
            recv_exact(s, 16)
        elif atyp == 3:
            recv_exact(s, recv_exact(s, 1)[0])
        recv_exact(s, 2)
        return s
    except Exception:
        s.close()
        raise


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProbeError("peer closed the connection")
        buf += chunk
    return buf


def ws_handshake(sock, host, port, path, scheme):
    key = base64.b64encode(os.urandom(16)).decode()
    default_port = 443 if scheme == "wss" else 80
    host_header = host if port == default_port else "%s:%d" % (host, port)
    sock.sendall(
        (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n" % (path, host_header, key)
        ).encode()
    )
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ProbeError("closed during the handshake; got %r" % buf[:200])
        buf += chunk
        if len(buf) > 65536:
            raise ProbeError("handshake response too large")
    head, leftover = buf.split(b"\r\n\r\n", 1)
    lines = head.decode("latin1").split("\r\n")
    status = lines[0]
    if " 101" not in status:
        raise ProbeError("no upgrade: %s" % status)
    expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "sec-websocket-accept" and value.strip() == expected:
            return status, leftover
    raise ProbeError("Sec-WebSocket-Accept missing or wrong: %s" % status)


def send_text(sock, text):
    payload = text.encode()
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        header = bytes([0x81, 0x80 | n])
    elif n < 65536:
        header = bytes([0x81, 0x80 | 126]) + struct.pack(">H", n)
    else:
        header = bytes([0x81, 0x80 | 127]) + struct.pack(">Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(header + mask + masked)


class FrameReader:
    """Just enough RFC 6455 to read what a relay sends back."""

    def __init__(self, sock, buffered=b""):
        self.sock = sock
        self.buf = buffered

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ProbeError("closed by peer")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def frame(self):
        b0, b1 = self._need(2)
        opcode = b0 & 0x0F
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._need(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._need(8))[0]
        mask = self._need(4) if b1 & 0x80 else None
        payload = self._need(length)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload


def probe(url, proxy, timeout, limit):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("ws", "wss"):
        raise ProbeError("expected a ws:// or wss:// URL, got %r" % url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    started = time.monotonic()
    sock = socks5_connect(proxy, host, port, timeout)
    print("  SOCKS5 CONNECT ok                       %5.2fs" % (time.monotonic() - started))
    try:
        if parsed.scheme == "wss":
            # An onion address already authenticates the service, and these
            # certificates are routinely self-signed, so the name is not checked.
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=host)
            print("  TLS established (cert not checked)      %5.2fs"
                  % (time.monotonic() - started))
        status, leftover = ws_handshake(sock, host, port, path, parsed.scheme)
        print("  %-38s  %5.2fs" % (status, time.monotonic() - started))

        reader = FrameReader(sock, leftover)
        send_text(sock, json.dumps(["REQ", "probe", {"kinds": [1], "limit": limit}]))
        print("  sent REQ kinds=[1] limit=%d" % limit)

        events = 0
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            opcode, payload = reader.frame()
            if opcode == 0x9:  # ping
                continue
            if opcode == 0x8:
                raise ProbeError("relay closed the connection after %d events" % events)
            try:
                message = json.loads(payload)
            except ValueError:
                print("  non-JSON frame %r" % payload[:100])
                continue
            kind = message[0]
            if kind == "EVENT":
                events += 1
                event = message[2]
                print("  EVENT  id=%s… kind=%s" % (event["id"][:16], event["kind"]))
            elif kind == "EOSE":
                print("  EOSE   after %d events                  %5.2fs"
                      % (events, time.monotonic() - started))
                return events
            else:
                print("  %s %s" % (kind, json.dumps(message[1:])[:120]))
                if kind in ("CLOSED", "NOTICE", "AUTH"):
                    raise ProbeError("relay answered %s instead of serving the REQ" % kind)
        raise ProbeError("no EOSE within %gs (%d events)" % (timeout, events))
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("url", help="ws:// or wss:// URL of the relay onion service")
    parser.add_argument(
        "--proxy",
        default=os.environ.get("TOR_SOCKS_PROXY", "127.0.0.1:9050"),
        help="Tor SOCKS5 proxy as host:port; bracket an IPv6 literal "
        "(default: $TOR_SOCKS_PROXY or 127.0.0.1:9050)",
    )
    parser.add_argument("--timeout", type=float, default=90.0, help="seconds per step")
    parser.add_argument("--limit", type=int, default=2, help="events to ask the relay for")
    args = parser.parse_args()

    proxy = split_hostport(args.proxy, 9050)
    shown = "[%s]" % proxy[0] if ":" in proxy[0] else proxy[0]
    print("%s via %s:%d" % (args.url, shown, proxy[1]))
    try:
        probe(args.url, proxy, args.timeout, args.limit)
    except (ProbeError, OSError, ssl.SSLError) as error:
        print("  FAILED: %s" % error)
        return 1
    print("  OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
