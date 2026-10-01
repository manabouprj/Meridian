"""Syslog receiver (UDP, TCP and TLS; RFC 3164 / 5424; newline or octet-counted framing) -> landing batches.

Firewalls, proxies, VPN concentrators, Linux hosts (rsyslog / syslog-ng), NXLog CE (om_ssl / om_tcp) and many
appliances only speak syslog. The receiver buffers lines and flushes a gzip batch to the landing zone every
`flush_seconds` or `max_lines`, whichever comes first. Parsing happens later, in the worker (format: syslog | cef |
leef | windows), so the receiver never drops a line it cannot understand.

TLS (RFC 5425, normally port 6514): pass --tls-port with a certificate and key, as file paths or as PEM in
MERIDIAN_SYSLOG_TLS_CERT / MERIDIAN_SYSLOG_TLS_KEY (loaded through an anonymous in-memory file, never written to
disk). --tls-client-ca turns on mutual TLS: only senders with a certificate from that CA can connect. TLS 1.2+.
Alternatively terminate TLS on a load balancer (AWS NLB TLS listener) in front of the plain TCP port.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import ssl
import threading
import time

from ..lake.storage import ObjectStore
from .landing import write_batch

log = logging.getLogger("meridian.syslog")


class Buffer:
    """Lines waiting to be written. A failed write puts the lines back (bounded by max_buffered, oldest dropped
    first and counted), so a storage outage delays data instead of silently losing it."""

    def __init__(self, landing: ObjectStore, source_key: str, flush_seconds: float = 30, max_lines: int = 20000,
                 max_buffered: int = 500_000):
        self.landing, self.source_key = landing, source_key
        self.flush_seconds, self.max_lines, self.max_buffered = flush_seconds, max_lines, max_buffered
        self.lines: list[str] = []
        self.last = time.monotonic()
        self.flushed = 0
        self.dropped = 0
        self._lock = threading.Lock()

    def add(self, line: str) -> None:
        line = line.strip("\x00\r\n ")
        if not line:
            return
        with self._lock:
            self.lines.append(line[:65536])
            if len(self.lines) > self.max_buffered:          # only reachable while storage is failing
                drop = len(self.lines) - self.max_buffered
                del self.lines[:drop]
                self.dropped += drop

    def due(self) -> bool:
        return len(self.lines) >= self.max_lines or (self.lines and time.monotonic() - self.last >= self.flush_seconds)

    def flush(self) -> str | None:
        with self._lock:
            self.last = time.monotonic()
            if not self.lines:
                return None
            lines, self.lines = self.lines, []
        try:
            key = write_batch(self.landing, self.source_key, lines)
        except Exception:
            with self._lock:                                 # put them back in front of anything newer
                self.lines = lines + self.lines
            raise
        self.flushed += len(lines)
        return key


class _UDP(asyncio.DatagramProtocol):
    def __init__(self, buf: Buffer):
        self.buf = buf

    def datagram_received(self, data, addr):
        for line in data.decode("utf-8", "replace").splitlines():
            self.buf.add(line)


async def _tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, buf: Buffer):
    try:
        while not reader.at_eof():
            head = await reader.read(1)
            if not head:
                break
            if head.isdigit():                         # octet counting: "<len> <msg>"
                num = head + await reader.readuntil(b" ")
                msg = await reader.readexactly(int(num.strip()))
                buf.add(msg.decode("utf-8", "replace"))
            else:
                rest = await reader.readline()
                buf.add((head + rest).decode("utf-8", "replace"))
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
        pass
    finally:
        writer.close()


def _pem_path(value: str | None, env: str) -> tuple[str | None, int | None]:
    """A file path, or PEM text from the environment written to an anonymous memory file (Linux memfd)."""
    if value:
        return value, None
    pem = os.environ.get(env, "")
    if "-----BEGIN" not in pem:
        return None, None
    if hasattr(os, "memfd_create"):
        fd = os.memfd_create(env.lower(), 0)
        os.write(fd, pem.encode())
        return f"/proc/self/fd/{fd}", fd
    import tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)       # pragma: no cover - non-Linux dev hosts
    f.write(pem)
    f.close()
    os.chmod(f.name, 0o600)
    return f.name, None


def tls_context(cert: str | None = None, key: str | None = None, client_ca: str | None = None) -> ssl.SSLContext:
    cert_path, cfd = _pem_path(cert, "MERIDIAN_SYSLOG_TLS_CERT")
    key_path, kfd = _pem_path(key, "MERIDIAN_SYSLOG_TLS_KEY")
    if not cert_path or not key_path:
        raise ValueError("TLS syslog needs a certificate and key (--tls-cert/--tls-key or MERIDIAN_SYSLOG_TLS_CERT/_KEY PEM)")
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.load_cert_chain(cert_path, key_path)
    finally:
        for fd in (cfd, kfd):
            if fd is not None:
                os.close(fd)
    if client_ca:
        ctx.load_verify_locations(client_ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


async def serve(landing: ObjectStore, source_key: str, host: str = "0.0.0.0", udp_port: int = 5514,
                tcp_port: int = 5514, flush_seconds: float = 30, tls_port: int = 0,
                tls: ssl.SSLContext | None = None) -> None:
    """Plain UDP+TCP on udp_port/tcp_port (0 = off) and TLS on tls_port (0 = off)."""
    buf = Buffer(landing, source_key, flush_seconds)
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):              # ECS / Container Apps send SIGTERM before stopping
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):          # pragma: no cover - Windows / non-main thread
            pass
    transport = None
    servers = []
    if udp_port:
        transport, _ = await loop.create_datagram_endpoint(lambda: _UDP(buf), local_addr=(host, udp_port))
    if tcp_port:
        servers.append(await asyncio.start_server(lambda r, w: _tcp_handler(r, w, buf), host, tcp_port, limit=1 << 20))
    if tls_port:
        if tls is None:
            raise ValueError("tls_port set without a TLS context")
        servers.append(await asyncio.start_server(lambda r, w: _tcp_handler(r, w, buf), host, tls_port, limit=1 << 20,
                                                  ssl=tls))
    if not servers and transport is None:
        raise ValueError("no listener: set --port and/or --tls-port")
    log.warning("syslog receiver for source '%s' on %s (udp/tcp %s, tls %s)", source_key, host, udp_port or "off",
                tls_port or "off")
    try:
        async with contextlib.AsyncExitStack() as stack:
            for srv in servers:
                await stack.enter_async_context(srv)
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=1)
                except TimeoutError:
                    pass
                if buf.due():
                    try:
                        await loop.run_in_executor(None, buf.flush)
                    except Exception as exc:          # lines are kept and retried on the next cycle
                        log.error("syslog flush failed (%d lines kept): %s", len(buf.lines), exc)
    finally:
        if transport is not None:
            transport.close()
        try:
            buf.flush()                               # final flush on shutdown
        except Exception as exc:
            log.error("final syslog flush failed, %d lines lost: %s", len(buf.lines), exc)
