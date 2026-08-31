"""Data-plane: 4-byte framing, network-config parsing, heartbeat and the
TUN <-> TLS pump (PROTOCOL.md §6).

Frame layout (both directions), big-endian length:

    offset size field
      0     1   type     (1=data, 2=heartbeat, 3=netconfig, 4=force-logoff)
      1     1   subtype
      2     2   length   (uint16 BE) = payload byte count
      4   len   payload
"""
from __future__ import annotations

import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import constants as C


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------
def encode_frame(ftype: int, subtype: int, payload: bytes = b"") -> bytes:
    if len(payload) > 0xFFFF:
        raise ValueError("frame payload exceeds 65535 bytes")
    return struct.pack(">BBH", ftype, subtype, len(payload)) + payload


class FrameDecoder:
    """Reassembles frames from a byte stream that may split/coalesce them."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[tuple[int, int, bytes]]:
        self._buf += data
        out: list[tuple[int, int, bytes]] = []
        while len(self._buf) >= C.FRAME_HEADER_LEN:
            ftype, subtype, length = struct.unpack_from(">BBH", self._buf, 0)
            if len(self._buf) < C.FRAME_HEADER_LEN + length:
                break  # wait for the rest of the payload
            start = C.FRAME_HEADER_LEN
            payload = bytes(self._buf[start:start + length])
            del self._buf[:start + length]
            out.append((ftype, subtype, payload))
        return out


# --------------------------------------------------------------------------
# network-config param block (PROTOCOL.md §6.5)
# --------------------------------------------------------------------------
@dataclass
class NetworkConfig:
    ipaddress: str = ""
    subnetmask: str = ""
    gateway: str = ""
    prefixlength: str = ""
    dns: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    exclude_routes: list[str] = field(default_factory=list)
    restrict: str = ""
    keepalive_time: int = 0
    default_gateway: bool = False
    ipv6address: str = ""
    ipv6gateway: str = ""
    ipv6dns: list[str] = field(default_factory=list)
    ipv6routes: list[str] = field(default_factory=list)
    raw: str = ""

    @property
    def is_valid(self) -> bool:
        # Missing IP or GATEWAY -> error (getVpnParamFromResp).
        return bool(self.ipaddress) and bool(self.gateway or self.default_gateway)


def parse_netconfig(data: bytes) -> NetworkConfig:
    """Parse the plaintext ``KEY:value`` block (newline-separated)."""
    text = data.decode("utf-8", "replace")
    cfg = NetworkConfig(raw=text)

    def _split(v: str) -> list[str]:
        return [p for p in (x.strip() for x in v.replace(";", ",").split(",")) if p]

    for line in text.replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().upper()
        val = val.strip()
        if key == "IPADDRESS":
            cfg.ipaddress = val
        elif key == "SUBNETMASK":
            cfg.subnetmask = val
        elif key == "GATEWAY":
            cfg.gateway = val
        elif key == "PREFIXLENGTH":
            cfg.prefixlength = val
        elif key == "DNS":
            cfg.dns = _split(val)
        elif key == "ROUTES":
            cfg.routes = _split(val)
        elif key == "EXCLUDE ROUTES":
            cfg.exclude_routes = _split(val)
        elif key == "RESTRICT":
            cfg.restrict = val
        elif key == "KEEPALIVETIME":
            try:
                cfg.keepalive_time = int(val)
            except ValueError:
                pass
        elif key == "IPV6ADDRESS":
            cfg.ipv6address = val
        elif key == "IPV6GATEWAY":
            cfg.ipv6gateway = val
        elif key == "IPV6DNS":
            cfg.ipv6dns = _split(val)
        elif key == "IPV6ROUTES":
            cfg.ipv6routes = _split(val)
    # A "0.0.0.0/0" route or empty routes means redirect-all (full tunnel).
    if any(r.startswith("0.0.0.0") for r in cfg.routes) or not cfg.routes:
        cfg.default_gateway = True
    return cfg


# --------------------------------------------------------------------------
# tunnel runtime
# --------------------------------------------------------------------------
class TunnelClosed(Exception):
    pass


class Tunnel:
    """Pumps packets between a TUN fd and the TLS tunnel socket, runs the 1 s
    heartbeat, and dispatches control frames.  ``tun_fd`` may be ``None`` for
    headless testing (data frames are then delivered to ``on_data``)."""

    def __init__(self, sock: socket.socket, tun_fd: Optional[int],
                 *, initial_buffer: bytes = b"",
                 keepalive_interval: float = C.DEFAULT_KEEPALIVE_INTERVAL,
                 keepalive_max_miss: int = C.DEFAULT_KEEPALIVE_MAX_MISS,
                 on_netconfig: Optional[Callable[[NetworkConfig], None]] = None,
                 on_data: Optional[Callable[[bytes], None]] = None,
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.sock = sock
        self.tun_fd = tun_fd
        self.dec = FrameDecoder()
        # The binary loops every 1 s but only SENDS a heartbeat every
        # KEEPALIVETIME seconds (struct+0x40); model that as a send interval.
        self.keepalive_interval = max(1.0, float(keepalive_interval or
                                                 C.DEFAULT_KEEPALIVE_INTERVAL))
        self.keepalive_max_miss = keepalive_max_miss
        self.on_netconfig = on_netconfig
        self.on_data = on_data
        self._log = log or (lambda m: None)
        self._stop = threading.Event()
        self._miss = 0
        self._miss_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._hb_thread: Optional[threading.Thread] = None
        self.bytes_in = 0
        self.bytes_out = 0
        # Frames already decoded from the post-NET_EXTEND bytes, held (not
        # dispatched) until run() so early data frames are never dropped.
        self._early: list[tuple[int, int, bytes]] = (
            self.dec.feed(initial_buffer) if initial_buffer else [])

    # -- sending -----------------------------------------------------------
    def send_frame(self, ftype: int, subtype: int, payload: bytes = b"") -> None:
        with self._send_lock:
            self.sock.sendall(encode_frame(ftype, subtype, payload))

    def send_ip(self, packet: bytes) -> None:
        self.send_frame(C.FRAME_DATA, 0, packet)
        self.bytes_out += len(packet)

    # -- heartbeat ---------------------------------------------------------
    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.keepalive_interval):
            with self._miss_lock:
                if self._miss >= self.keepalive_max_miss:
                    self._log("heartbeat: no response, going offline")
                    self._stop.set()
                    try:
                        self.sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    return
                self._miss += 1
            try:
                self.send_frame(C.FRAME_HEARTBEAT, 1)
            except OSError:
                self._stop.set()
                return

    def _reset_miss(self) -> None:
        with self._miss_lock:
            self._miss = 0

    # -- receiving / dispatch ---------------------------------------------
    def _dispatch(self, frames) -> None:
        for ftype, subtype, payload in frames:
            self._reset_miss()  # any inbound frame proves the link is alive
            if ftype == C.FRAME_DATA:
                self.bytes_in += len(payload)
                if self.tun_fd is not None:
                    import os
                    os.write(self.tun_fd, payload)
                if self.on_data:
                    self.on_data(payload)
            elif ftype == C.FRAME_HEARTBEAT:
                pass  # ack; miss already reset
            elif ftype == C.FRAME_NETCONFIG:
                if subtype == C.NETCONFIG_SUB_UPDATE:
                    cfg = parse_netconfig(payload)
                    self._log(f"netconfig update: ip={cfg.ipaddress} gw={cfg.gateway}")
                    if self.on_netconfig:
                        self.on_netconfig(cfg)
                elif subtype == C.NETCONFIG_SUB_DTLS:
                    self._log("netconfig: DTLS offered, ignored (Linux)")
            elif ftype == C.FRAME_LOGOFF:
                self._log("gateway forced log-off (type=4)")
                self._stop.set()

    # -- run ---------------------------------------------------------------
    def run(self) -> None:
        self._hb_thread = threading.Thread(target=self._heartbeat_loop,
                                            name="h3c-heartbeat", daemon=True)
        self._hb_thread.start()
        # Replay any frames buffered during NET_EXTEND / wait_netconfig.
        if self._early:
            early, self._early = self._early, []
            self._dispatch(early)
        rlist = [self.sock]
        if self.tun_fd is not None:
            rlist.append(self.tun_fd)
        try:
            while not self._stop.is_set():
                ready, _, _ = select.select(rlist, [], [], 1.0)
                for r in ready:
                    if r is self.sock:
                        data = self.sock.recv(C.BIG_BUF_SIZE)
                        if not data:
                            raise TunnelClosed("tunnel socket closed")
                        self._dispatch(self.dec.feed(data))
                    else:  # TUN fd has an outbound packet
                        import os
                        pkt = os.read(self.tun_fd, C.BIG_BUF_SIZE)
                        if pkt:
                            self.send_ip(pkt)
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop.set()

    def wait_netconfig(self, timeout: float = 15.0) -> Optional[NetworkConfig]:
        """Block until the first type=3/sub=2 netconfig frame arrives (used right
        after NET_EXTEND, before starting the pump).  Any other frames seen in
        the meantime (e.g. early data frames) are retained in ``self._early`` so
        ``run()`` delivers them — they are never dropped."""
        # 1) check frames already decoded from the initial buffer
        keep: list[tuple[int, int, bytes]] = []
        found: Optional[NetworkConfig] = None
        for fr in self._early:
            if found is None and fr[0] == C.FRAME_NETCONFIG and fr[1] == C.NETCONFIG_SUB_UPDATE:
                found = parse_netconfig(fr[2])
            else:
                keep.append(fr)
        self._early = keep
        if found is not None:
            return found
        # 2) read until a netconfig frame appears
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r, _, _ = select.select([self.sock], [], [], max(0.0, deadline - time.monotonic()))
            if not r:
                continue
            data = self.sock.recv(C.BIG_BUF_SIZE)
            if not data:
                raise TunnelClosed("tunnel socket closed before netconfig")
            for ftype, subtype, payload in self.dec.feed(data):
                if ftype == C.FRAME_NETCONFIG and subtype == C.NETCONFIG_SUB_UPDATE:
                    return parse_netconfig(payload)
                self._early.append((ftype, subtype, payload))  # retain for run()
        return None
