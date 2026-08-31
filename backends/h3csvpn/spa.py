"""Zero-Trust SPA (Single Packet Authorization) knock — optional.

Before the SSL VPN port (443) is reachable on a Zero-Trust gateway, the client
sends a 47-byte UDP "knock" to UDP/8000 that authenticates with an RFC 4226
HOTP over a random per-packet counter (PROTOCOL.md §5.6, §7.3).  The per-client
``clientKey`` and ``aid`` come from an earlier SDP registration over HTTPS
(``/api/terminal/...``) — that registration is deployment-specific and out of
scope for this reference client, so the key/aid are supplied by the caller.

SpaKnockPacket (47 bytes base, big-endian):
    0x00  u16  declaredLen = 0x0110
    0x02  [32] clientAid (padded/truncated to 32 bytes)
    0x22  u32  pktID  (random; also the HOTP counter)
    0x26  [6]  password = HOTP(clientKey, pktID)
    0x2c  u8   portCount = (nports // 2) + 1     # recovered formula; VALIDATE
    0x2d  u16  port0 (htons)
    0x2f  u16  portN... (htons, optional)
"""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass

from . import constants as C
from .crypto import hotp_bytes


@dataclass
class SpaConfig:
    aid: bytes              # client AID (<=32 bytes) from SDP registration
    client_key: bytes       # per-client HOTP key from SDP registration
    ports: tuple[int, ...] = (C.SPA_AUTH_PORT,)
    digits: int = C.SPA_HOTP_DIGITS


def build_knock(cfg: SpaConfig, pkt_id: int | None = None) -> bytes:
    if pkt_id is None:
        pkt_id = struct.unpack(">I", os.urandom(4))[0]
    aid = cfg.aid[:C.SPA_AID_LEN].ljust(C.SPA_AID_LEN, b"\x00")
    # digits=5 + RFC4226 Luhn checksum -> 6 chars filling the password[6] field.
    pw = hotp_bytes(cfg.client_key, pkt_id, nbytes=6, digits=cfg.digits,
                    add_checksum=True)
    nports = len(cfg.ports)
    port_count = (nports // 2) + 1
    pkt = struct.pack(">H", C.SPA_DECLARED_LEN)
    pkt += aid
    pkt += struct.pack(">I", pkt_id)
    pkt += pw
    pkt += struct.pack(">B", port_count)
    for p in cfg.ports:
        pkt += struct.pack(">H", p)
    return pkt


def send_knock(host: str, cfg: SpaConfig, port: int = C.SPA_KNOCK_PORT_GW,
               pkt_id: int | None = None) -> bytes:
    pkt = build_knock(cfg, pkt_id=pkt_id)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(pkt, (host, port))
    return pkt
