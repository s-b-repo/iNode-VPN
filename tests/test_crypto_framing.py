import struct

import pytest

from h3csvpn import constants as C
from h3csvpn import crypto
from h3csvpn import tunnel
from h3csvpn import spa
from h3csvpn import safexml


# ---- HOTP / RFC 4226 ------------------------------------------------------
RFC4226 = {0: "755224", 1: "287082", 2: "359152", 3: "969429", 4: "338314",
           5: "254676", 6: "287922", 7: "162583", 8: "399871", 9: "520489"}


@pytest.mark.parametrize("counter,expected", RFC4226.items())
def test_hotp_rfc4226_vectors(counter, expected):
    assert crypto.hotp(b"12345678901234567890", counter, 6) == expected


def test_hotp_bytes_length():
    # plain 6 digits, no checksum
    b = crypto.hotp_bytes(b"12345678901234567890", 0, nbytes=6, digits=6,
                          add_checksum=False)
    assert b == b"755224" and len(b) == 6


def test_hotp_luhn_checksum_default():
    # SPA default: 5 HOTP digits + 1 Luhn check digit -> 6 chars.
    # hotp(...,5)=55224 ; Luhn checksum over those 5 digits = 0 -> "552240".
    b = crypto.hotp_bytes(b"12345678901234567890", 0)  # digits=5, checksum=True
    assert len(b) == 6 and b == b"552240"
    assert crypto.hotp(b"12345678901234567890", 0, digits=5) == "55224"


# ---- URL encoding ---------------------------------------------------------
def test_urlencode_body_encodes_everything():
    body = crypto.urlencode_body("<data><password>a b/c</password></data>")
    assert body.startswith("request=")
    assert " " not in body and "/" not in body[len("request="):]
    # iNode URLEncoder::Encode (urlencoder.cpp:18) emits '+' for space, not %20.
    assert "%20" not in body and "a+b" in body


# ---- frame codec ----------------------------------------------------------
def test_frame_roundtrip_and_split():
    f = tunnel.encode_frame(C.FRAME_DATA, 0, b"hello")
    assert f == struct.pack(">BBH", 1, 0, 5) + b"hello"
    dec = tunnel.FrameDecoder()
    out = dec.feed(f[:1]) + dec.feed(f[1:4]) + dec.feed(f[4:])
    assert out == [(1, 0, b"hello")]


def test_frame_coalesced():
    dec = tunnel.FrameDecoder()
    blob = (tunnel.encode_frame(2, 1) + tunnel.encode_frame(1, 0, b"X")
            + tunnel.encode_frame(3, 2, b"IPADDRESS:1.2.3.4\n"))
    out = dec.feed(blob)
    assert [(t, s) for t, s, _ in out] == [(2, 1), (1, 0), (3, 2)]


def test_heartbeat_constant():
    assert tunnel.encode_frame(2, 1) == C.HEARTBEAT_FRAME == b"\x02\x01\x00\x00"


def test_length_is_big_endian():
    f = tunnel.encode_frame(1, 0, b"\x00" * 0x0102)
    assert f[2:4] == b"\x01\x02"  # 258 big-endian


# ---- netconfig parse ------------------------------------------------------
def test_parse_netconfig_full():
    block = (b"IPADDRESS:10.8.0.5\nSUBNETMASK:255.255.255.0\nGATEWAY:10.8.0.1\n"
             b"PREFIXLENGTH:24\nDNS:8.8.8.8,8.8.4.4\nROUTES:192.168.0.0/16\n"
             b"EXCLUDE ROUTES:192.168.99.0/24\nKEEPALIVETIME:30\n")
    nc = tunnel.parse_netconfig(block)
    assert nc.is_valid
    assert nc.ipaddress == "10.8.0.5" and nc.gateway == "10.8.0.1"
    assert nc.dns == ["8.8.8.8", "8.8.4.4"]
    assert nc.routes == ["192.168.0.0/16"]
    assert nc.exclude_routes == ["192.168.99.0/24"]
    assert nc.keepalive_time == 30


def test_netconfig_invalid_without_ip():
    nc = tunnel.parse_netconfig(b"GATEWAY:10.0.0.1\n")
    assert not nc.is_valid


# ---- SPA knock ------------------------------------------------------------
def test_spa_knock_layout():
    cfg = spa.SpaConfig(aid=b"A" * 32, client_key=b"12345678901234567890",
                        ports=(443,))
    pkt = spa.build_knock(cfg, pkt_id=0)
    assert len(pkt) == C.SPA_HEADER_LEN == 0x2F
    assert pkt[0:2] == struct.pack(">H", C.SPA_DECLARED_LEN)  # 0x0110
    assert pkt[2:34] == b"A" * 32                              # aid
    assert pkt[34:38] == struct.pack(">I", 0)                 # pktID
    # password = 5 HOTP digits + Luhn checksum (counter=0 -> "552240")
    assert pkt[38:44] == crypto.hotp_bytes(b"12345678901234567890", 0)
    assert pkt[38:44] == b"552240"
    assert pkt[44] == 1                                       # portCount (1//2)+1
    assert pkt[45:47] == struct.pack(">H", 443)               # port0


# ---- XML hardening --------------------------------------------------------
def test_xxe_blocked():
    with pytest.raises(Exception):
        safexml.fromstring(
            '<!DOCTYPE foo [<!ENTITY x "y">]><data><a>&x;</a></data>')
