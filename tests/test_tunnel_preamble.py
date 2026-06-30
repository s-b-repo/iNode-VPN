"""Tests for the new NET_EXTEND preamble handling and vnic pure helpers."""
import socket
import struct

from h3csvpn import constants as C
from h3csvpn import vnic
from h3csvpn.httpclient import Connection
from h3csvpn.session import SslVpnSession, Credentials, Options, _http_content_length
from h3csvpn.tunnel import encode_frame


def _netcfg_block():
    return (b"IPADDRESS:10.8.0.5\nSUBNETMASK:255.255.255.0\n"
            b"GATEWAY:10.8.0.1\nDNS:10.8.0.1\nKEEPALIVETIME:25\n")


def _session():
    return SslVpnSession(Credentials("u", "p"), Options(host="h"))


def _preamble(server_bytes: bytes):
    """Feed server_bytes into a Connection and run _read_tunnel_preamble."""
    a, b = socket.socketpair()
    b.sendall(server_bytes)
    b.close()
    conn = Connection(a, "h", 443)
    try:
        return _session()._read_tunnel_preamble(conn)
    finally:
        a.close()


def test_preamble_raw_frames():
    # gateway sends frames straight away (no HTTP preamble)
    blob = encode_frame(C.FRAME_NETCONFIG, 2, _netcfg_block())
    leftover, cfg = _preamble(blob)
    assert cfg is None              # netconfig is in the frame, read by wait_netconfig
    assert leftover == blob


def test_preamble_http_then_frames():
    # HTTP preamble (no body) followed by the netconfig frame
    frame = encode_frame(C.FRAME_NETCONFIG, 2, _netcfg_block())
    blob = b"HTTP/1.1 200 OK\r\nServer: SSLVPN-Gateway/7.0\r\n\r\n" + frame
    leftover, cfg = _preamble(blob)
    assert cfg is None
    assert leftover == frame


def test_preamble_http_body_carries_param_block():
    # some firmwares put the KEY:value param block in the HTTP body
    body = _netcfg_block()
    blob = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)) + body
    leftover, cfg = _preamble(blob)
    assert cfg is not None and cfg.ipaddress == "10.8.0.5"
    assert cfg.keepalive_time == 25
    assert leftover == b""


def test_http_content_length_helper():
    assert _http_content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 42") == 42
    assert _http_content_length(b"HTTP/1.1 200 OK\r\nX: y") is None


def test_vnic_cidr_helpers():
    assert vnic._mask_to_prefix("255.255.255.0") == 24
    assert vnic._mask_to_prefix("255.255.0.0") == 16
    assert vnic._normalize_cidr("10.0.0.0/8") == "10.0.0.0/8"
    assert vnic._normalize_cidr("10.0.0.0 255.0.0.0") == "10.0.0.0/8"
    assert vnic._normalize_cidr("1.2.3.4") == "1.2.3.4/32"
    assert vnic._normalize_cidr("") == ""


def test_vnic_atomic_write(tmp_path):
    p = tmp_path / "resolv.conf"
    vnic._atomic_write(str(p), b"nameserver 1.1.1.1\n")
    assert p.read_bytes() == b"nameserver 1.1.1.1\n"
    # overwrite is atomic and complete
    vnic._atomic_write(str(p), b"x")
    assert p.read_bytes() == b"x"
