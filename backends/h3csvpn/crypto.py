"""Encoding / crypto helpers for the H3C iNode SSL VPN protocol.

Recovered facts (see ``docs/PROTOCOL.md`` §5 + Addendum A):

* The login/challenge body is the whole ``<data>`` doc **URL-percent-encoded**
  and prefixed ``request=``.  The password is **cleartext inside TLS** — no
  app-layer RSA/AES on the standard V7 path.
* ``<private>`` is a small base64 host-telemetry blob (RFC4648 standard
  alphabet); an empty value is accepted by the gateway.
* SPA (Zero-Trust) uses an RFC 4226 HMAC-SHA1 HOTP over a random 32-bit counter.
* An optional RSA mode (``base64(RSA_encrypt(pubkey, pw))``) is provided behind a
  flag for any firmware that advertises ``H3C_USER_RSAKEY`` — not used by default.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
# Bytes the iNode encoder leaves verbatim: ASCII letters and digits ONLY.
_URL_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")


# --------------------------------------------------------------------------
# wire encoding
# --------------------------------------------------------------------------
def urlencode_body(xml: str) -> str:
    """``request=`` + ``URLEncoder::Encode(xml)`` — byte-exact with the iNode
    client's encoder (``URLEncoder::Encode``, ``urlencoder.cpp:6-26``).

    The whole ``<data>`` document is run through this once.  iNode uses classic
    ``application/x-www-form-urlencoded`` rules, **not** RFC 3986:

      * ASCII ``[A-Za-z0-9]`` are kept verbatim;
      * **a space becomes ``+``** (``urlencoder.cpp:18``) — *not* ``%20``;
      * every other byte (including ``-`` ``.`` ``_`` ``~`` ``<`` ``>`` ``/``
        ``@`` ``%`` and any non-ASCII/UTF-8 byte) becomes ``%XX``.

    This matters: a username like ``stephan botes`` goes out as
    ``stephan+botes``.  A gateway whose CGI maps only ``+``->space (and treats a
    literal ``%20`` as text) would otherwise reject the username.  (Earlier this
    used ``quote(safe="")`` which emits ``%20`` and keeps ``-._~`` — both wrong.)
    """
    out = []
    for byte in xml.encode("utf-8"):
        if chr(byte) in _URL_UNRESERVED:
            out.append(chr(byte))
        elif byte == 0x20:
            out.append("+")
        else:
            out.append("%%%02X" % byte)
    return "request=" + "".join(out)


def make_private_blob(*, host: str = "", os_name: str = "Linux",
                      extra: bytes = b"") -> str:
    """Best-effort ``<private>`` base64 telemetry blob.

    The exact byte layout of ``makePrivateContent`` is not fully decoded; the
    gateway accepts an empty/placeholder value, so we default to empty and only
    emit a minimal, clearly-delimited blob when ``host``/``extra`` is supplied.
    """
    if not host and not extra:
        return ""
    payload = host.encode("utf-8", "replace") + b"\x00" + \
        os_name.encode("ascii", "replace") + b"\x00" + extra
    return base64.b64encode(payload).decode("ascii")


# --------------------------------------------------------------------------
# SPA HOTP (RFC 4226) — PROTOCOL.md §5.6, generateOTP @0x1bd70
# --------------------------------------------------------------------------
_DIGITS_POWER = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000]
_DOUBLE = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9]  # RFC 4226 Appendix A doubling table


def _luhn_checksum(num: int, digits: int) -> int:
    """RFC 4226 ``calcChecksum`` (Luhn mod-10 over the low ``digits`` digits)."""
    total, dbl = 0, True
    for _ in range(digits):
        d = num % 10
        num //= 10
        if dbl:
            d = _DOUBLE[d]
        total += d
        dbl = not dbl
    result = total % 10
    return (10 - result) if result > 0 else 0


def hotp(key: bytes, counter: int, digits: int = 6,
         add_checksum: bool = False) -> str:
    """RFC 4226 HOTP/HMAC-SHA1.  ``counter`` is the random ``pktID`` sent in
    clear; ``key`` is the per-client ``clientKey`` from SDP registration.

    With ``add_checksum`` a Luhn check digit is appended (RFC 4226), giving a
    ``digits+1`` long string — this is how the SPA knock fills its 6-byte
    password field with ``digits=5`` (PROTOCOL.md §5.6: digits=5, addChecksum=1)."""
    msg = struct.pack(">Q", counter & 0xFFFFFFFFFFFFFFFF)
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    off = mac[19] & 0x0F
    binc = ((mac[off] & 0x7F) << 24) | (mac[off + 1] << 16) | \
           (mac[off + 2] << 8) | mac[off + 3]
    otp = binc % _DIGITS_POWER[digits]
    if add_checksum:
        otp = otp * 10 + _luhn_checksum(otp, digits)
        return str(otp).zfill(digits + 1)
    return str(otp).zfill(digits)


def hotp_bytes(key: bytes, counter: int, nbytes: int = 6, digits: int = 5,
               add_checksum: bool = True) -> bytes:
    """The SPA password field is ``nbytes`` (6).  The recovered call uses
    ``digits=5, addChecksum=1`` -> a 6-char string that exactly fills the field.
    Pads with NUL (``sprintf`` semantics) if the string is shorter."""
    s = hotp(key, counter, digits=digits, add_checksum=add_checksum)
    return s.encode("ascii")[:nbytes].ljust(nbytes, b"\x00")


# --------------------------------------------------------------------------
# optional RSA password mode (NOT default; firmware variant)
# --------------------------------------------------------------------------
def rsa_encrypt_password_b64(pubkey_pem_or_der: bytes, password: str) -> str:
    """base64(RSA_PKCS1_encrypt(pubkey, password)).

    Only needed if a gateway advertises an RSA public key (``H3C_USER_RSAKEY``).
    Requires the ``cryptography`` package; raises a clear error otherwise.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import (
            load_der_public_key, load_pem_public_key)
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "RSA password mode requires the 'cryptography' package "
            "(pip install cryptography)") from exc

    data = pubkey_pem_or_der
    try:
        pub = load_pem_public_key(data)
    except Exception:
        pub = load_der_public_key(data)
    ct = pub.encrypt(password.encode("utf-8"), padding.PKCS1v15())
    return base64.b64encode(ct).decode("ascii")
