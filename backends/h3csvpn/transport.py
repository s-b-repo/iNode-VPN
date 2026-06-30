"""TLS connection setup for the control and tunnel channels.

The real client (``buildSslCtx``) verifies the peer + hostname and optionally
presents a client certificate (PEM/PFX) or a GM SM2 SKF UKey.  Many real H3C
deployments use a private/self-signed gateway certificate, so ``--insecure`` is
supported (off by default).  GM/SM2 (CNTLS) is out of scope for this reference
client and noted as a limitation.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass
from typing import Optional

from . import constants as C
from .httpclient import Connection


class TLSPinError(ssl.SSLError):
    pass


@dataclass
class TLSConfig:
    verify: bool = True
    cafile: Optional[str] = None
    # Secure alternative to --insecure for self-signed gateways: pin the peer
    # certificate's SHA-256 fingerprint (hex, colons optional).
    pin_sha256: Optional[str] = None
    client_cert: Optional[str] = None      # PEM file (cert+key) for mutual TLS
    client_key: Optional[str] = None
    client_key_password: Optional[str] = None
    server_hostname: Optional[str] = None  # SNI override
    min_tls: Optional[str] = None          # "1.0" / "1.2" / None=auto
    timeout: float = 30.0


def _normalize_pin(pin: str) -> str:
    return pin.replace(":", "").replace(" ", "").lower()


def build_ssl_context(cfg: TLSConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Fingerprint pinning verifies the exact gateway cert without a CA chain —
    # the right way to trust a self-signed gateway. Hostname/CA checks are then
    # redundant, so we disable them but still bind to the pinned cert below.
    if cfg.verify and not cfg.pin_sha256:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if cfg.cafile:
            ctx.load_verify_locations(cfg.cafile)
        else:
            ctx.load_default_certs()
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cfg.client_cert:
        ctx.load_cert_chain(cfg.client_cert, keyfile=cfg.client_key,
                            password=cfg.client_key_password)
    if cfg.min_tls == "1.0":
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    elif cfg.min_tls == "1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # H3C gateways are often old; allow legacy ciphers/weak certs whenever trust
    # does NOT come from X.509 chain validation (i.e. fingerprint pin or no
    # verify), since SECLEVEL is then irrelevant to the trust decision.
    if cfg.pin_sha256 or not cfg.verify:
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    return ctx


def tls_connect(host: str, port: int = C.DEFAULT_PORT,
                cfg: Optional[TLSConfig] = None) -> Connection:
    """Open a fresh TLS connection and wrap it in an HTTP ``Connection``.

    A *new* TLS socket is used for the tunnel channel (the gateway requires the
    ``NET_EXTEND`` upgrade on a separate connection from the auth channel).
    """
    cfg = cfg or TLSConfig()
    ctx = build_ssl_context(cfg)
    sni = cfg.server_hostname or host
    raw = socket.create_connection((host, port), timeout=cfg.timeout)
    try:
        sock = ctx.wrap_socket(raw, server_hostname=sni)
        if cfg.pin_sha256:
            der = sock.getpeercert(binary_form=True) or b""
            got = hashlib.sha256(der).hexdigest()
            want = _normalize_pin(cfg.pin_sha256)
            if got != want:
                raise TLSPinError(
                    f"certificate pin mismatch: peer={got} expected={want}")
    except Exception:
        try:
            raw.close()
        except OSError:
            pass
        raise
    sock.settimeout(cfg.timeout)
    return Connection(sock, host, port)
