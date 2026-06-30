"""Hardened XML parsing for untrusted gateway responses.

The stdlib ``xml.etree.ElementTree`` is vulnerable to entity-expansion
("billion laughs") and, on some configs, XXE.  The H3C SSL VPN protocol never
uses a DOCTYPE or internal/external entities, so we:

  1. use ``defusedxml`` when it is installed (best), otherwise
  2. reject any document that declares a DOCTYPE/ENTITY and parse the rest with
     the stdlib parser.

This keeps the client dependency-free by default while staying safe against a
malicious or compromised gateway.
"""
from __future__ import annotations

import re
from xml.etree import ElementTree as _ET

_DTD_RE = re.compile(rb"<!(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


class UnsafeXMLError(ValueError):
    """Raised when a document contains a DOCTYPE/ENTITY declaration."""


def _to_bytes(data) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8", "replace")
    return bytes(data)


try:  # pragma: no cover - exercised only when the dep is present
    from defusedxml.ElementTree import fromstring as _defused_fromstring

    def fromstring(data) -> _ET.Element:
        return _defused_fromstring(_to_bytes(data))

    HARDENING = "defusedxml"
except Exception:  # defusedxml not installed -> manual guard
    def fromstring(data) -> _ET.Element:
        raw = _to_bytes(data)
        if _DTD_RE.search(raw):
            raise UnsafeXMLError("XML declares a DOCTYPE/ENTITY; refusing to parse")
        return _ET.fromstring(raw)

    HARDENING = "no-dtd-guard"
