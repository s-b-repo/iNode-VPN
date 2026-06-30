"""A tiny HTTP/1.1 client that runs over an already-connected (TLS) socket.

We can't use ``http.client`` because the protocol needs:
  * full control of header order / exact cookie strings,
  * a custom request verb (``NET_EXTEND``) that then switches the same socket to
    a raw binary frame stream,
  * to keep the connection alive across many requests.

This implements just enough: request writing, response parsing (status line,
headers, Content-Length / chunked bodies), a simple cookie jar, and redirect
classification.  It is deliberately small and readable.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field

from . import constants as C


class HTTPError(Exception):
    pass


@dataclass
class Response:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    raw_status_line: str = ""

    def header(self, name: str, default: str = "") -> str:
        nl = name.lower()
        for k, v in self.headers:
            if k.lower() == nl:
                return v
        return default

    def headers_all(self, name: str) -> list[str]:
        nl = name.lower()
        return [v for k, v in self.headers if k.lower() == nl]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def is_success(self) -> bool:
        return self.status == 200

    @property
    def is_redirect(self) -> bool:
        return C.REDIRECT_MIN <= self.status <= C.REDIRECT_MAX


class CookieJar:
    """Minimal cookie store: name -> value, last-write-wins (the gateway uses a
    flat namespace: svpnginfo / svpnvldid / svpnuid / vldID / domainId)."""

    def __init__(self) -> None:
        self._c: dict[str, str] = {}

    def update_from_response(self, resp: Response) -> None:
        for sc in resp.headers_all("Set-Cookie"):
            first = sc.split(";", 1)[0].strip()
            if "=" in first:
                name, val = first.split("=", 1)
                self._c[name.strip()] = val.strip()

    def set(self, name: str, value: str) -> None:
        self._c[name] = value

    def get(self, name: str, default: str = "") -> str:
        return self._c.get(name, default)

    def header_value(self, names=None) -> str:
        items = self._c.items() if names is None else [
            (n, self._c[n]) for n in names if n in self._c]
        return "; ".join(f"{n}={v}" for n, v in items)


class Connection:
    """HTTP/1.1 over a connected stream socket (plain or ``ssl.SSLSocket``)."""

    def __init__(self, sock: socket.socket, host: str, port: int = 443) -> None:
        self.sock = sock
        self.host = host
        self.port = port
        self.cookies = CookieJar()
        self._buf = b""

    # -- low level ---------------------------------------------------------
    def _send_all(self, data: bytes) -> None:
        self.sock.sendall(data)

    def _recv_some(self) -> bytes:
        data = self.sock.recv(65536)
        if not data:
            raise HTTPError("connection closed by peer")
        return data

    def _read_until(self, marker: bytes, *, cap: int = C.MAX_HEADER_BYTES) -> bytes:
        while marker not in self._buf:
            if len(self._buf) > cap:
                raise HTTPError(f"line/marker not found within {cap} bytes "
                                "(hostile or non-HTTP response)")
            self._buf += self._recv_some()
        idx = self._buf.index(marker) + len(marker)
        out, self._buf = self._buf[:idx], self._buf[idx:]
        return out

    def _read_exact(self, n: int) -> bytes:
        if n > C.MAX_BODY_BYTES:
            raise HTTPError(f"declared body size {n} exceeds cap {C.MAX_BODY_BYTES}")
        while len(self._buf) < n:
            self._buf += self._recv_some()
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def take_buffered(self) -> bytes:
        """Return (and clear) any bytes already read past the HTTP response —
        needed when the socket switches to raw framing after ``NET_EXTEND``."""
        out, self._buf = self._buf, b""
        return out

    # -- requests ----------------------------------------------------------
    def request(self, method: str, path: str, *, headers=None, body: bytes = b"",
                ua: str = C.UA_V7, cookies=None, host_header=None,
                read_response: bool = True):
        host = host_header or self.host
        if self.port not in (80, 443):
            host = f"{host}:{self.port}"
        lines = [f"{method} {path} {C.HTTP_VERSION}",
                 f"Host: {host}",
                 f"User-Agent: {ua}",
                 "Connection: Keep-Alive"]
        cookie_str = ""
        if cookies is True:
            cookie_str = self.cookies.header_value()
        elif isinstance(cookies, str):
            cookie_str = cookies
        elif isinstance(cookies, (list, tuple)):
            cookie_str = self.cookies.header_value(cookies)
        if cookie_str:
            lines.append(f"Cookie: {cookie_str}")
        for k, v in (headers or []):
            lines.append(f"{k}: {v}")
        if body:
            lines.append(f"Content-Type: {C.FORM_CONTENT_TYPE}")
            lines.append(f"Content-Length: {len(body)}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
        self._send_all(raw)
        if not read_response:
            return None
        resp = self._read_response()
        self.cookies.update_from_response(resp)
        return resp

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body, **kw):
        if isinstance(body, str):
            body = body.encode("latin-1", "replace")
        return self.request("POST", path, body=body, **kw)

    # -- response parsing --------------------------------------------------
    def _read_response(self) -> Response:
        head = self._read_until(b"\r\n\r\n").decode("latin-1", "replace")
        status_line, _, rest = head.partition("\r\n")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise HTTPError(f"bad status line: {status_line!r}")
        status = int(parts[1])
        reason = parts[2] if len(parts) > 2 else ""
        headers: list[tuple[str, str]] = []
        for hl in rest.split("\r\n"):
            if not hl:
                continue
            k, _, v = hl.partition(":")
            headers.append((k.strip(), v.strip()))
        tmp = Response(status, reason, headers, b"", status_line)

        te = tmp.header("Transfer-Encoding").lower()
        if "chunked" in te:
            body = self._read_chunked()
        else:
            cl = tmp.header("Content-Length")
            try:
                cl_int = int(cl)
                if str(cl_int) != cl.strip():
                    raise HTTPError(f"non-integer Content-Length: {cl!r}")
                body = self._read_exact(cl_int)
            except ValueError:
                raise HTTPError(f"bad Content-Length: {cl!r}")
        tmp.body = body
        return tmp

    def _read_chunked(self) -> bytes:
        out = bytearray()
        chunks = 0
        while True:
            chunks += 1
            if chunks > C.MAX_CHUNKS:
                raise HTTPError("too many chunks (hostile response)")
            size_line = self._read_until(b"\r\n").strip()
            token = size_line.split(b";", 1)[0].strip()
            try:
                size = int(token, 16)
            except ValueError:
                raise HTTPError(f"bad chunk size: {size_line!r}")
            if size == 0:
                # drain optional trailer header lines up to the terminating CRLF.
                # Cap the number of trailer lines to prevent DoS from a malicious
                # server that sends endless trailers without a terminator.
                trailers = 0
                while True:
                    trailers += 1
                    if trailers > 100:
                        raise HTTPError("too many trailer lines (hostile response)")
                    if self._read_until(b"\r\n") == b"\r\n":
                        break
                break
            out += self._read_exact(size)
            if len(out) > C.MAX_BODY_BYTES:
                raise HTTPError("chunked body exceeds size cap")
            self._read_exact(2)  # CRLF after chunk
        return bytes(out)
