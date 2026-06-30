"""A mock H3C iNode SSL VPN ("V7") gateway for end-to-end testing.

Implements the server side of PROTOCOL.md well enough to exercise the client:
index/gatewayinfo, optional CAPTCHA, login (+ optional SMS challenge), the
``NET_EXTEND`` upgrade, the network-config frame, heartbeats and data echo.

It is intentionally permissive and is NOT a real gateway — it exists so the
client can be validated offline.  Run standalone:

    python -m mock.mock_gateway --port 4443 --user alice --password secret
"""
from __future__ import annotations

import argparse
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit, parse_qs

# frame constants (kept local so the mock has no dependency on the client pkg)
FRAME_DATA, FRAME_HEARTBEAT, FRAME_NETCONFIG, FRAME_LOGOFF = 1, 2, 3, 4
VERSION_HEADER = "SSLVPN-Gateway/7.0"


def make_self_signed_cert(dirpath: str) -> tuple[str, str]:
    cert = os.path.join(dirpath, "gw.crt")
    key = os.path.join(dirpath, "gw.key")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "h3c-mock-gw")])
        now = datetime.datetime.now(datetime.timezone.utc)
        crt = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name).public_key(k.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=3650))
               .add_extension(x509.SubjectAlternativeName(
                   [x509.DNSName("localhost"), x509.DNSName("h3c-mock-gw")]), False)
               .sign(k, hashes.SHA256()))
        with open(key, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
        with open(cert, "wb") as f:
            f.write(crt.public_bytes(serialization.Encoding.PEM))
    except Exception:  # fall back to the openssl CLI
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                        "-keyout", key, "-out", cert, "-days", "3650", "-nodes",
                        "-subj", "/CN=h3c-mock-gw"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


@dataclass
class MockConfig:
    username: str = "alice"
    password: str = "secret"
    require_captcha: bool = False
    captcha_answer: str = "1234"
    require_challenge: bool = False
    challenge_type: str = "SMS"
    challenge_code: str = "654321"
    assign_ip: str = "10.8.0.5"
    netmask: str = "255.255.255.0"
    gateway: str = "10.8.0.1"
    dns: tuple[str, ...] = ("10.8.0.1",)
    routes: tuple[str, ...] = ("192.168.50.0/24",)


class MockGateway:
    def __init__(self, host="127.0.0.1", port=0, cfg: MockConfig | None = None):
        self.host, self.port = host, port
        self.cfg = cfg or MockConfig()
        self._tmp = tempfile.mkdtemp(prefix="h3cmock-")
        self.cert, self.key = make_self_signed_cert(self._tmp)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self.cert, self.key)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # tracks (per svpnginfo) whether the challenge step has been satisfied
        self._sessions: dict[str, dict] = {}

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "MockGateway":
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def cert_fingerprint_sha256(self) -> str:
        import hashlib
        der = ssl.PEM_cert_to_DER_cert(open(self.cert).read())
        return hashlib.sha256(der).hexdigest()

    # -- server loop -------------------------------------------------------
    def _serve(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                raw, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket) -> None:
        try:
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        try:
            self._serve_conn(conn)
        except (ssl.SSLError, OSError, ConnectionError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # -- HTTP plumbing -----------------------------------------------------
    def _read_request(self, conn, buf: bytearray):
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buf += chunk
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        buf[:] = rest
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = (lines[0].split(" ") + ["", ""])[:3]
        headers = {}
        for hl in lines[1:]:
            k, _, v = hl.partition(":")
            headers[k.strip().lower()] = v.strip()
        body = b""
        if "content-length" in headers:
            need = int(headers["content-length"])
            while len(buf) < need:
                buf += conn.recv(4096)
            body, rest2 = bytes(buf[:need]), bytes(buf[need:])
            buf[:] = rest2
        return method, path, headers, body

    def _send(self, conn, status="200 OK", body=b"", cookies=None, ctype="text/xml"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        hdr = [f"HTTP/1.1 {status}", f"Server: {VERSION_HEADER}",
               f"Content-Type: {ctype}", f"Content-Length: {len(body)}",
               "Connection: Keep-Alive"]
        for c in (cookies or []):
            hdr.append(f"Set-Cookie: {c}")
        conn.sendall(("\r\n".join(hdr) + "\r\n\r\n").encode("latin-1") + body)

    # -- request routing ---------------------------------------------------
    def _serve_conn(self, conn) -> None:
        buf = bytearray()
        while not self._stop.is_set():
            req = self._read_request(conn, buf)
            if req is None:
                return
            method, path, headers, body = req
            if method == "NET_EXTEND":
                self._serve_tunnel(conn, headers, bytes(buf))
                return
            sp = urlsplit(path)
            q = parse_qs(sp.query)
            sid = _cookie(headers, "svpnginfo") or "sess-1"

            if sp.path == "/svpn/index.cgi" and q.get("type", [""])[0] == "getdomainlist":
                self._send(conn, body=self._domainlist())
            elif sp.path == "/svpn/index.cgi":
                self._send(conn, body=self._gatewayinfo(),
                           cookies=[f"svpnginfo={sid}"])
            elif sp.path == "/svpn/image.cgi":
                self._send(conn, body=b"\x89PNG\r\n\x1a\nMOCKCAPTCHA",
                           ctype="image/png",
                           cookies=[f"svpnvldid=1", f"vldID=1", f"svpnginfo={sid}"])
            elif sp.path.endswith("check.cgi") or sp.path.endswith("login_submit.cgi"):
                self._send(conn, body=self._do_login(sid, body),
                           cookies=[f"svpnginfo={sid}"])
            elif sp.path.endswith("check_return.cgi"):
                self._send(conn, body=self._do_challenge(sid, body),
                           cookies=[f"svpnginfo={sid}"])
            elif sp.path == "/svpn/logout.cgi":
                self._send(conn, body="<data><result>Success</result></data>")
                return
            else:
                self._send(conn, status="404 Not Found",
                           body="<data><result>NotFound</result></data>")

    # -- handlers ----------------------------------------------------------
    def _gatewayinfo(self) -> str:
        v = "1" if self.cfg.require_captcha else "0"
        return ("<data><gatewayinfo><auth>"
                "<supportPassword>1</supportPassword><supportCert>0</supportCert>"
                "<supportDKey>0</supportDKey>"
                f"<supportvldimg>{v}</supportvldimg>"
                "<vldimg url=\"/svpn/image.cgi\"/>"
                "<login>/svpn/vpnuser/check.cgi</login>"
                "<logout>/svpn/logout.cgi</logout>"
                "<challenge>/svpn/vpnuser/check_return.cgi</challenge>"
                "</auth></gatewayinfo></data>")

    def _domainlist(self) -> str:
        return ("<data><domainlist>"
                "<domain><name>RADIUS</name><url>/svpn/vpnuser/check.cgi</url></domain>"
                "<domain><name>Local</name><url>/svpn/vpnuser/check.cgi</url></domain>"
                "</domainlist></data>")

    def _form(self, body: bytes) -> dict:
        text = body.decode("latin-1")
        if text.startswith("request="):
            return {"_xml": unquote(text[len("request="):])}
        out = {}
        for kv in text.split("&"):
            k, _, v = kv.partition("=")
            out[k] = unquote(v)
        return out

    def _xml_field(self, xml: str, tag: str) -> str:
        import re
        m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.S)
        return m.group(1) if m else ""

    def _do_login(self, sid: str, body: bytes) -> str:
        form = self._form(body)
        xml = form.get("_xml", "")
        user = self._xml_field(xml, "username") or form.get("txtUsrName", "")
        pw = self._xml_field(xml, "password") or form.get("txtPassword", "")
        vld = self._xml_field(xml, "vldCode") or form.get("vldCode", "")
        user = user.split("@", 1)[0]
        if self.cfg.require_captcha and vld != self.cfg.captcha_answer:
            return "<data><result>Failed</result><message>bad captcha</message></data>"
        if user != self.cfg.username or pw != self.cfg.password:
            return "<data><result>Failed</result><message>bad credentials</message></data>"
        if self.cfg.require_challenge:
            self._sessions[sid] = {"await_challenge": True}
            return (f"<data><result>Challenge</result><type>{self.cfg.challenge_type}</type>"
                    "<message>enter the SMS code</message><waitTime>120</waitTime>"
                    "<intervaltime>60</intervaltime></data>")
        self._sessions[sid] = {"authed": True}
        return "<data><result>Success</result><replyMessage>welcome</replyMessage></data>"

    def _do_challenge(self, sid: str, body: bytes) -> str:
        xml = self._form(body).get("_xml", "")
        code = self._xml_field(xml, "code")
        if code == self.cfg.challenge_code:
            self._sessions[sid] = {"authed": True}
            return "<data><result>Success</result><replyMessage>ok</replyMessage></data>"
        return ("<data><result>Challenge</result>"
                f"<type>{self.cfg.challenge_type}</type>"
                "<message>wrong code, try again</message></data>")

    # -- tunnel ------------------------------------------------------------
    def _netconfig_block(self) -> bytes:
        c = self.cfg
        lines = [f"IPADDRESS:{c.assign_ip}", f"SUBNETMASK:{c.netmask}",
                 f"GATEWAY:{c.gateway}", "PREFIXLENGTH:24",
                 f"DNS:{','.join(c.dns)}", f"ROUTES:{','.join(c.routes)}",
                 "KEEPALIVETIME:30"]
        return ("\n".join(lines) + "\n").encode("utf-8")

    def _frame(self, ftype, sub, payload=b""):
        return struct.pack(">BBH", ftype, sub, len(payload)) + payload

    def _serve_tunnel(self, conn, headers, leftover: bytes) -> None:
        # push the network-config frame immediately (type=3/sub=2)
        conn.sendall(self._frame(FRAME_NETCONFIG, 2, self._netconfig_block()))
        buf = bytearray(leftover)
        dec_state = bytearray(buf)
        conn.settimeout(60)
        pending = bytearray(leftover)
        while not self._stop.is_set():
            try:
                data = conn.recv(65536)
            except (socket.timeout, OSError):
                break
            if not data:
                break
            pending += data
            while len(pending) >= 4:
                ftype, sub, length = struct.unpack_from(">BBH", pending, 0)
                if len(pending) < 4 + length:
                    break
                payload = bytes(pending[4:4 + length])
                del pending[:4 + length]
                if ftype == FRAME_HEARTBEAT:
                    conn.sendall(self._frame(FRAME_HEARTBEAT, 1))  # ack
                elif ftype == FRAME_DATA:
                    conn.sendall(self._frame(FRAME_DATA, 0, payload))  # echo


def _cookie(headers: dict, name: str) -> str:
    raw = headers.get("cookie", "")
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4443)
    ap.add_argument("--user", default="alice")
    ap.add_argument("--password", default="secret")
    ap.add_argument("--captcha", action="store_true")
    ap.add_argument("--challenge", action="store_true")
    a = ap.parse_args()
    cfg = MockConfig(username=a.user, password=a.password,
                     require_captcha=a.captcha, require_challenge=a.challenge)
    gw = MockGateway(a.host, a.port, cfg).start()
    print(f"mock H3C SSL VPN gateway on {a.host}:{gw.port}")
    print(f"cert SHA-256 pin: {gw.cert_fingerprint_sha256()}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        gw.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
