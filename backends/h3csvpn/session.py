"""End-to-end SSL VPN session orchestration (PROTOCOL.md §2 / §8).

Drives: (optional SPA knock) -> TLS -> /svpn/index.cgi -> gatewayinfo/domainlist
-> CAPTCHA -> login -> challenge/2FA loop -> kick-old -> NET_EXTEND tunnel ->
network-config -> virtual NIC -> data pump -> logout.
"""
from __future__ import annotations

import select
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlsplit

from . import constants as C
from . import protocol as P
from .crypto import urlencode_body, make_private_blob, rsa_encrypt_password_b64
from .httpclient import Connection, Response
from .transport import TLSConfig, tls_connect
from .tunnel import Tunnel, NetworkConfig, parse_netconfig
from . import spa as spa_mod


class AuthError(Exception):
    pass


@dataclass
class Credentials:
    username: str
    password: str
    domain: str = ""              # domain name hint (selects from domain list)
    new_password: str = ""        # for CHANGEPWD challenges


@dataclass
class Options:
    host: str = ""
    port: int = C.DEFAULT_PORT
    language: str = "cn"
    mac: str = ""
    tls: TLSConfig = field(default_factory=TLSConfig)
    private_blob: str = ""        # empty = let the gateway accept default
    rsa_pubkey: Optional[bytes] = None   # enables RSA password mode if set
    zero_trust: Optional[spa_mod.SpaConfig] = None
    ead: bool = False
    keepalive_max_miss: int = C.DEFAULT_KEEPALIVE_MAX_MISS
    # CAPTCHA handling (the live gateway gates login on a weak BMP captcha)
    auto_captcha: bool = True       # OCR-solve and auto-retry on "Verify code error"
    captcha_retries: int = 8        # max fresh-captcha attempts before giving up
    show_captcha: bool = True       # render the captcha image in the terminal


# Interaction hooks (overridable for non-interactive / test use)
class Prompter:
    def captcha(self, image: bytes) -> str:
        # the image is rendered to the terminal by the session before this call
        try:
            return input("[captcha] enter the code shown above: ").strip()
        except EOFError:
            sys.stderr.write("[!] CAPTCHA required but no input is available; "
                             "enable --auto-captcha or pass --vldcode.\n")
            return ""

    def challenge_code(self, ctype: str, message: str) -> str:
        try:
            return input(f"[challenge:{ctype}] {message}\nCode: ").strip()
        except EOFError:
            return ""


@dataclass
class AuthState:
    conn: Connection
    version: str
    gateway: P.GatewayInfo
    login_url: str
    svpnginfo: str
    domain_id: str = "0"


class SslVpnSession:
    def __init__(self, creds: Credentials, opts: Options,
                 prompter: Optional[Prompter] = None,
                 vld_code: str = "",
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.creds = creds
        self.opts = opts
        self.prompter = prompter or Prompter()
        self.vld_code = vld_code
        self._log = log or (lambda m: sys.stderr.write(m + "\n"))
        self.auth: Optional[AuthState] = None

    # -- helpers -----------------------------------------------------------
    def _encode_password(self, pw: str) -> str:
        if self.opts.rsa_pubkey:
            return rsa_encrypt_password_b64(self.opts.rsa_pubkey, pw)
        return pw  # cleartext-in-TLS (standard V7 path; PROTOCOL.md Addendum A)

    def _private(self) -> str:
        if self.opts.private_blob:
            return self.opts.private_blob
        return make_private_blob()  # "" by default

    def _full_user(self) -> str:
        if self.creds.domain and "@" not in self.creds.username:
            return f"{self.creds.username}@{self.creds.domain}"
        return self.creds.username

    # -- phase: authenticate ----------------------------------------------
    def authenticate(self) -> AuthState:
        if self.opts.zero_trust:
            self._log("SPA: sending Zero-Trust knock")
            spa_mod.send_knock(self.opts.host, self.opts.zero_trust)

        conn = tls_connect(self.opts.host, self.opts.port, self.opts.tls)
        self._log(f"TLS connected to {self.opts.host}:{self.opts.port}")

        # 1) index.cgi + follow redirects, detect version, get gatewayinfo
        resp = conn.get(C.PATH_INDEX, ua=C.UA_V7)
        version = "V7" if C.VERSION_SENTINEL in resp.header("Server") else "V3"
        if version == "V3":
            self._log("warning: gateway looks like legacy V3 (no "
                      f"'{C.VERSION_SENTINEL}'); this client implements V7")
        saw_domainlist = False
        hops = 0
        while resp.is_redirect and hops < 10:
            loc = resp.header("Location")
            if "getdomainlist" in loc:
                saw_domainlist = True
            path = _path_of(loc)
            resp = conn.get(path, ua=C.UA_V7, cookies=True)
            hops += 1
        if not resp.is_success:
            raise AuthError(f"index.cgi returned {resp.status} {resp.reason}")

        gw = P.parse_gatewayinfo(resp.text) if "<" in resp.text else P.GatewayInfo()
        login_url = gw.login_url

        # 2) domain list (if advertised / redirected)
        domain_id = "0"
        if saw_domainlist or self.creds.domain:
            dl_url = login_url  # the domainlist is usually fetched from index flow
            try:
                dresp = conn.get(C.PATH_INDEX + "?type=getdomainlist", ua=C.UA_V7,
                                 cookies=C.DOMAIN_COOKIE.format(domain_id=domain_id))
                if dresp.is_success and "<domain" in dresp.text:
                    domains = P.parse_domainlist(dresp.text)
                    chosen = _pick_domain(domains, self.creds.domain)
                    if chosen:
                        self._log(f"domain: {chosen.name} -> {chosen.url}")
                        login_url = chosen.url or login_url
            except Exception as exc:  # domain list is best-effort
                self._log(f"domain list skipped: {exc}")

        svpnginfo = conn.cookies.get(C.SESSION_COOKIE)

        # 3+4) CAPTCHA + login.  The gateway binds the captcha answer to the
        # svpnginfo=vld@... cookie set by GET <vldimg>; a wrong answer yields
        # result=Failed / replyMessage="Verify code error".  When the captcha is
        # required we auto-solve (OCR) and auto-retry with a fresh image.
        if gw.support_vldimg:
            result = self._captcha_login_loop(conn, gw, login_url)
        else:
            result = self._login_once(conn, login_url, self.vld_code)
        svpnginfo = conn.cookies.get(C.SESSION_COOKIE, svpnginfo)

        # 5) challenge / 2FA loop
        result = self._run_challenge_loop(conn, gw, result)
        if not result.is_success:
            raise AuthError(f"authentication failed: result={result.result!r} "
                            f"msg={result.message or result.reply_message!r}")

        svpnginfo = conn.cookies.get(C.SESSION_COOKIE, svpnginfo)
        if not svpnginfo:
            self._log("warning: no svpnginfo cookie after login")
        self._log("authentication OK")

        # 6) optional EAD host-check ack
        if self.opts.ead:
            conn.post(_path_of(gw.challenge_url), b"hostcheckresult=&ActXisIns=1",
                      ua=C.UA_V7, cookies=True,
                      headers=[("Referer",
                                f"https://{self.opts.host}{_path_of(gw.login_url)}")])

        self.auth = AuthState(conn, version, gw, login_url, svpnginfo, domain_id)
        return self.auth

    # -- captcha + login ---------------------------------------------------
    def _login_once(self, conn: Connection, login_url: str,
                    vld_code: str) -> P.LoginResult:
        xml = P.build_login_xml(
            username=self._full_user(),
            password=self._encode_password(self.creds.password),
            vld_code=vld_code, language=self.opts.language,
            mac=self.opts.mac, private=self._private())
        resp = conn.post(_path_of(login_url), urlencode_body(xml), ua=C.UA_V7,
                         cookies=True)
        return P.parse_login_result(resp.text)

    def _show_captcha(self, image: bytes) -> None:
        from . import captcha as cap
        try:
            _w, _h, rows = cap.decode_bmp(image)
        except Exception:
            return
        sys.stderr.write("[captcha] image:\n" + cap.render_ansi(rows) + "\n")

    def _captcha_login_loop(self, conn: Connection, gw: P.GatewayInfo,
                            login_url: str) -> P.LoginResult:
        """Fetch a captcha, solve it (OCR or manual), submit login; on a
        "Verify code error" rejection fetch a FRESH captcha and retry.  The
        gateway's reply is the success oracle, so this reliably defeats the weak
        captcha without a human when ``auto_captcha`` is on."""
        from . import captcha as cap
        preset = self.vld_code                       # explicit --vldcode
        retries = max(1, self.opts.captcha_retries)
        result: Optional[P.LoginResult] = None
        for attempt in range(retries):
            img = conn.get(_path_of(gw.vldimg_url), ua=C.UA_V7, cookies=True,
                           headers=[("Accept", "*/*")])
            if self.opts.show_captcha:
                self._show_captcha(img.body)
            if preset:
                code = preset
            elif self.opts.auto_captcha:
                code = cap.solve(img.body) or ""
                if code:
                    sys.stderr.write(f"[captcha] OCR solved (try {attempt+1}/"
                                     f"{retries}): {code}\n")
                elif cap.have_solver():
                    # The captcha is single-use with a short TTL; don't waste the
                    # window on a low-confidence read — fetch a fresh image.
                    sys.stderr.write(f"[captcha] try {attempt+1}/{retries}: "
                                     "low-confidence read, refetching\n")
                    continue
                else:
                    sys.stderr.write("[captcha] no OCR (tesseract missing); "
                                     "manual entry.\n")
                    code = self.prompter.captcha(img.body)
            else:
                code = self.prompter.captcha(img.body)

            result = self._login_once(conn, login_url, code)
            if not _is_verify_error(result):
                return result                        # captcha passed (or success)
            sys.stderr.write(f"[captcha] rejected: {result.reply_message!r}\n")
            if preset:
                break                                # a fixed code won't improve
        if result is None:
            raise AuthError(
                f"could not solve the CAPTCHA within {retries} attempts "
                "(OCR produced no confident read; try --no-auto-captcha to enter "
                "it manually, or raise --captcha-retries)")
        return result

    def _run_challenge_loop(self, conn: Connection, gw: P.GatewayInfo,
                            result: P.LoginResult) -> P.LoginResult:
        guard = 0
        while result.is_challenge and guard < 10:
            guard += 1
            ctype = result.ctype or "SMS"
            self._log(f"challenge: type={ctype} msg={result.message!r}")
            if ctype == "CHANGEPWD":
                code = ""
                new_pw = self.creds.new_password or self.prompter.challenge_code(
                    ctype, result.message or "enter new password")
                xml = P.build_challenge_xml(
                    username=self._full_user(), ctype=ctype, code=code,
                    language=self.opts.language,
                    password=self._encode_password(self.creds.password),
                    new_password=self._encode_password(new_pw),
                    vld_code=self.vld_code, mac=self.opts.mac,
                    private=self._private())
            else:
                code = self.prompter.challenge_code(ctype, result.message or
                                                    result.reply_message)
                pw = (self._encode_password(self.creds.password)
                      if ctype == "SMS-IMC" else None)
                xml = P.build_challenge_xml(
                    username=self._full_user(), ctype=ctype, code=code,
                    language=self.opts.language, password=pw,
                    vld_code=self.vld_code, mac=self.opts.mac,
                    private=self._private())
            resp = conn.post(_path_of(gw.challenge_url), urlencode_body(xml),
                             ua=C.UA_V7, cookies=True,
                             headers=[("Referer",
                                       f"https://{self.opts.host}{_path_of(gw.login_url)}")])
            result = P.parse_login_result(resp.text)
        return result

    # -- phase: tunnel -----------------------------------------------------
    def open_tunnel(self) -> tuple[Tunnel, NetworkConfig]:
        if not self.auth:
            raise RuntimeError("authenticate() first")
        if self.opts.zero_trust:
            spa_mod.send_knock(self.opts.host, self.opts.zero_trust)
        tconn = tls_connect(self.opts.host, self.opts.port, self.opts.tls)
        self._log("tunnel: TLS connected, sending NET_EXTEND")
        tconn.request(C.TUNNEL_VERB, "/", ua=C.UA_V7,
                      cookies=f"{C.SESSION_COOKIE}={self.auth.svpnginfo}",
                      read_response=False)
        # The gateway may answer with an HTTP-ish preamble (sometimes carrying
        # the param block as the body) and then raw frames, or raw frames
        # straight away. Strip any preamble, then read the param block frame.
        leftover, pre_cfg = self._read_tunnel_preamble(tconn)
        tun = Tunnel(tconn.sock, tun_fd=None, initial_buffer=leftover,
                     keepalive_max_miss=self.opts.keepalive_max_miss,
                     log=self._log)
        cfg = pre_cfg or tun.wait_netconfig(timeout=20.0)
        if cfg is None or not cfg.is_valid:
            raise AuthError("did not receive a valid network-config frame")
        if cfg.keepalive_time:
            tun.keepalive_interval = max(1.0, float(cfg.keepalive_time))
        self._log(f"tunnel up: ip={cfg.ipaddress} mask={cfg.subnetmask} "
                  f"gw={cfg.gateway} dns={cfg.dns} routes={len(cfg.routes)} "
                  f"keepalive={tun.keepalive_interval:.0f}s")
        return tun, cfg

    def _read_tunnel_preamble(self, tconn: Connection):
        """Consume an optional ``HTTP/1.x`` preamble after NET_EXTEND.

        Returns ``(leftover_frame_bytes, netconfig_or_None)``. If the gateway
        sends the param block as an HTTP body (KEY:value text) it is parsed here;
        otherwise the network-config arrives as a type=3/sub=2 frame and is read
        by ``Tunnel.wait_netconfig``.
        """
        sock = tconn.sock
        buf = bytearray(tconn.take_buffered())
        t0 = time.monotonic()
        while not buf and time.monotonic() - t0 < 10:
            r, _, _ = select.select([sock], [], [], 10)
            if not r:
                break
            buf += sock.recv(65536)
        if bytes(buf[:5]) != b"HTTP/":
            return bytes(buf), None  # raw frame stream
        while b"\r\n\r\n" not in buf and time.monotonic() - t0 < 15:
            r, _, _ = select.select([sock], [], [], 10)
            if not r:
                break
            buf += sock.recv(65536)
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        buf = bytearray(rest)
        cl = _http_content_length(head)
        netcfg = None
        if cl is not None:
            while len(buf) < cl and time.monotonic() - t0 < 20:
                r, _, _ = select.select([sock], [], [], 10)
                if not r:
                    break
                buf += sock.recv(65536)
            body, buf = bytes(buf[:cl]), bytearray(buf[cl:])
            if b"IPADDRESS" in body:
                netcfg = parse_netconfig(body)
        return bytes(buf), netcfg

    def logout(self) -> None:
        if self.auth:
            try:
                self.auth.conn.get(self.auth.gateway.logout_url, ua=C.UA_V7,
                                   cookies=True)
                self._log("logged out")
            except Exception as exc:
                self._log(f"logout request failed (ignored): {exc}")


def _is_verify_error(result: P.LoginResult) -> bool:
    """True when the gateway rejected the login specifically because of a bad
    CAPTCHA (replyMessage "Verify code error") — distinct from a credential
    failure, so we can retry the captcha without retrying the password."""
    return "verify code" in (result.reply_message or "").lower()


def _path_of(url: str) -> str:
    if not url:
        return "/"
    if url.startswith(("http://", "https://")):
        sp = urlsplit(url)
        return sp.path + (("?" + sp.query) if sp.query else "")
    return url if url.startswith("/") else "/" + url


def _http_content_length(head: bytes) -> Optional[int]:
    for line in head.split(b"\r\n"):
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length" and v.strip().isdigit():
            return int(v.strip())
    return None


def _pick_domain(domains: list[P.Domain], hint: str):
    if not domains:
        return None
    if hint:
        for d in domains:
            if d.name.lower() == hint.lower():
                return d
    return domains[0]
