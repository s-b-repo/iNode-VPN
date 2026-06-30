"""End-to-end: drive the real client against the mock gateway over TLS."""
import threading
import time

import pytest

from h3csvpn.session import SslVpnSession, Credentials, Options, Prompter, AuthError
from h3csvpn.transport import TLSConfig
from mock.mock_gateway import MockGateway, MockConfig


@pytest.fixture
def gateway():
    gw = MockGateway("127.0.0.1", 0, MockConfig()).start()
    time.sleep(0.05)
    yield gw
    gw.stop()


def _opts(gw, **kw):
    # trust the mock via certificate fingerprint pinning (no --insecure needed)
    tls = TLSConfig(verify=False, pin_sha256=gw.cert_fingerprint_sha256(),
                    server_hostname="localhost")
    return Options(host="127.0.0.1", port=gw.port, tls=tls, **kw)


class FixedPrompter(Prompter):
    def __init__(self, code="654321", captcha="1234"):
        self._code, self._captcha = code, captcha

    def captcha(self, image):
        return self._captcha

    def challenge_code(self, ctype, message):
        return self._code


def test_auth_success(gateway):
    sess = SslVpnSession(Credentials("alice", "secret"), _opts(gateway))
    st = sess.authenticate()
    assert st.svpnginfo
    sess.logout()


def test_auth_bad_password(gateway):
    sess = SslVpnSession(Credentials("alice", "WRONG"), _opts(gateway))
    with pytest.raises(AuthError):
        sess.authenticate()


def test_auth_with_captcha():
    gw = MockGateway("127.0.0.1", 0, MockConfig(require_captcha=True)).start()
    time.sleep(0.05)
    try:
        # exercises the manual prompter path (auto OCR off)
        sess = SslVpnSession(Credentials("alice", "secret"),
                             _opts(gw, auto_captcha=False),
                             prompter=FixedPrompter())
        st = sess.authenticate()
        assert st.svpnginfo
    finally:
        gw.stop()


def test_auth_with_sms_challenge():
    gw = MockGateway("127.0.0.1", 0,
                     MockConfig(require_challenge=True, challenge_code="654321")).start()
    time.sleep(0.05)
    try:
        sess = SslVpnSession(Credentials("alice", "secret"), _opts(gw),
                             prompter=FixedPrompter(code="654321"))
        st = sess.authenticate()
        assert st.svpnginfo
    finally:
        gw.stop()


def test_tunnel_netconfig_and_data_echo(gateway):
    sess = SslVpnSession(Credentials("alice", "secret"), _opts(gateway))
    sess.authenticate()
    tun, cfg = sess.open_tunnel()
    assert cfg.ipaddress == "10.8.0.5"
    assert cfg.gateway == "10.8.0.1"
    assert cfg.dns == ["10.8.0.1"]
    assert cfg.routes == ["192.168.50.0/24"]

    got = []
    ev = threading.Event()

    def on_data(payload):
        got.append(payload)
        ev.set()

    tun.on_data = on_data
    runner = threading.Thread(target=tun.run, daemon=True)
    runner.start()
    try:
        pkt = bytes.fromhex("4500001c000040004001") + b"PINGPING"
        tun.send_ip(pkt)
        assert ev.wait(5), "did not receive echoed data frame"
        assert got[0] == pkt
        assert tun.bytes_out >= len(pkt) and tun.bytes_in >= len(pkt)
    finally:
        tun.stop()
        runner.join(timeout=2)
    sess.logout()
