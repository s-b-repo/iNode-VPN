"""Tests for the corrections/features added after live-testing a real
SSLVPN-Gateway/7.0 (102.134.120.103): the newer gatewayinfo layout, the
persistent captcha settings, and the stdlib BMP decode/segment pipeline."""
import struct

from h3csvpn import captcha as cap
from h3csvpn import protocol as P
from h3csvpn.config import Settings, config_path


# -- gatewayinfo: real (newer) layout --------------------------------------
LIVE_GETINFO = """<data>
  <gatewayinfo>
    <auth>
      <supportPassword>true</supportPassword>
      <supportCert>false</supportCert>
      <supportDKey>false</supportDKey>
      <supportvldimg>true</supportvldimg>
      <supportWechat>false</supportWechat>
    </auth>
    <url>
      <vldimg>/vldimg.cgi</vldimg>
      <login>/_xml/login.cgi</login>
      <logout>/_xml/logout.cgi</logout>
      <checkonline>/_xml/checkonline.cgi</checkonline>
      <challenge>/_xml/login_challenge.cgi</challenge>
    </url>
  </gatewayinfo>
</data>"""

# older layout the RE originally assumed
OLD_GETINFO = """<data><gatewayinfo><auth>
  <supportPassword>1</supportPassword><supportCert>0</supportCert>
  <supportDKey>0</supportDKey><supportvldimg>1</supportvldimg>
  <vldimg url="/svpn/image.cgi"/>
  <login>/svpn/vpnuser/check.cgi</login>
  <logout>/svpn/logout.cgi</logout>
  <challenge>/svpn/vpnuser/check_return.cgi</challenge>
</auth></gatewayinfo></data>"""


def test_gatewayinfo_live_true_false_and_url_block():
    gi = P.parse_gatewayinfo(LIVE_GETINFO)
    assert gi.support_password is True
    assert gi.support_vldimg is True          # 'true' must parse as True
    assert gi.support_cert is False
    assert gi.login_url == "/_xml/login.cgi"   # from the <url> block, not <auth>
    assert gi.vldimg_url == "/vldimg.cgi"
    assert gi.challenge_url == "/_xml/login_challenge.cgi"
    assert gi.logout_url == "/_xml/logout.cgi"


def test_gatewayinfo_old_layout_still_parses():
    gi = P.parse_gatewayinfo(OLD_GETINFO)
    assert gi.support_password is True and gi.support_vldimg is True
    assert gi.vldimg_url == "/svpn/image.cgi"   # url= attribute form
    assert gi.login_url == "/svpn/vpnuser/check.cgi"


# -- persistent captcha settings -------------------------------------------
def test_settings_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert config_path().startswith(str(tmp_path))
    s = Settings(auto_captcha=False, captcha_retries=3, show_captcha=False)
    s.save()
    loaded = Settings.load()
    assert loaded.auto_captcha is False
    assert loaded.captcha_retries == 3
    assert loaded.show_captcha is False


def test_settings_defaults_when_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    s = Settings.load()
    assert s.auto_captcha is True and s.captcha_retries >= 1


# -- stdlib BMP decode + segmentation --------------------------------------
def _make_bmp(width, height, pixels):
    """Build a minimal 24-bit bottom-up BMP. pixels[y][x] = (r,g,b), y=0 top."""
    row_size = ((24 * width + 31) // 32) * 4
    body = bytearray()
    for y in range(height - 1, -1, -1):       # bottom-up
        row = bytearray()
        for x in range(width):
            r, g, b = pixels[y][x]
            row += bytes((b, g, r))
        row += b"\x00" * (row_size - len(row))
        body += row
    pix_off = 54
    fsize = pix_off + len(body)
    hdr = b"BM" + struct.pack("<IHHI", fsize, 0, 0, pix_off)
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0,
                      len(body), 2835, 2835, 0, 0)
    return bytes(hdr + dib + body)


def test_bmp_decode_roundtrip_and_segment():
    # 12x6 white image with two 2px-wide black bars (two "glyphs") separated by
    # a gap -> decode must recover colours and _segment must find 2 bands.
    W, H = 12, 6
    px = [[(255, 255, 255)] * W for _ in range(H)]
    for y in range(1, 5):
        for x in (2, 3):       # glyph 1
            px[y][x] = (10, 10, 10)
        for x in (8, 9):       # glyph 2
            px[y][x] = (10, 200, 10)
    data = _make_bmp(W, H, px)

    w, h, rows = cap.decode_bmp(data)
    assert (w, h) == (W, H)
    assert rows[0][0] == (255, 255, 255)        # top-left is white
    assert rows[2][2] == (10, 10, 10)           # glyph-1 ink recovered
    assert rows[2][8] == (10, 200, 10)          # glyph-2 (green) recovered

    grid = cap._denoise(cap._ink_grid(rows), min_blob=2)
    bands = cap._segment(grid)
    assert len(bands) == 2                       # two separated glyphs

    ansi = cap.render_ansi(rows)
    assert "▀" in ansi                           # produced a half-block preview
