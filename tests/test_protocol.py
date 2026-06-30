from h3csvpn import protocol as P
from h3csvpn import constants as C
from h3csvpn.crypto import urlencode_body


def test_login_xml_field_order():
    xml = P.build_login_xml(username="bob", password="pw", vld_code="9",
                            language="en", mac="AA-BB-CC-DD-EE-FF",
                            private="UFJJVg==")
    order = ["username", "password", "vldCode", "language", "OS",
             "macAddress", "supportChallengePwd", "private"]
    idxs = [xml.index(f"<{t}>") for t in order]
    assert idxs == sorted(idxs), "login XML elements must be in recovered order"
    assert "<password>pw</password>" in xml  # cleartext (Addendum A)


def test_login_body_is_request_urlencoded():
    body = urlencode_body(P.build_login_xml(username="u", password="p"))
    assert body.startswith("request=")
    assert "%3Cdata%3E" in body and "%3Cpassword%3E" in body
    assert "<" not in body and "=" == body[len("request")]  # everything encoded


def test_urlencode_matches_inode_encoder():
    # iNode URLEncoder::Encode (urlencoder.cpp): space -> '+', not %20.
    body = urlencode_body(P.build_login_xml(username="stephan botes",
                                            password="JD2B@yLw8%f9WM"))
    assert "stephan+botes" in body          # space encodes as '+'
    assert "%20" not in body                # never %20
    assert "JD2B%40yLw8%25f9WM" in body     # '@'->%40, '%'->%25 (uppercase)


def test_urlencode_escapes_rfc3986_unreserved():
    # iNode encodes -._~ as %XX (Python's quote would keep them verbatim).
    body = urlencode_body("a-b._c~d")
    assert "a" in body and "b" in body
    assert "%2D" in body and "%2E" in body and "%5F" in body and "%7E" in body


def test_xml_escaping_of_special_chars():
    xml = P.build_login_xml(username="a&b", password="<x>\"'")
    assert "<username>a&amp;b</username>" in xml
    assert "&lt;x&gt;" in xml


def test_challenge_branches():
    sms = P.build_challenge_xml(username="u", ctype="SMS", code="111111")
    assert "<password>" not in sms and "<newPassword>" not in sms

    imc = P.build_challenge_xml(username="u", ctype="SMS-IMC", code="1", password="pw")
    assert "<password>pw</password>" in imc and "<newPassword>" not in imc

    chg = P.build_challenge_xml(username="u", ctype="CHANGEPWD", code="",
                                password="old", new_password="new")
    assert chg.index("<password>old</password>") < chg.index("<newPassword>new</newPassword>")


def test_parse_gatewayinfo():
    gi = P.parse_gatewayinfo(
        "<data><gatewayinfo><auth>"
        "<supportPassword>1</supportPassword><supportvldimg>1</supportvldimg>"
        "<vldimg url='/svpn/image.cgi'/><login>/svpn/vpnuser/check.cgi</login>"
        "<logout>/svpn/logout.cgi</logout>"
        "<challenge>/svpn/vpnuser/check_return.cgi</challenge>"
        "</auth></gatewayinfo></data>")
    assert gi.support_password and gi.support_vldimg
    assert gi.login_url == "/svpn/vpnuser/check.cgi"
    assert gi.challenge_url == "/svpn/vpnuser/check_return.cgi"


def test_parse_domainlist():
    ds = P.parse_domainlist(
        "<data><domainlist>"
        "<domain><name>RADIUS</name><url>/svpn/vpnuser/check.cgi</url></domain>"
        "<domain><name>AD</name><url>/svpn/ad.cgi</url></domain>"
        "</domainlist></data>")
    assert [d.name for d in ds] == ["RADIUS", "AD"]
    assert ds[1].url == "/svpn/ad.cgi"


def test_parse_login_result_states():
    ok = P.parse_login_result("<data><result>Success</result></data>")
    assert ok.is_success and not ok.is_challenge

    ch = P.parse_login_result(
        "<data><result>Challenge</result><type>SMS</type>"
        "<message>code?</message><waitTime>120</waitTime>"
        "<intervaltime>60</intervaltime></data>")
    assert ch.is_challenge and ch.ctype == "SMS"
    assert ch.wait_time == 120 and ch.interval_time == 60
