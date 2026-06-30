"""XML message builders/parsers for the H3C iNode SSL VPN V7 protocol.

The client serialises every request as a ``<data>...</data>`` document built
with a vendored TinyXML.  **Element order is significant** (the gateway parses
positionally on some firmwares), so the builders emit children in the exact
order recovered from ``FormatLoginXML`` / ``FormatChallengeAuthXML``
(``SslVpnXmlParser.cpp``).  We build the XML by hand to guarantee that order and
to match the client byte-for-byte; we parse responses leniently with ElementTree.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from . import constants as C
from .safexml import fromstring as _safe_fromstring


# --------------------------------------------------------------------------
# building
# --------------------------------------------------------------------------
def _el(tag: str, value: str = "", attrs: Optional[dict] = None) -> str:
    a = "".join(f' {k}="{escape(str(v))}"' for k, v in (attrs or {}).items())
    if value == "" and not attrs:
        return f"<{tag}></{tag}>"
    return f"<{tag}{a}>{escape(str(value))}</{tag}>"


def build_login_xml(*, username: str, password: str, vld_code: str = "",
                    language: str = "cn", os_name: str = C.OS_FIELD,
                    mac: str = "", support_challenge_pwd: str = "1",
                    private: str = "") -> str:
    """``FormatLoginXML`` — _VPNLogInPacketInfoV7.

    Emission order (exact): username, password, vldCode, language, OS,
    macAddress, supportChallengePwd, private.  The password is cleartext
    (URL-encoding is applied later to the whole document) — see Addendum A.
    """
    parts = [
        _el("username", username),
        _el("password", password),
        _el("vldCode", vld_code),
        _el("language", language),
        _el("OS", os_name),
        _el("macAddress", mac),
        _el("supportChallengePwd", support_challenge_pwd),
        _el("private", private),
    ]
    return f"<{C.XML_ROOT}>" + "".join(parts) + f"</{C.XML_ROOT}>"


def build_challenge_xml(*, username: str, ctype: str, code: str,
                        language: str = "cn", password: Optional[str] = None,
                        new_password: Optional[str] = None, vld_code: str = "",
                        os_name: str = C.OS_FIELD, mac: str = "",
                        private: str = "") -> str:
    """``FormatChallengeAuthXML`` — _VPNCahllengeAuthPacketInfo.

    Always: username, type, code, language.  Then branch on ``type``:
      * SMS-IMC   -> add <password>
      * CHANGEPWD -> add <password> (old) then <newPassword> (new)
    All paths then append: vldCode, OS, macAddress, private.
    """
    parts = [
        _el("username", username),
        _el("type", ctype),
        _el("code", code),
        _el("language", language),
    ]
    if ctype == "SMS-IMC":
        parts.append(_el("password", password or ""))
    elif ctype == "CHANGEPWD":
        parts.append(_el("password", password or ""))
        parts.append(_el("newPassword", new_password or ""))
    parts += [
        _el("vldCode", vld_code),
        _el("OS", os_name),
        _el("macAddress", mac),
        _el("private", private),
    ]
    return f"<{C.XML_ROOT}>" + "".join(parts) + f"</{C.XML_ROOT}>"


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def _text(root: ET.Element, path: str, default: str = "") -> str:
    el = root.find(path)
    return (el.text or "").strip() if el is not None else default


@dataclass
class GatewayInfo:
    """Capabilities parsed from ``<data><gatewayinfo><auth>`` (GetVpnConnInfo)."""
    support_password: bool = True
    support_cert: bool = False
    support_dkey: bool = False
    support_vldimg: bool = False
    vldimg_url: str = C.PATH_IMAGE
    login_url: str = C.PATH_LOGIN_V7
    logout_url: str = C.PATH_LOGOUT
    challenge_url: str = C.PATH_CHALLENGE_V7


def _flag(el: ET.Element, tag: str, default: str) -> bool:
    """A capability flag. Firmwares disagree on the encoding: older builds use
    ``1``/``0``, the live SSLVPN-Gateway/7.0 uses ``true``/``false``."""
    v = _text(el, tag, default).strip().lower()
    return v in ("1", "true", "yes", "on")


def parse_gatewayinfo(xml: str) -> GatewayInfo:
    """Parse ``<data><gatewayinfo>`` from ``/client_getinfo.cgi`` (or the older
    inline form). Two firmware layouts are handled:

    * **newer** (live SSLVPN-Gateway/7.0): flags are ``true``/``false`` under
      ``<auth>``; URLs live in a sibling ``<url>`` block as element *text*
      (``<login>/_xml/login.cgi</login>``, ``<vldimg>/vldimg.cgi</vldimg>``).
    * **older** (RE assumption): flags ``1``/``0`` and URLs as ``<auth>`` children
      with ``vldimg`` carrying the path in a ``url=`` attribute.
    """
    root = _safe_fromstring(xml)
    auth = root.find(".//gatewayinfo/auth")
    url = root.find(".//gatewayinfo/url")
    if auth is None:
        auth = root  # some firmwares omit the wrapper
    gi = GatewayInfo()
    if auth.find("supportPassword") is not None:
        gi.support_password = _flag(auth, "supportPassword", "1")
    gi.support_cert = _flag(auth, "supportCert", "0")
    gi.support_dkey = _flag(auth, "supportDKey", "0")
    gi.support_vldimg = _flag(auth, "supportvldimg", "0")

    # URLs: prefer the dedicated <url> block, fall back to <auth> children/attrs.
    src = url if url is not None else auth
    vimg = src.find("vldimg")
    if vimg is not None:
        gi.vldimg_url = (vimg.get("url") or (vimg.text or "").strip()
                         or gi.vldimg_url)
    gi.login_url = _text(src, "login", gi.login_url) or gi.login_url
    gi.logout_url = _text(src, "logout", gi.logout_url) or gi.logout_url
    gi.challenge_url = _text(src, "challenge", gi.challenge_url) or gi.challenge_url
    return gi


@dataclass
class Domain:
    name: str
    url: str


def parse_domainlist(xml: str) -> list[Domain]:
    root = _safe_fromstring(xml)
    out: list[Domain] = []
    for d in root.findall(".//domainlist/domain"):
        out.append(Domain(name=_text(d, "name"), url=_text(d, "url")))
    if not out:  # tolerate flat <domain> children
        for d in root.findall(".//domain"):
            out.append(Domain(name=_text(d, "name"), url=_text(d, "url")))
    return out


@dataclass
class LoginResult:
    """``<data>`` login/challenge response (GetLogInInfo / parseAuthRespMsgV7)."""
    result: str = ""
    reply_message: str = ""
    emo_server: str = ""
    ctype: str = ""
    message: str = ""
    sms_dynamic_pwd: bool = False
    wait_time: int = 0
    interval_time: int = 0
    raw: str = ""

    @property
    def is_success(self) -> bool:
        return self.result == C.RESULT_SUCCESS

    @property
    def is_challenge(self) -> bool:
        if self.is_success:
            return False
        return self.result == C.RESULT_CHALLENGE or self.ctype in C.CHALLENGE_TYPES


def parse_login_result(xml: str) -> LoginResult:
    root = _safe_fromstring(xml)

    def _int(path: str) -> int:
        try:
            return int(_text(root, path, "0") or "0")
        except ValueError:
            return 0

    return LoginResult(
        result=_text(root, "result"),
        reply_message=_text(root, "replyMessage"),
        emo_server=_text(root, "EMOServer"),
        ctype=_text(root, "type"),
        message=_text(root, "message"),
        sms_dynamic_pwd=_text(root, "smsDynamicPwdd", "0") == "1",
        wait_time=_int("waitTime"),
        interval_time=_int("intervaltime"),
        raw=xml,
    )
