"""h3c-svpn — an open-source, clean-room interoperable client for the
H3C iNode SSL VPN ("V7") protocol.

Reverse-engineered from the H3C iNode 7.3 Linux client; see ``docs/PROTOCOL.md``.
This is an independent interoperability implementation and is not affiliated with
or endorsed by H3C / New H3C Technologies.
"""
from __future__ import annotations

__version__ = "0.1.0"

from .constants import *  # noqa: F401,F403
from .session import (  # noqa: F401
    SslVpnSession, Credentials, Options, Prompter, AuthError,
)
from .transport import TLSConfig  # noqa: F401
from .protocol import (  # noqa: F401
    build_login_xml, build_challenge_xml,
    parse_gatewayinfo, parse_domainlist, parse_login_result,
)
from .tunnel import (  # noqa: F401
    encode_frame, FrameDecoder, NetworkConfig, parse_netconfig, Tunnel,
)
from . import crypto, spa  # noqa: F401
