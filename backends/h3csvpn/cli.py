"""Command-line interface for h3c-svpn."""
from __future__ import annotations

import argparse
import getpass
import os
import socket
import sys

from . import __version__
from . import constants as C
from .config import Settings, config_path
from .session import SslVpnSession, Credentials, Options, AuthError
from .transport import TLSConfig
from .tunnel import Tunnel
from . import vnic as vnic_mod


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="h3c-svpn",
        description="Open-source interoperable client for the H3C iNode SSL VPN.")
    p.add_argument("gateway", help="gateway host or host:port")
    p.add_argument("-u", "--user", required=True, help="username")
    p.add_argument("-p", "--password", help="password (prompted if omitted)")
    p.add_argument("-d", "--domain", default="", help="auth domain name")
    p.add_argument("--port", type=int, default=C.DEFAULT_PORT)
    p.add_argument("--mac", default="", help="override MAC reported to gateway")
    p.add_argument("--language", default="cn", choices=["cn", "en"])
    p.add_argument("--vldcode", default="", help="CAPTCHA answer (if known)")

    cap = p.add_argument_group(
        "captcha",
        "CAPTCHA auto-solve / auto-retry. These flags persist to "
        f"{config_path()} so the toggle state is remembered across runs.")
    cap.add_argument("--auto-captcha", dest="auto_captcha", action="store_true",
                     default=None, help="OCR-solve the captcha and auto-retry "
                     "on 'Verify code error' (persisted toggle)")
    cap.add_argument("--no-auto-captcha", dest="auto_captcha",
                     action="store_false",
                     help="disable auto-solve; prompt for the captcha manually")
    cap.add_argument("--captcha-retries", dest="captcha_retries", type=int,
                     default=None, metavar="N",
                     help="max fresh-captcha attempts (persisted)")
    cap.add_argument("--show-captcha", dest="show_captcha", action="store_true",
                     default=None, help="render the captcha image in the "
                     "terminal each attempt (persisted toggle)")
    cap.add_argument("--no-show-captcha", dest="show_captcha",
                     action="store_false", help="do not draw the captcha image")

    tls = p.add_argument_group("TLS")
    tls.add_argument("--cafile", help="CA bundle to verify the gateway cert")
    tls.add_argument("--pin-sha256", help="pin the gateway cert SHA-256 "
                     "(secure way to trust a self-signed gateway)")
    tls.add_argument("--insecure", action="store_true",
                     help="disable TLS verification (UNSAFE; prefer --pin-sha256)")
    tls.add_argument("--client-cert", help="client cert PEM for mutual TLS")
    tls.add_argument("--client-key", help="client key PEM (if separate)")
    tls.add_argument("--min-tls", choices=["1.0", "1.2"], default=None)

    adv = p.add_argument_group("advanced")
    adv.add_argument("--rsa-pubkey", help="PEM/DER RSA pubkey -> encrypt password "
                     "(firmware variant; default is cleartext-in-TLS)")
    adv.add_argument("--ead", action="store_true",
                     help="send an empty EAD host-check result after login")
    adv.add_argument("--ifname", default=C.IFNAME_TEMPLATE,
                     help="TUN interface name template")
    adv.add_argument("--no-tunnel", action="store_true",
                     help="authenticate only; do not bring up the tunnel")
    adv.add_argument("--dry-run", action="store_true",
                     help="print the login request body and exit (no connection)")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--version", action="version", version=f"h3c-svpn {__version__}")
    return p


def _split_host(gateway: str, default_port: int) -> tuple[str, int]:
    if gateway.startswith(("http://", "https://")):
        from urllib.parse import urlsplit
        sp = urlsplit(gateway)
        return sp.hostname or gateway, sp.port or default_port
    if ":" in gateway and gateway.count(":") == 1:
        h, _, port = gateway.partition(":")
        # Reject CR/LF in hostname to prevent HTTP header injection
        h = h.replace("\r", "").replace("\n", "")
        if not h:
            raise ValueError(f"empty host in {gateway!r}")
        return h, int(port)
    gw = gateway.replace("\r", "").replace("\n", "")
    if not gw:
        raise ValueError(f"empty host in {gateway!r}")
    return gw, default_port


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    host, port = _split_host(args.gateway, args.port)

    password = args.password or os.environ.get("H3C_SVPN_PASSWORD")
    if password is None and not args.dry_run:
        password = getpass.getpass("Password: ")
    creds = Credentials(username=args.user, password=password or "",
                        domain=args.domain)

    if args.dry_run:
        from . import protocol as P
        from .crypto import urlencode_body
        xml = P.build_login_xml(username=creds.username, password=creds.password,
                                language=args.language, mac=args.mac)
        print("POST", "<loginURL>", "HTTP/1.1")
        print(f"User-Agent: {C.UA_V7}")
        print(f"Content-Type: {C.FORM_CONTENT_TYPE}")
        print()
        print(urlencode_body(xml))
        return 0

    rsa = None
    if args.rsa_pubkey:
        with open(args.rsa_pubkey, "rb") as f:
            rsa = f.read()

    tls = TLSConfig(
        verify=not args.insecure,
        cafile=args.cafile,
        pin_sha256=args.pin_sha256,
        client_cert=args.client_cert,
        client_key=args.client_key,
        min_tls=args.min_tls,
    )
    if args.insecure and not args.pin_sha256:
        sys.stderr.write("[!] WARNING: TLS verification disabled (--insecure). "
                         "This exposes you to MITM. Prefer --pin-sha256.\n")

    # CAPTCHA settings: load persisted toggle, apply any CLI override, re-persist.
    settings = Settings.load()
    changed = False
    if args.auto_captcha is not None:
        settings.auto_captcha = args.auto_captcha; changed = True
    if args.show_captcha is not None:
        settings.show_captcha = args.show_captcha; changed = True
    if args.captcha_retries is not None:
        settings.captcha_retries = max(1, args.captcha_retries); changed = True
    if changed:
        settings.save()
        sys.stderr.write(f"[config] saved captcha settings to {config_path()} "
                         f"(auto_captcha={settings.auto_captcha}, "
                         f"retries={settings.captcha_retries}, "
                         f"show_captcha={settings.show_captcha})\n")

    opts = Options(host=host, port=port, language=args.language, mac=args.mac,
                   tls=tls, rsa_pubkey=rsa, ead=args.ead,
                   auto_captcha=settings.auto_captcha,
                   captcha_retries=settings.captcha_retries,
                   show_captcha=settings.show_captcha)

    # Zero-Trust / SDP: read SPA key from env var (H3C_SPA_KEY) so it never
    # appears in argv/ps. Set by the Qt GUI via QProcessEnvironment.
    spa_key = os.environ.get("H3C_SPA_KEY", "")
    if spa_key:
        import binascii
        from .spa import SpaConfig
        def _unhex(s: str) -> bytes:
            return binascii.unhexlify(s.replace(":", "").replace(" ", "")) if s else b""
        try:
            ports = tuple(int(p) for p in os.environ.get("H3C_SPA_PORTS", "443").split(",")
                          if p.strip()) or (C.SPA_AUTH_PORT,)
            opts.zero_trust = SpaConfig(
                aid=_unhex(os.environ.get("H3C_SPA_AID", "")),
                client_key=_unhex(spa_key), ports=ports)
            sys.stderr.write(f"[SPA] Zero-Trust knock enabled (ports={ports})\\n")
        except (binascii.Error, ValueError) as exc:
            sys.stderr.write(f"[x] invalid SPA env value: {exc}\\n")
            return 2

    def log(msg: str) -> None:
        sys.stderr.write(msg + "\n")

    sess = SslVpnSession(creds, opts, vld_code=args.vldcode,
                         log=log if args.verbose else (lambda m: None))
    try:
        sess.authenticate()
    except AuthError as exc:
        sys.stderr.write(f"[x] {exc}\n")
        return 2
    except OSError as exc:
        sys.stderr.write(f"[x] connection error: {exc}\n")
        return 2

    if args.no_tunnel:
        print("Authentication succeeded (--no-tunnel).")
        sess.logout()
        return 0

    try:
        tun, cfg = sess.open_tunnel()
    except AuthError as exc:
        sys.stderr.write(f"[x] tunnel setup failed: {exc}\n")
        sess.logout()
        return 3

    if not vnic_mod.have_root():
        sys.stderr.write("[x] tunnel needs root (CAP_NET_ADMIN) to create the "
                         "TUN device. Re-run with sudo, or use --no-tunnel.\n")
        sess.logout()
        return 4

    try:
        server_ip = socket.gethostbyname(host)
    except OSError:
        server_ip = None

    nic = vnic_mod.VirtualNIC(name_template=args.ifname)
    try:
        nic.open()
        nic.configure(cfg, server_ip=server_ip)
        tun.tun_fd = nic.fd
        print(f"[+] Connected. interface={nic.ifname} ip={cfg.ipaddress} "
              f"dns={','.join(cfg.dns) or '-'}. Ctrl-C to disconnect.")
        tun.run()
    except KeyboardInterrupt:
        print("\n[+] disconnecting...")
    finally:
        tun.stop()
        nic.close()
        sess.logout()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
