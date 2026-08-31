# h3c-svpn — open-source H3C iNode SSL VPN client

A clean-room, interoperable client for the **H3C iNode SSL VPN ("V7")** protocol
used by H3C SecPath / F1000-class gateways. It speaks the same wire protocol as
the proprietary H3C *iNode Intelligent Client*, but is a small, readable,
dependency-light Python implementation you can audit and extend.

The protocol was reverse-engineered from the (unstripped, DWARF-bearing) Linux
iNode 7.3 client. The full specification lives in **[`docs/PROTOCOL.md`](docs/PROTOCOL.md)**
— it is implementation-grade (exact CGI paths, XML field order, cookies, frame
byte-layout, TUN/route/DNS programming, and the Zero-Trust SPA knock).

> **Interoperability / legal note.** This is an independent interoperability
> implementation produced by analysing software the author lawfully possesses,
> in the tradition of OpenConnect and similar projects. It is **not affiliated
> with, endorsed by, or supported by H3C / New H3C Technologies**. "H3C" and
> "iNode" are trademarks of their respective owners. Use it only against
> gateways you are authorised to access.

---

## Status

| Capability | State |
|---|---|
| Capability discovery (`/svpn/index.cgi` → `/client_getinfo.cgi`, gatewayinfo) | ✅ implemented (handles `true/false` flags + `<url>` block) |
| Password login (cleartext-in-TLS, the standard V7 path) | ✅ implemented |
| CAPTCHA (validation image) | ✅ **auto-solved** (`--auto-captcha`, OCR + retry) or manual; terminal preview |
| Challenge / 2FA (SMS, SMS-IMC, PROMPTPWD, CHANGEPWD) | ✅ implemented |
| Kick concurrent session / EAD host-check ack | ✅ implemented |
| `NET_EXTEND` tunnel, 4-byte framing, heartbeat | ✅ implemented |
| Virtual NIC (TUN), routes, DNS | ✅ implemented (Linux, needs root) |
| Zero-Trust SPA knock (HOTP) | ✅ packet builder (SDP registration is out of scope) |
| Optional mutual TLS (client cert) | ✅ PEM client cert |
| GM / SM2 (CNTLS / SKF UKey) gateways | ❌ not supported (TLS-layer only; noted limitation) |
| Validated end-to-end against the bundled **mock gateway** | ✅ passing tests |
| Validated against a **live** `SSLVPN-Gateway/7.0` | ✅ discovery + CAPTCHA + login reached; see `docs/CAPTCHA.md` |

The client was validated against a faithful **mock gateway**
(`mock/mock_gateway.py`) and then against a **live** `SSLVPN-Gateway/7.0`, which
revealed the real capability layout (`/client_getinfo.cgi`, `true/false` flags,
`<url>` block) — now handled — and a weak CAPTCHA, analysed in
**[`docs/CAPTCHA.md`](docs/CAPTCHA.md)**. The CAPTCHA is auto-solved by
`h3csvpn/captcha.py` (stdlib BMP decode + ANSI terminal preview + optional
`tesseract` OCR); `--auto-captcha` / `--no-auto-captcha` is a persisted toggle.

---

## Install

The core client is **pure Python 3.9+ stdlib** — no install needed to try it:

```bash
git clone <this repo> && cd h3c-svpn
python -m h3csvpn --help
```

Recommended extras (hardened XML, RSA mode, tests):

```bash
pip install -r requirements-dev.txt   # defusedxml, cryptography, pytest
# or:  pip install .[secure,rsa,test]
```

`defusedxml` is auto-used if present (the client falls back to a built-in
DTD/entity guard otherwise).

---

## Usage

```bash
# Authenticate only (no tunnel, no root needed) — great for a first test:
python -m h3csvpn vpn.example.com -u alice -d RADIUS --no-tunnel -v

# Full connection (creates a TUN device; needs root):
sudo python -m h3csvpn vpn.example.com:443 -u alice -d RADIUS

# Show the exact login request this client would send (no connection):
python -m h3csvpn vpn.example.com -u alice -p 'pw' --dry-run
```

Password sources (in order): `-p/--password`, `$H3C_SVPN_PASSWORD`, interactive prompt.

### Trusting the gateway certificate (TLS)

Many H3C gateways ship a private/self-signed certificate. Pick the **secure**
option:

```bash
# 1) Best: pin the gateway certificate fingerprint (no CA needed, MITM-safe):
python -m h3csvpn vpn.example.com -u alice --pin-sha256 AB:CD:...:EF

# 2) Or verify against a CA bundle you trust:
python -m h3csvpn vpn.example.com -u alice --cafile gateway-ca.pem

# 3) Last resort (UNSAFE, prints a warning): disable verification entirely:
python -m h3csvpn vpn.example.com -u alice --insecure
```

Get a gateway's pin with:
`openssl s_client -connect host:443 </dev/null 2>/dev/null | openssl x509 -fingerprint -sha256 -noout`.

### Useful flags

`--domain/-d` auth domain · `--vldcode` CAPTCHA answer · `--ead` send host-check ack ·
`--client-cert` mutual-TLS PEM · `--rsa-pubkey` firmware RSA-password variant ·
`--min-tls 1.0|1.2` · `--ifname` TUN name template · `--no-tunnel` · `-v/-vv` verbose.

---

## How it works (module map)

```
h3csvpn/
  constants.py   all recovered protocol constants/enums (cited to the binary)
  protocol.py    XML builders/parsers (exact field order; TinyXML-compatible)
  crypto.py      url-encoding, <private> blob, RFC-4226 HOTP, optional RSA
  safexml.py     XXE/entity-hardened XML parsing of untrusted responses
  httpclient.py  minimal HTTP/1.1 over a (TLS) socket: cookies, redirects, chunked
  transport.py   TLS setup: verify / CA / fingerprint-pin / client cert
  tunnel.py      4-byte frame codec, network-config parser, heartbeat, TUN<->TLS pump
  vnic.py        TUN device (ioctl) + routes/DNS via `ip` + resolv.conf
  spa.py         Zero-Trust SPA single-packet-authorization knock (HOTP)
  session.py     end-to-end orchestration (auth -> challenge -> tunnel)
  cli.py         command-line interface
mock/mock_gateway.py   a fake H3C V7 gateway for offline end-to-end testing
docs/PROTOCOL.md       the full reverse-engineered protocol specification
```

The connection flow (`docs/PROTOCOL.md` §2): *(optional SPA knock)* → TLS →
`GET /svpn/index.cgi` → parse capabilities/domains → *(CAPTCHA)* →
`POST request=<urlencoded login XML>` → *(challenge/2FA loop)* → kick-old →
`NET_EXTEND` on a fresh TLS socket → network-config frame → program TUN/routes/DNS
→ raw IP packets in 4-byte frames + 1 s heartbeat → `GET /svpn/logout.cgi`.

---

## Testing

```bash
python -m pytest                  # 32 tests: protocol, crypto, framing, e2e mock
python -m mock.mock_gateway --port 4443 --challenge   # run the mock standalone
```

The end-to-end tests stand up the mock gateway over TLS and drive the real
client through auth (incl. CAPTCHA and SMS challenge), the `NET_EXTEND` tunnel,
network-config parsing, and a data-frame round trip — all without root.

The SPA HOTP is checked against the **official RFC 4226 test vectors**.

---

## Security notes

* TLS verification is **on by default**; `--insecure` is opt-in and warns loudly.
  Prefer `--pin-sha256` for self-signed gateways.
* Gateway responses are untrusted: XML parsing is hardened against XXE /
  entity-expansion (`defusedxml` when available, else a DTD/entity guard).
* On the standard V7 path the password is sent **cleartext inside the TLS
  channel** (confirmed by RE — see `docs/PROTOCOL.md` Addendum A); confidentiality
  relies entirely on TLS, so don't use `--insecure` with real credentials.

## Limitations / TODO

* GM/SM2 (CNTLS, SKF USB-Key) gateways are not supported.
* Zero-Trust SPA requires SDP registration (`/api/terminal/...`) to obtain the
  per-client key/aid; only the knock packet builder is implemented.
* Linux only (TUN + `ip`). The protocol is OS-agnostic; ports welcome.
* IPv6 split-tunnel and MTU application are best-effort (see spec §6.5/§6.6).
