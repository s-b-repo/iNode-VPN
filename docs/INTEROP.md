# Interop & live-gateway validation guide

`h3c-svpn` is validated end-to-end against the bundled **mock gateway**. The
items below are the things that can only be pinned down against a **real** H3C
gateway, plus exactly how to capture and check them. They map to
`PROTOCOL.md` §9 (open questions / test plan).

## 1. Capture a real session (ground truth)

The fastest way to validate everything is one TLS-decrypted capture of the real
iNode client connecting to your gateway.

* **Option A — `SSLKEYLOGFILE`.** Run the official iNode client with
  `SSLKEYLOGFILE=/tmp/keys.log` set, capture with `tcpdump -i any -w h3c.pcap port 443`,
  then in Wireshark set *TLS → (Pre)-Master-Secret log filename* to `keys.log`.
* **Option B — MITM proxy.** Put `mitmproxy`/`burp` in front with a CA the test
  host trusts; the iNode client must accept the MITM cert (may require disabling
  cert pinning on the client side, often not enforced for the gateway cert).

From that capture, extract and diff against this client:

| What to confirm | Where in this client |
|---|---|
| login POST body is exactly `request=<percent-encoded XML>` | `crypto.urlencode_body`, `--dry-run` |
| `<password>` is the **cleartext** password (not RSA/base64) | `session._encode_password` (Addendum A) |
| login XML field set/order for your firmware | `protocol.build_login_xml` |
| `<private>` blob bytes (we send empty) | `crypto.make_private_blob` |
| `macAddress` format (`AA-BB-CC-DD-EE-FF` vs `:` vs `H;`) | `--mac` / `Options.mac` |
| `language` value (`cn`/`CN`/`en`/`EN`/`1`) | `--language` |
| domain-list fetch URL + cookie | `session.authenticate` (best-effort; adjust if it differs) |
| `NET_EXTEND` response: HTTP preamble? then frames? param block text vs binary | `session.open_tunnel`, `tunnel.wait_netconfig` |
| frame header endianness + type/subtype numbers | `tunnel.encode_frame` / `FrameDecoder` |
| heartbeat bytes + interval + miss threshold | `tunnel.Tunnel._heartbeat_loop` |

## 2. Step-by-step bring-up

```bash
# 1. capability probe + auth only (no root):
python -m h3csvpn <gw> -u <user> -d <domain> --no-tunnel -vv --pin-sha256 <pin>

#    -> confirms TLS, version sentinel, gatewayinfo parse, login round-trip.
#    If login fails with a credentials error but you KNOW they're right, your
#    firmware may want RSA-encrypted passwords: re-try with --rsa-pubkey <key>.

# 2. full tunnel (root):
sudo H3C_SVPN_PASSWORD=... python -m h3csvpn <gw> -u <user> -d <domain> -vv --pin-sha256 <pin>
#    -> creates inode0, programs IP/routes/DNS; ping an intranet host.
```

## 3. Known "validate-live" items (and safe defaults we ship)

1. **Password encoding** — we send cleartext-in-TLS (RE-confirmed, Addendum A).
   If your gateway rejects it, capture the real login: if you see
   `base64(...)` in `<password>` and a public key advertised, use `--rsa-pubkey`.
2. **`<private>` blob** — shipped empty; accepted by the gateways we modelled.
   If rejected, capture the real blob and extend `crypto.make_private_blob`.
3. **`NET_EXTEND` framing of the param block** — we read it as a `type=3/sub=2`
   frame whose payload is the `KEY:value` text block. Some firmwares may send the
   block as the HTTP body before frames begin; `open_tunnel` should be checked
   against your capture (see `PROTOCOL.md` §6.5, OQ#4).
4. **SPA HOTP digit count** — 6 by default; if a Zero-Trust knock is rejected,
   try `SpaConfig(digits=5)` (`PROTOCOL.md` §5.6, OQ#6).
5. **macAddress / language formatting** — defaults `AA-BB-CC-DD-EE-FF` / `cn`.

## 4. What is intentionally out of scope

* GM/SM2 (CNTLS) TLS and SKF USB-Key client auth.
* Zero-Trust SDP registration (`/api/terminal/...`) that issues the per-client
  SPA key/aid — only the knock packet builder is provided.
* Windows/macOS virtual-NIC plumbing (the protocol is OS-agnostic; only the
  `vnic.py` layer is Linux-specific).
