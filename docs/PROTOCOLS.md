# Protocol implementation status & roadmap

## 802.1X (iNode port id 8021) — ✅ working

Implemented in `src/protocols/Dot1xProtocol.cpp` as a thin wrapper around `minieap` (or `mentohust` as fallback). Both are open-source community reimplementations of the HC-CHAPv2 variant that H3C's `libInodeX1Pt.so` speaks.

The wrapper exposes the full knob set the original client offers through its "Advanced" panel:
- auth mode (PAP / CHAP / MSCHAPv2 / EAP-MD5 / EAP-PEAP / HC-CHAPv2)
- rjv3 on/off, service type, carrier string
- heartbeat (`-r` for minieap, `-t` for mentohust)
- arbitrary extra args (free-form) — useful for the campus-specific flags some iMC builds require

**IP addressing:** 802.1X only authenticates the port — the supplicant brings no
address of its own. The profile's *IP mode* (Advanced tab) is applied right after
auth succeeds: **Inherit** leaves the OS as-is, **DHCP** triggers a renew, and
**Static** programs the address / netmask / gateway / DNS via the privileged
`inode-ipcfg-helper` (polkit `org.inode.ClientQt.ipcfg`). It is torn down on
disconnect. The same applies to WLAN (which wraps the 802.1X plugin).

**Known limitations:**
- Campus deployments with custom iNode hash salts may require passing extra `--rjv3` flags through *Extra args*. Capture a successful auth from the original client and compare if the default profile doesn't work.
- `libInodeX1Pt.so` also implements H3C's "智能感知" (smart re-auth) heartbeat — `minieap` covers it for the common case, but some server builds expect a client-hello frame minieap doesn't send.

## WLAN (iNode port id 1100) — ✅ working

Wireless 802.1X in `src/protocols/WlanProtocol.cpp`:

1. `nmcli device wifi connect <ssid> password <pw> ifname <iface>` — hands association to NetworkManager, which is the only supplicant that plays nicely with WPA3/802.11w on modern distros.
2. Once associated, the Dot1x plugin runs the same 802.1X flow as the wired case on the now-connected `wlanX` interface.

If the profile's SSID field is empty, the plugin falls back to plain 802.1X (useful for pre-associated setups).

## L2TP/IPSec (port 2401) — ✅ working against RFC-compliant servers

Uses system `strongswan` + `xl2tpd`. The GUI writes fragment configs under `/etc/ipsec.conf.d/` and `/etc/xl2tpd/xl2tpd.conf.d/` through the polkit helper (`scripts/inode-l2tp-helper`). `forceencaps=yes` can be toggled per-profile for concentrators that always require UDP encap on 4500. The PSK and password are streamed to the helper on **stdin** (`--secrets-stdin`), never passed as command-line arguments, so they never appear in `ps`/`/proc`.

**Where it won't work:** iMC/EIA deployments that require H3C's proprietary IKE vendor ID exchange or custom phase-2 transforms. Those need custom strongswan plugin work or a userspace IKE implementation — not trivial, but out of scope here.

## Portal v2 — ✅ working

Implemented natively in `src/protocols/PortalProtocol.cpp`. Full state machine: REQ_CHALLENGE → ACK_CHALLENGE → REQ_AUTH → ACK_AUTH → AFF_ACK_AUTH, plus a timer-driven keep-alive and REQ_LOGOUT on disconnect. MD5-keyed checksum uses the per-profile shared secret (defaults to `h3c` if unset).

Each iMC Portal deployment ships with:
- a shared secret (typical defaults: `h3c`, `huawei3com`, `portalsecret`),
- a UDP port (2000 is default; some deployments use 50100),
- a dialect switch (v2 vs H3C-TLV).

The **v2 standard** dialect is on the wire here. The **H3C TLV** dialect is now wired up experimentally — see below.

## H3C Portal (proprietary dialect) — 🧪 experimental (faithful framing, untested)

**Wire protocol reference:** `libInodePortalPt.so` (unstripped + DWARF) in the
original client, fully reverse-engineered. **Correction to earlier notes:** the
H3C dialect is *not* "Portal v2 plus a `0x0A` user-mac TLV". In this binary
`0x0A` is `ATTR_PORTAL_BAS_IP`, and `0x0F`/`0x13` are not wire attributes at all.
The dialect is a **separate proprietary protocol** sharing only the 32-byte
header and MD5 authenticator with v2.

**What was recovered (and implemented in `PortalProtocol`, dialect == 1):**

- **Private opcode space** (header byte +1): `LOGIN_REQUEST=0x64`,
  `LOGIN_RESPONSE=0x65`, `LOGOUT_REQUEST=0x66`, `HANDSHAKE`(heartbeat)`=0x68`,
  `DOMAIN_REQUEST=0x6E`, `NTF_USERDISCOVER=0x74`, `HASH_RESPONSE=0x7A` — not the
  standard `0x01–0x07`.
- **Header:** version-driven size (v1=16, **v2=32**, v3=48); v2 = 16-byte base +
  16-byte authenticator at +0x10. Big-endian numerics.
- **Authenticator:** `MD5(packet-with-auth-field-zeroed ‖ shared_secret)` (plain
  MD5, not HMAC) written into +0x10 — same algorithm v2 already used here.
- **TLV:** `Type(1) | Length=ValueLen+2 (1) | Value`; body cap 1352 B.
- **Attributes:** `BAS_IP=0x0A`, `RELAY(version/ip-config base64)=0x21`,
  `ENCRYPT_ENABLE=0x38`, `USER_NAME=0x65`, `USER_PASSWORD=0x66`,
  `PRIVATE_IP=0x67` (16-byte blob), `PUBLIC_IP=0x68` (16-byte blob),
  `START_TIME=0x71` (4-byte BE). Login attr order: `0x21 → 0x67 → 0x68 → 0x65 →
  0x66 → 0x38 → 0x71`.
- **Anti-track hash challenge:** server sends attr `0x82` (encrypted hash key);
  client must return a 32-byte value in attr `0x83` (opcode `0x7A`). The digest
  is a function-code-dispatched MD5 (`CalculateHashValue`, "anti track") that was
  **not fully recovered** — `PortalProtocol::replyH3cHashChallenge()` answers
  best-effort (`MD5(key‖secret)` padded to 32 B) and logs a warning; a strict BAS
  will reject it.

**Status.** `PortalProtocol` (dialect == 1) now sends a real H3C
`LOGIN_REQUEST(0x64)` with the correct attributes/header/authenticator, runs a
`HANDSHAKE(0x68)` keep-alive, and tears down with `LOGOUT_REQUEST(0x66)`. This is
**best-effort and untested against a live H3C Portal** (we have none). Remaining
unknowns needing a packet capture: the exact `0x21` relay-blob struct, the
PAP/CHAP password encoding switch (PAP plaintext is sent), the anti-track hash
digest, and the numeric values of the RESPONSE/CHALLENGE opcodes (only the
REQUEST builders hardcode constants in the binary).

## SSL VPN (port 7000) — ✅ working (via the bundled `h3csvpn` backend)

**Wire protocol reference:** `libiNodeSslvpnPt.so` (SslVpnXmlParser.cpp, SslvpnMgr.cpp, HttpsAuth.cpp) in the unstripped Linux iNode 7.3 client. The protocol was reverse-engineered first-hand and is **not** the speculative `POST /svpn/login` JSON flow earlier guessed here — it is XML-over-HTTPS ("V7").

**How it's implemented.** Rather than re-deriving the wire format in C++, `SslVpnProtocol` drives a bundled clean-room backend — the pure-Python `h3csvpn` package under `backends/h3csvpn/` — exactly as the 802.1X plugin wraps `minieap` and the L2TP plugin wraps `strongswan`. The backend was reverse-engineered from the binary above and validated end-to-end against a live `SSLVPN-Gateway/7.0`.

Flow (`backends/h3csvpn`; full spec in `docs/PROTOCOL.md` of the h3c-svpn source tree):

1. *(optional SPA knock)* → TLS → `GET /svpn/index.cgi` → **302 → `/client_getinfo.cgi`**; parse the `gatewayinfo` (capability flags `true`/`false`, CGI URLs in a `<url>` block, domain list).
2. *(optional CAPTCHA)* `GET /vldimg.cgi` → BMP; the backend OCR-solves it (`tesseract`) and auto-retries against the server's reply oracle.
3. `POST <login.cgi>` body `request=` + URL-encoded `<data>` login XML (username `user@domain`, password cleartext-in-TLS by default, or RSA/SM2 variants) → challenge/2FA loop (SMS, PROMPTPWD, CHANGEPWD), kick-concurrent-session, optional EAD ack.
4. `NET_EXTEND` on a fresh TLS socket → network-config block → program a TUN device + routes + DNS → raw IP packets in 4-byte frames with a 1 s heartbeat → `GET /svpn/logout.cgi` on teardown. The live `SSLVPN-Gateway/7.0` returns the param block in the **HTTP response headers** (`IPADDRESS`/`SUBNETMASK`/`ROUTES`/`GATEWAY`, with `Content-Length: 0`), and `SUBNETMASK` is a prefix length (e.g. `24` = `/24`); the backend parses both that header form and the older body/frame forms.

**Split tunnel (enterprise).** By default the client routes only the subnets the gateway pushes (`ROUTES`) through the VPN and leaves the host default route + system DNS untouched, so general internet traffic is unaffected. The per-profile *Split tunnel* toggle (CLI `--split-tunnel`) enforces this even if a gateway requests redirect-all. The test gateway used during development pushes specific corporate subnets and no DNS, so it is naturally split. Verified end-to-end: with the tunnel up, the host default route and `/etc/resolv.conf` are unchanged, public internet stays reachable directly, and the corporate subnets are reachable through `inode0`.

**Integration plumbing.** Because the tunnel needs `CAP_NET_ADMIN`, the GUI launches the backend through `scripts/inode-svpn-helper` via `pkexec` (polkit action `org.inode.ClientQt.svpn`), or directly if already root. The password is streamed on the helper's **stdin** (never in argv/`ps`); `PYTHONSAFEPATH=1` pins module resolution to the vendored backend. `disconnect()` runs `inode-svpn-helper stop`, which `SIGINT`s the backend for a clean gateway logout + TUN teardown. The Qt layer parses backend output to drive connection state and live stats (interface / IP / DNS).

**Profile mapping.** `serverHost[:serverPort]` (or the SSL VPN *Gateway URL*) → gateway; `username`/`domain` → `-u`/`-d`; trust mode → system CA (default) / `--cafile` (Pinned, from `caCertPath`) / `--insecure` (None); a per-profile **SHA-256 cert pin** (with a one-click *Fetch* button) → `--pin-sha256`, which **overrides** the trust mode — the correct, secure way to trust a self-signed gateway whose cert CN doesn't match the host (so a CA bundle can't validate it); `userCertPath` → mutual-TLS client cert.

**Runtime deps:** `python3` (stdlib only for the core), `tesseract` for CAPTCHA OCR, `pkexec`/polkit for the tunnel. Optional `python3-defusedxml` (hardened XML) and `python3-cryptography` (RSA password variant).

**Limitations (inherited from the backend):** GM/SM2 (CNTLS / SKF UKey) gateways are TLS-layer-only (unsupported); Zero-Trust SDP registration that issues the per-client SPA key is out of scope (only the knock builder exists).

## EAD (port 9019) — 🧪 host-check ack done; standalone posture **implemented** (untested vs live iMC)

**Wire protocol reference:** `libInodeSecurityAuth.so` (`CreatePkt` @0x45cd0, `VerifyPkt` @0x44450, `PushSecurityResult` @0x46250).

**What works now.** The **SSL VPN EAD host-check acknowledgement** — tick *“Send EAD host-check acknowledgement after login”* on an SSL VPN profile (backend `--ead`); the client posts the host-check result after authentication. Verified against the live `SSLVPN-Gateway/7.0` (auth still succeeds with it on). Note: the original client sends this only on the legacy **V3** path and skips it on V7, so it is usually a no-op on modern gateways — harmless either way.

**Standalone iMC EAD posture (UDP/9019) — revised verdict: not crypto-blocked.** Earlier this doc said the posture blob was signed by a key inside the closed collector and was unreproducible. Reverse-engineering `libInodeSecurityAuth.so` shows that is **wrong**: the SEC posture packet carries **no RSA/HMAC/SHA signature**. It is sealed only by:

- a **RADIUS-style keyed-MD5** over (packet with a zeroed 16-byte checksum field at `+0x6` ‖ seed), with the **hardcoded** seed string `SC-EAD_Server$REQ&ShareKey@9019` (DIF/917T transport variant: `DIF-SERVER$RPT&CheckSum@917T`); and
- an optional **static XTEA** body cipher (Δ `0x9E3779B9`, 32 rounds, ECB) with the **hardcoded** key `g_arruiKey = {0x95632125, 0x74256318, 0x36752015, 0x67825319}` (`.data` @0x2df8d0).

> Both seals are **constant across all clients and sessions** (recovered from `libInodeSecurityAuth.so`). **Correction:** `libwacollector.so` is OPSWAT's **OESIS V4** collector, and the RSA/AES/cert material embedded in it is for OPSWAT's *own* module/cache integrity — it is **not** used to sign the H3C posture report. So there is no vendor signing key gating this at all.

Both seals are constant across all clients/sessions (no per-session derivation), so a clean-room client can build a valid `SEC_CHECK_RESULT` the server accepts.

**Now implemented** in `EadProtocol` (pure Qt/C++, UDP, no privileges — same shape as `PortalProtocol`). Recovered and built faithfully:

- **Header (28 bytes), confirmed against `CreatePkt` @0x45cd0 / `SecDataProcess` @0x72320:** `ulPktHeadId` = wire bytes `00 0A D8 77` (+0); `usPktHeadLen` u16 **big-endian** (+4); `checkSum[16]` (+6); `pktId` u32 **big-endian** (+22, correlator); **opcode** u16 **big-endian** (+26) — the message type lives here, *not* in `ulPktHeadId`; body at +28.
- **Checksum:** `MD5(packet-with-16-byte-cksum-zeroed ‖ "SC-EAD_Server$REQ&ShareKey@9019")` (31-byte seed, no NUL) written back at +6.
- **Body:** `<?xml version="1.0" encoding="UTF-8"?><msg><ver></ver><content><data> … <i n="NAME">value</i> … </data></content></msg>`. Each `*checkResult` field **empty == pass** (the binary only appends a fault token on failure). `EadProtocol::buildPostureXml()` emits a compliant posture plus identity (`userName/hwAddr/ipAddr/hostname/osType/OSInfo/OSKernelVersion/arch/clientVersion`).
- **State machine:** `SEC_START(1)` (carrying the posture) → on `SEC_CHECK_LIST(2)` resend as `SEC_CHECK_RESULT(3)` → `SEC_CHCK_SUCCESS(4)` ⇒ connected + `SEC_HEARTBEAT(17)` keep-alive, or `SEC_CHECK_FAIL(6)` ⇒ fail; `SEC_OFFLINE(19)` on disconnect. Opcodes confirmed against `PacketMatching` @0x445c0.
- **Body cipher:** ECB-XTEA (Δ `0x9E3779B9`, 16 rounds, body key `{0x35469812,0x83479025,0x23192486,0x36615829}` — distinct from the general `g_arruiKey`) is **only** negotiated for later, post-handshake packets. `GetPktEncryType` returns 0 (no encryption) for the initial handshake, so `EadProtocol` sends **unencrypted** bodies and does not implement the cipher.

**Untested** against a live iMC EIA server (we have none). Remaining unknowns: exact `*exception` literal values, server-supplied heartbeat/monitor intervals (defaults assumed), and whether a deployment mandates body encryption mid-session. The SSL VPN host-check above remains the verified path.

## SDP (port 19006) — 🧪 experimental (SPA knock + SSL VPN)

SDP (software-defined perimeter) is, in H3C's stack, an **SSL VPN preceded by a Single-Packet-Authorization (SPA) knock** that opens the otherwise-closed gateway port. That is now wired up: an **SDP** profile (or any SSL VPN profile with the *SPA key/AID/ports* filled in) sends the RFC-4226-HOTP knock — `backends/h3csvpn/spa.py`, validated 47-byte packet — before the TLS/auth flow (`--spa-key/--spa-aid/--spa-ports/--spa-knock-port`).

Verified against `libZeroTrust.so` (`onKnockUDPMsg` @0x22630, `generateOTP` @0x1bd70): packet is `declaredLen=0x0110` (written **native little-endian** → bytes `10 01`) · `aid[32]` (raw string bytes) · `pktID=bswap(rand)` · `password[6]` · `portCount` · ports (htons); fire-and-forget UDP to **hardcoded dst port 8000** (`knockPort` is a separate packet field). Register port 19006 / knock 59993 are **config-supplied**, not constants in this binary.

- **Password = `generateOTP(clientKey, counter, digits=5, addLuhn=1)`**: HMAC-SHA1 over an **8-byte big-endian counter**, RFC-4226 dynamic truncation, `mod 100000` (5 digits) **+ 1 Luhn check digit** ⇒ 6 ASCII digits. **Correction:** the counter is a **random** value (`(int)rand()`), *not* time- or event-based; the **same `rand()`** value is byte-swapped to form `pktID`, so the gateway recovers the counter from `pktID`. (`spa.py` already produces byte-identical output: a random `pkt_id` packed big-endian on the wire and fed to HOTP as the counter.)

**Out of scope:** the SDP **registration** that mints the per-client `clientKey`/`aid`. Per `AssemblePwdAuthReq` @0x19160 / `ParsePwdAuthResp` @0x1e2a0 it rides on the first auth: `POST https://<gw>/api/terminal/pc/userLogin` with JSON carrying **10 fields** — `userAccount, userPassword, clientSn, clientMac, clientAid, clientPrivate, clientVersion, clientSrcIp, clientOSInfo, clientOsType` (last is an int); the response `data.clientAid`/`data.clientKey` (and `firstAuthToken`) are cached in `/etc/spa/spa_cfg.cnf` as `SdpAid-<ip>`/`SdpKey-<ip>`. Reproducible structurally but needs valid gateway credentials — supply the AID/key from an enrolled client.
