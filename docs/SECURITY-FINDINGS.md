# Security findings — H3C iNode protocols & this client

This document records security issues found while reverse-engineering the H3C
iNode protocols for interoperability and while auditing this client's own code.
It has two parts:

1. **Protocol-design weaknesses in H3C's protocols** — these are properties of
   the *vendor* protocols (recovered from the original client's libraries). They
   are reported here for defenders; this project does not "exploit" them, though
   a faithful interop client necessarily interacts with them.
2. **Implementation issues in this client** — bugs in our own backend/helpers,
   with the status of each (fixed / accepted / documented).

No live third-party systems were tested to produce this document; the protocol
facts come from static analysis of the licensed client's unstripped libraries.

---

## Part 1 — H3C protocol-design weaknesses

### P1. EAD posture is forgeable — endpoint admission defense bypass (Critical)

The standalone iMC **EAD "SEC" posture** protocol (UDP/9019) seals its posture
report with **no real signature**. Reverse-engineering `libInodeSecurityAuth.so`
shows the only integrity seal is:

- a **keyed-MD5** checksum over the packet plus a **hardcoded seed string**
  (`SC-EAD_Server$REQ&ShareKey@9019`), and
- an optional **static XTEA** body cipher with a **hardcoded key**.

Both values are **constant across every client and every session** — there is no
per-session nonce, no per-user key, and no asymmetric signature. Consequently:

- Any party that knows the (now-recovered, constant) seed can build a posture
  report the server accepts, declaring the host fully **compliant** regardless of
  its true state. A non-compliant or hostile endpoint can pass admission control.
- The lack of a per-session nonce makes captured posture packets **replayable**.

**Impact:** EAD/posture enforcement provides no security guarantee against a
client that chooses not to cooperate. It is a configuration/visibility control,
not a security boundary. Defenders should not rely on EAD posture as the sole
gate for sensitive network segments.

### P2. Portal authenticator relies on a weak/shared secret — auth & logout forgery (High)

H3C Portal packets (standard v2 and the H3C dialect) authenticate with
`MD5(packet-with-auth-field-zeroed ‖ shared_secret)` — plain MD5, not HMAC. The
shared secret is a **deployment-wide constant** that very frequently defaults to
well-known strings (`h3c`, `huawei3com`). Where the secret is weak or known:

- An attacker can **forge a `LOGOUT` for any user's IP**, deauthenticating
  arbitrary users (denial of service), since logout packets are keyed the same
  way and carry the victim IP in the header.
- An attacker can forge auth/affirm packets.
- The CHAP password attribute is `MD5(reqId ‖ password ‖ challenge)`, which is
  **offline-crackable** from a single captured exchange.

There is no strong replay protection beyond the serial/request IDs.

**Impact:** Portal access control and accounting integrity depend entirely on the
secrecy and strength of a shared secret that is often neither.

### P3. SDP/SPA knock is replayable (Medium)

The Zero-Trust **SPA single-packet-authorization knock** (recovered from
`libZeroTrust.so`) authenticates with an RFC-4226 HOTP, but the HOTP **counter is
a random value that is transmitted in the packet** (as the byte-swapped
`pktID`). There is no monotonic counter and no time window, so the only secret is
the per-client `clientKey`. Therefore:

- A captured knock can likely be **replayed** to re-open the gateway's "closed"
  port, undermining the core SDP premise that the port is invisible without a
  valid knock (unless the gateway separately tracks seen packet IDs).
- The `clientKey`/`aid` are cached on disk at `/etc/spa/spa_cfg.cnf`; if that
  file is readable by other local users, knocks become forgeable.

### P4. SSL VPN: cleartext credentials behind weak default TLS trust (High)

The SSL VPN sends the password **cleartext inside TLS** (only URL-encoded /
XML-escaped). That is safe *only if TLS is properly verified*. In practice H3C
gateways ship **self-signed certificates** (e.g. `CN=HTTPS-Self-Signed-…`, no
SAN), so:

- Default CA validation fails, pushing users toward disabling verification —
  which exposes the password to a trivial **man-in-the-middle**.
- Any deployment that runs the original client with verification off is leaking
  credentials to anyone on-path.

**Mitigation in this client:** per-profile **SHA-256 certificate pinning** (the
correct way to trust a self-signed gateway). Use it instead of disabling
verification. See `--pin-sha256` / the GUI "Cert pin" field.

### P5. Obscurity-based "crypto" (Low / informational)

Local config/credential storage and the SPA/posture seals use **hardcoded keys**,
**ECB-mode XTEA** (no IV), and **MD5**. These provide obfuscation, not
cryptographic protection; anyone with the (now-published) constants can
reproduce them. Treat anything protected only by these as plaintext.

---

## Part 2 — Implementation issues in this client (and status)

| # | Severity | Issue | Status |
|---|----------|-------|--------|
| C1 | **Critical** | CAPTCHA BMP decoder OOM (the observed SIGKILL/137) | **Fixed** |
| C2 | High | Tunnel frame-reassembly buffer had no cap (slow OOM) | **Fixed** |
| C3 | Medium | Root helper loaded python from an unvalidated `--backend` (root RCE) | **Fixed** |
| C4 | Low | Cert-pin comparison was not constant-time | **Fixed** |
| C5 | High | Pinned TLS connections also lower cipher SECLEVEL to 0 | **Accepted (compat)** |
| C6 | Medium | `inode-l2tp-helper` still accepts secrets on argv | **Documented** |
| C7 | Medium | Gateway-pushed routes/DNS applied with light validation | **Documented** |

### C1 — CAPTCHA BMP decoder out-of-memory (Fixed) — *this is the crash you hit*

`captcha.py:decode_bmp()` read `width`/`height` straight from the BMP header
(attacker-controlled) and allocated a `width × height` matrix of Python tuples
(~72 bytes each) **before** validating them against the actual payload size. A
gateway — or an on-path attacker when verification is off — could serve a tiny
BMP declaring enormous dimensions (e.g. `40000×40000` ⇒ ~100 GB), and the kernel
**OOM-killer** terminated the process (`Killed … exited with code 137`). This is
reached automatically on the default login path (`show_captcha`/`auto_captcha`
both default on), so it needs no user interaction and no authentication.

**Fix:** `decode_bmp` now bounds the declared dimensions (`≤ 4096` per side,
`≤ 1,048,576` pixels) and verifies the declared pixel array fits within the body
before allocating; both callers already degrade gracefully on the resulting
`ValueError` (skip preview / fall back to manual captcha entry).

### C2 — Tunnel reassembly buffer cap (Fixed)

`FrameDecoder.feed()` appended every received chunk to an internal buffer and
only drained complete frames; a gateway dribbling partial frames that never
complete could grow it without bound (a slower memory-exhaustion DoS). A single
frame can never exceed `FRAME_HEADER_LEN + 65535`, so the buffer is now capped at
`MAX_FRAME_BUFFER` (1 MiB) and a stalled/garbage stream raises instead of
growing.

### C3 — Privileged-helper backend path (Fixed)

`inode-svpn-helper` runs as root via pkexec and imports python from the caller's
`--backend` directory. It now canonicalizes the path, refuses
transient/world-writable locations (`/tmp`, `/var/tmp`, `/dev/shm`, `/run`,
`/proc`), and **refuses any backend that is group/other-writable**, so a
malicious `h3csvpn/` cannot be planted and loaded as root. (A root-ownership
requirement was deliberately avoided because the portable package legitimately
runs from the user's own home directory.)

### C4 — Constant-time pin compare (Fixed)

The SHA-256 certificate-pin check now uses `hmac.compare_digest`. (Pins are not
secret, so this is hardening, not a real timing oracle.)

### C5 — SECLEVEL=0 on pinned connections (Accepted — compatibility)

When a cert pin is set, the backend also lowers OpenSSL's cipher security level
to 0. In principle a pinned connection should keep modern ciphers; in practice
the gateways that *need* pinning (old, self-signed) are the same ones that
require legacy ciphers to connect at all, and the trust decision already rests on
the exact-cert pin. Lowering SECLEVEL is therefore an intentional
**compatibility** tradeoff for these legacy gateways, not a verification bypass.
Documented rather than changed to avoid breaking real connectivity. Plain
`--insecure` (no pin, no verification) remains opt-in and warned about.

### C6 — L2TP secrets on argv (Documented)

`inode-l2tp-helper` accepts the PSK/password via `--secrets-stdin` (preferred)
but still also accepts `--psk`/`--password` on argv, where they would be visible
in `ps`/`/proc` while the root helper runs. The GUI uses the stdin path; the argv
options remain for manual CLI use. Prefer `--secrets-stdin`.

### C7 — Gateway-pushed routes/DNS (Documented)

A VPN gateway can push routes and DNS servers; in full-tunnel mode a malicious
gateway can redirect host traffic/DNS. This is partly inherent to the VPN trust
model. The default **split-tunnel** mode mitigates it (only the gateway's own
subnets are routed). Route CIDRs / DNS entries are passed to `ip`/`resolv.conf`
as argv (no shell injection), but ideally each should be regex-validated as a
well-formed IP/CIDR before use (as `inode-ipcfg-helper` already does).

---

## Not vulnerabilities (reviewed, OK)

- **XML parsing** prefers `defusedxml` and otherwise rejects `<!DOCTYPE`/
  `<!ENTITY>` before parsing — no XXE / billion-laughs.
- **HTTP layer** caps Content-Length, chunk sizes and chunk count.
- No `eval`/`pickle`; settings load filters JSON keys to known fields.
- Temp files use `mkstemp` (0600, O_EXCL) or root-only `/etc` atomic writes.
- The SSL VPN password is cleartext-in-TLS by protocol design (P4), protected by
  TLS when verification/pinning is enabled — not a client bug.
