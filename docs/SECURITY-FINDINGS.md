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
| C8 | High | `inode-l2tp-helper`: newline injection into root configs via `--server`/`--username`/PSK | **Fixed** |
| C9 | Medium | `inode-svpn-helper stop` signalled the bare pidfile PID (PID-reuse kill) | **Fixed** |
| C10 | Medium | `secrets.enc` written world-readable (umask-dependent 0644) | **Fixed** |
| C11 | Low | `inode-ipcfg-helper` accepted out-of-range octets (`999.1.1.1`) | **Fixed** |
| C12 | High | GPG backend: bare `gpg --decrypt` (empty stdin) + `QFile::rename` no-overwrite → only the first credential ever persisted | **Fixed (review)** |

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

### C8 — L2TP helper config injection (Fixed)

`inode-l2tp-helper` interpolates caller-supplied values into root-owned config
files with heredocs. `--server` landed verbatim in `ipsec.conf` (`right=${SERVER}`),
`--username` in `/etc/ppp/chap-secrets`, and the PSK inside `ipsec.secrets`
quoting (`: PSK "${PSK}"`). A value containing newlines could inject arbitrary
directives into these root-trusted configs (e.g. extra `conn` blocks), and a PSK
containing `"` broke the secrets-file quoting.

**Fix:** `up` now validates `--server` against hostname/IPv4/IPv6-in-brackets
grammar, rejects control characters in server/username/psk/password, and refuses
a PSK containing `"` or `\` (strongSwan has no escape for either). The `down`
path (which only needs `--name`) is unaffected.

### C9 — PID-reuse on SSL VPN teardown (Fixed)

`inode-svpn-helper stop` read the bare PID from `/run/inode-svpn/<name>.pid` and
signalled it. If the backend had crashed and the PID was recycled by an
unrelated process, teardown would SIGINT/SIGKILL that innocent process (and it
runs as root, so root-owned processes were reachable). The pidfile directory is
root-only (0700), so the pidfile itself could not be forged, but stale entries
after a crash were realistic.

**Fix:** `stop` now reads `/proc/<pid>/cmdline` and only signals processes whose
cmdline contains `h3csvpn`; anything else is reported as a stale pidfile and
left alone.

### C10 — Encrypted credential file permissions (Fixed)

`EncryptedFileStore` persisted `secrets.enc` through QSettings, which writes
with the process umask — commonly 0644 on single-user assumptions. The file
holds only ciphertext, but the header (salt + verifier) is offline-cracking
material that no other local user should see, and future entry contents may be
more sensitive.

**Fix:** every sync point now clamps the file to 0600 (`syncAndHarden()`), and
write failures surface as a failed `store()` instead of a silent success.
The GPG backend's `secrets.gpg` is written via `mkstemp` + atomic rename with
the same 0600 clamp.

### C11 — IP-config helper octet validation (Fixed)

`inode-ipcfg-helper` validated IPs with `^[0-9]{1,3}(\.[0-9]{1,3}){3}$`,
accepting octets above 255 (`999.999.999.999`) and prefix 0. `ip` itself
rejects these, but the failure surfaced late and confusingly (after
`resolv.conf` had possibly been rewritten in the `apply` path).

**Fix:** strict per-octet 0–255 check, rejection of leading-zero octets
(`010.1.1.1` would be parsed as **octal** 8.1.1.1 by iproute2's `inet_aton`
fallback — silently programming a different address than the user typed), and
`10#`-base parsing for the prefix, all before any system mutation.

### C12 — GPG backend write-path defects (Fixed in review)

Found by end-to-end in-process testing (external CLI tests masked both):

- `gpg --decrypt` was invoked **without the file argument**, i.e. decrypting
  empty stdin — the first `store()` (no file yet) succeeded, then every
  lookup/clear/update silently failed forever after.
- `QFile::rename` **refuses to overwrite an existing target** on Qt6 — every
  write after the first failed on the temp→final rename. Replaced with
  `std::filesystem::rename` (POSIX rename(2): atomic replace).

Both would have made the GPG backend appear to work while persisting only the
first credential ever written. Also fixed in review: a lost-update race
(mutateStore is decrypt→modify→re-encrypt; now serialized with a mutex and a
non-recursive-safe clear path), a stale cached recipient failing all writes
after a mid-session key rotation (now re-probes and falls back to symmetric),
and L2TP/`svpn-connect` argument hardening (whitespace rejection; empty-array
expansion under `set -u` on old bash).

---

## Credential-at-rest model (updated)

Saved profile credentials are stored by the **first available** backend, in
priority order — the active one is shown by `iNodeClient-Qt --doctor`:

1. **KWallet** (KF6 build) — unlocked by the login session via PAM.
2. **freedesktop Secret Service** — gnome-keyring / ksecretd / KeePassXC.
3. **System GnuPG** (`gpgstore`) — entries sealed to the user's default GPG
   secret key (`--trust-model always`, agent + pinentry own the passphrase;
   this app never sees it), or symmetric via pinentry when no key exists.
   Stored as an atomic-replaced, 0600 ASCII-armored blob at
   `~/.config/iNodeClient-Qt/secrets.gpg`. This is the recommended backend for
   users who already run a PGP keyring.
4. **AES-256-GCM + PBKDF2 (200k, SHA-256) master-password file** — last resort
   when no keyring/gpg exists; 0600, master password never touches disk.

All backends refuse to write plaintext: with no backend usable, `store()`
fails rather than persisting a secret.

---

## Not vulnerabilities (reviewed, OK)

- **XML parsing** prefers `defusedxml` and otherwise rejects `<!DOCTYPE`/
  `<!ENTITY>` before parsing — no XXE / billion-laughs.
- **HTTP layer** caps Content-Length, chunk sizes and chunk count.
- No `eval`/`pickle`; settings load filters JSON keys to known fields.
- Temp files use `mkstemp` (0600, O_EXCL) or root-only `/etc` atomic writes.
- The SSL VPN password is cleartext-in-TLS by protocol design (P4), protected by
  TLS when verification/pinning is enabled — not a client bug.
