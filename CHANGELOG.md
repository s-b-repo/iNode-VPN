# Changelog

All notable changes to the iNode Client (Qt edition) are documented here.
This project loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.3.0] — 2026-09-09

Bug-fix, hardening and resource-usage release; GPG credential backend removed.

### Documentation
- New **docs/TROUBLESHOOTING.md**: every message `deploy.sh`, the privileged
  helpers, the GUI and the SSL VPN backend can produce, with cause and fix,
  organised by stage (install → launch → credentials → polkit → SSL VPN →
  CAPTCHA → tunnel/DNS → 802.1X/WLAN → L2TP → Portal/EAD/SDP → reconnect/UI
  → update → logs & files). README, INSTALL, USAGE, PROTOCOLS and INTEROP
  link into it; the backend README's dead links (docs/mock/tests that are
  not shipped) are fixed and it documents the exit codes.

### Fixed (error reporting — so the fixes above are reachable)
- Backend: a bad gateway string (`:443`, `gw:abc`, empty) and an over-long
  `--ifname` are usage errors (exit 2) instead of tracebacks; a certificate
  verification failure prints the exact `openssl` pin command and the
  `--pin-sha256`/`--cafile` fix; `--rsa-pubkey` without `cryptography` or
  an unreadable key file exits 2 cleanly; unreadable/unsafe gateway XML is
  reported as "gateway sent an unreadable response" (exit 2); a missing
  `ip` command or `/dev/net/tun` is named with the package/modprobe fix
  (exit 5) instead of a raw errno; a non-interactive 2FA prompt says so;
  a failed `resolv.conf` backup says DNS was left unchanged.
- GUI: L2TP/IPSec bring-up failure, an 802.1X rejection or early supplicant
  exit, and a failed Wi-Fi association now emit a message (they set
  *Failed* silently before). The auto-reconnect "permanent error" heuristic
  also recognises gateway verdicts (`auth rejected`, `login rejected`,
  `posture rejected`), missing tools/helpers, privilege denials and the
  SSL VPN exit-2 fallback, so those no longer burn the retry budget.

### Fixed (GUI)
- **`--status` did nothing and `--disconnect` never reached the running
  client**: `--status` was parsed but unhandled (it just opened a second
  window) and `--disconnect` ran in a fresh process with nothing to
  disconnect. A per-user local control socket (`$XDG_RUNTIME_DIR/
  iNodeClient-Qt-<uid>.sock`, mode 0700) now links a running instance and
  later invocations: `--status` prints `<state>\t<profile>[\t<iface ip>]`
  (exit 0 connected, 2 idle, 3 not running), `--disconnect` tears the
  session down (exit 3 if nothing runs), `--connect <name>` is forwarded to
  the running instance, and a plain second launch raises the existing window
  instead of starting a duplicate. Both flags work headless.
- **"No stored password for profile."** on the first connect: new profiles
  had *Store password* unticked, so a typed password was silently dropped
  and every protocol that needs one refused to start. New profiles now
  store by default; a password typed with the box unticked is kept for the
  session; and whenever nothing is stored the GUI **asks at connect time**
  (with a *Remember* option) instead of failing. A keyring that refuses to
  store now produces a visible warning instead of nothing.
- `CredentialStore` gained a session-only in-memory overlay (never written
  to disk) that `retrieve()` consults first; `store()` logs its failures.

### Fixed (build / install)
- **Fresh `git clone` on umask 002 systems** (Debian/Kali user-private
  groups) left every file in `backends/h3csvpn` group-writable, so the root
  helper refused all SSL VPN connects in portable mode ("backend is
  group/other-writable"). `deploy.sh` now runs with `umask 022`, tightens
  `backends/` + `scripts/` on every build and verifies the result; CMake
  installs the backend copy with explicit 644/755 permissions.
- Root-owned leftovers from a one-time `sudo ./deploy.sh` (`build/`,
  `bin/`) made every later user run fail with "Permission denied";
  `deploy.sh` detects foreign-owned files and chowns them back (one sudo
  prompt), warns when itself run via sudo and hands `build/`/`bin/` back to
  the invoking user, and refuses up front on a non-writable checkout with
  the exact fix.
- **Build was broken**: `CredentialStore::ensureLegacyMigration()` was declared
  `static` but called a non-static member — every fresh checkout failed to
  compile. (The GPG-store migration is now a plain member function.)
- `--doctor`, `--version`, `--help` and `--list-profiles` aborted with
  "no Qt platform plugin could be initialized" on a headless box / over SSH
  (the last step of `deploy.sh` crashed in a TTY). Text-only entry points
  now fall back to the offscreen platform when no display is reachable.
- Version string is taken from CMake (`INODE_VERSION`) — `--version` printed
  0.2.0 while the docs already described v0.3.
- Portable mode: the root helper refused every SSL VPN connect on trees
  checked out with `umask 002` or after any user-side `python3 -m h3csvpn`
  run left a group-writable `__pycache__` behind. `deploy.sh --local` now
  tightens `backends/` + `scripts/` (new `--fix-perms` too), the CLI wrapper
  no longer writes bytecode into the tree, and the helper's refusal message
  names the fix.
- `--doctor` reported the polkit action as `ok` for a policy under
  `/usr/local/share`, which polkit never scans; it now checks the canonical
  `/usr/share/polkit-1/actions` and prints what to do.

### Added (deploy.sh)
- `--update`: `git pull --ff-only` → rebuild → reinstall in the same mode as
  before (system or portable). Zip installs skip the pull and just rebuild.
- Build-dependency detection in one pass (compiler, make, CMake, Qt6 dev via
  qmake6 / pkg-config / `Qt6Config.cmake`, python3); only then is the package
  manager invoked. `NO_DEPS=1` opts out, `JOBS=n` bounds parallelism.
- Optional packages (KF6 dev, tesseract, polkit, `libxcb-cursor0`, Qt
  linguist) are installed one by one — a renamed or missing optional no
  longer aborts the whole dependency step (`polkitd` vs `policykit-1`).
- Stale `build/CMakeCache.txt` from a moved/copied checkout is detected and
  the build dir recreated instead of CMake refusing to configure.
- `--help`, `doas` fallback, cache refresh on uninstall, PATH hint after a
  custom-PREFIX install; `iNode-VPN.sh` explains how to build when run before
  `deploy.sh --local`.

### Removed
- **System-GnuPG credential backend** (`GpgFileStore`): removed to cut attack
  surface (a `gpg` subprocess per operation and a second on-disk copy of every
  secret). A leftover `~/.config/iNodeClient-Qt/secrets.gpg` is transparently
  migrated on first use — decrypted once via gpg-agent/pinentry (the app still
  never sees the passphrase), re-sealed into the active backend, and renamed
  `secrets.gpg.migrated`. KWallet / Secret Service / AES-256-GCM-file
  backends are unchanged.

### Fixed (C++ / GUI)
- **High**: SSL VPN profiles with an SDP/SPA key crashed with a null-pointer
  dereference (`m_proc` used before creation); the SPA env is now applied to
  the process after construction.
- **High**: 802.1X never connected — `--stdin-password` was passed to the raw
  supplicant instead of the allow-listed `inode-dot1x-helper` (unknown flag →
  immediate exit, and pkexec policy mismatch). All launches now route through
  the helper.
- **High**: the AES-256-GCM fallback credential store could never be read
  back (`hasAnyStoredEntry()` inspected child *keys* while entries are child
  *groups* — always false → stored passwords silently unreadable).
- 802.1X "success" no longer blocks the GUI for up to 30 s: IP configuration
  (pkexec static config / DHCP renew) runs asynchronously; the DHCP timeout
  no longer reports success.
- L2TP/IPSec bring-up/teardown no longer freeze the GUI for up to 120 s:
  the helper runs asynchronously with a bounded watchdog; shutdown uses a
  detached `down` invocation instead of blocking the destructor.
- SSL VPN disconnect/teardown no longer blocks the GUI for up to 25 s
  (stop-helper is detached; a 5 s safety timer escalates SIGINT → kill).
- "Fetch pin" no longer routes user text through `bash -c` (command
  injection via a pasted gateway URL) — two piped `openssl` processes
  instead, run asynchronously.
- Wi-Fi passwords are no longer visible in `ps`: `nmcli --ask` reads the
  password from stdin instead of argv.
- Portal v2: REQ_AUTH now echoes the **server-assigned ReqId** from
  ACK_CHALLENGE (offset 6) instead of a locally invented counter — the
  standard dialect previously failed against real iMC/EIA servers. Attribute
  values are clamped to the 253-byte TLV limit; a 10 s watchdog fails
  cleanly when the server never answers; the plaintext password is dropped
  from memory once the session is up.
- Portal/EAD: asynchronous DNS (sync `QHostInfo::fromName()` on every send,
  heartbeats included, used to freeze the GUI); EAD arms its retransmit
  timer during resolution so a slow resolver can't wedge the protocol.
- The queued `m_active.reset()` in `MainWindow` can no longer destroy a
  freshly started connection racing an old session's late `Disconnected`.
- KWallet object leak on wallet reopen; uptime timer now ticks only while
  connected; portal-secret/SPA-key fields are password-masked; failed
  profile/log writes are logged instead of silently dropped; DHCP gateway
  tie-breaking prefers the kernel's (first) route.

### Fixed (Python SSL VPN backend)
- **High**: `_read_tunnel_preamble` busy-spun at 100 % CPU for the full
  deadline when the gateway closed the tunnel socket mid-handshake (EOF is
  permanently select()-readable) — EOF now raises `TunnelClosed`.
- **High**: a negative `Content-Length` desynchronized the reused
  auth-connection stream (buffer sliced with negative indices); missing
  Content-Length on non-204/304 responses is now an explicit error instead
  of a `ValueError` traceback.
- **High**: gateway-supplied BMP dimensions were trusted unconditionally —
  a 16 MB "captcha" decoded into ~400 MB of pixel tuples (OOM). Dimensions
  are now capped (≤ 4096 px, ≤ 1 M px total).
- Control and tunnel TLS sockets are closed on every failure path and at
  teardown (`Connection.close()`, try/finally in `authenticate()` /
  `open_tunnel()`); `Tunnel.stop()` joins the heartbeat thread and closes
  the socket (previously one live thread + fd leaked per tunnel session).
- Backend exceptions (`TunnelClosed`, `HTTPError`, `ssl.SSLError`) no longer
  escape as tracebacks: clean message, server-side logout attempted, proper
  exit codes for the GUI's auto-reconnect.
- Data pump: `SSLSocket.pending()` is drained before `select()` (a buffered
  TLS record used to idle the pump in 1 s ticks), socket timeout shortened
  (a partial record blocked the pump for up to 30 s), TUN writes checked.
- `resolv.conf` handling resolves symlinks (systemd-resolved systems kept
  their link intact now), validates DNS literals (no empty resolv.conf), and
  `ip route del` removes exactly the routes that were added.
- Full-tunnel mode refuses to start without a gateway bypass (previously
  hung the tunnel by routing its own TLS traffic into the TUN).
- Empty `H3C_SVPN_PASSWORD` no longer silently disables the password prompt;
  SPA knock rejects degenerate port lists; settings file type coercion;
  XML attribute values escape quotes; cert-pin compare is constant-time;
  HTTP 308 counted as a redirect.
- Shell helpers: `inode-l2tp-helper` chap-secrets matching is field-exact
  (a `.*` username previously deleted **all** entries as root) with trap
  rollback on failed bring-up; `inode-ipcfg-helper` refuses to install an
  empty `resolv.conf` and resolves symlinks.

## [Unreleased] — 2026-08-31

Deployment, security-hardening and documentation release.

### Added
- **One-shot `deploy.sh`**: distro-aware dependency install (apt/dnf/pacman/
  zypper), build, system install with polkit registration, `--local` portable
  mode, `--build-only`, `--uninstall`, and a trailing `--doctor` report.
- **`--doctor` CLI**: environment self-check — Qt/KF6, all four credential
  backends, external tools, privileged helpers, polkit action, Python backend.
- **System-GnuPG credential backend** (`GpgFileStore`): credentials sealed to
  the user's own GPG key (agent/pinentry own the passphrase; the app never
  sees it), symmetric pinentry fallback when no key exists, 0600 atomic
  writes at `~/.config/iNodeClient-Qt/secrets.gpg`. Wired into
  `CredentialStore` between Secret Service and the AES-GCM file fallback.
- **New docs**: `docs/INSTALL.md` (3 install methods, per-distro deps, GPG
  setup, troubleshooting) and a rewritten `docs/USAGE.md`; README restructured
  around them.

### Fixed (security)
- C8 (High): `inode-l2tp-helper` newline injection into root-owned
  ipsec.conf/chap-secrets via `--server`/`--username`/PSK — strict
  hostname/IP grammar, control-char and whitespace rejection, PSK quoting
  guards.
- C9 (Medium): `inode-svpn-helper stop` signalled the bare pidfile PID
  (PID-reuse could kill an innocent process) — now verifies the recorded PID
  is actually the h3csvpn backend via `/proc/<pid>/cmdline`.
- C10 (Medium): `secrets.enc` written world-readable — clamped to 0600 at
  every sync; write failures now propagate.
- C11 (Low): `inode-ipcfg-helper` accepted out-of-range octets and
  leading-zero octets (octal-parse hazard) — strict 0–255 per octet.
- C12 (High, in-review): GPG backend decrypt-without-path (empty stdin) and
  `QFile::rename` no-overwrite — every write after the first silently failed;
  fixed + covered by in-process tests.
- `deploy.sh`: polkit policy mirrored to `/usr/share` for non-`/usr` prefixes
  (polkit only scans canonical dirs); CMake helper dir pinned to the policy's
  exec paths (Debian triplet mismatch).
- CI: python job referenced a nonexistent `tests/` — replaced with a backend
  import check.
- Leaked gateway address / account names / personal paths scrubbed from
  docs and scripts; `captcha_lab.py` credentials replaced with interactive
  prompts.

## [Unreleased] — 2026-06-22

Audit pass over the UI/protocol layer: wired up controls that were collected but
ignored, fixed a credential-exposure issue, and corrected misleading labels.

### Added
- **Standalone EAD (iMC SEC) posture protocol implemented.** `EadProtocol` is no
  longer a stub: it speaks the UDP/9019 SEC protocol reverse-engineered from
  `libInodeSecurityAuth.so` (unstripped + DWARF). Pure Qt/C++ (no privileges, same
  shape as `PortalProtocol`): the 28-byte SEC header (`ulPktHeadId` bytes
  `00 0A D8 77`, big-endian length/pktId/opcode), the keyed-MD5 checksum over the
  hardcoded seed `SC-EAD_Server$REQ&ShareKey@9019`, a **compliant** XML posture
  body (`<i n="...">` items, empty `*checkResult` = pass) with identity fields,
  and the `SEC_START(1) → CHECK_LIST(2) → CHECK_RESULT(3) → SUCCESS(4)/FAIL(6) →
  HEARTBEAT(17)` state machine. Sends unencrypted bodies (the handshake is
  unencrypted per `GetPktEncryType`). **Untested against a live iMC EIA server**
  (we have none); framing/checksum/schema are byte-faithful to the binary.
- **Portable secure credential storage.** Added a freedesktop **Secret Service**
  backend (libsecret, `dlopen`'d at runtime — no build dependency) tried after
  KWallet and before the obfuscated fallback. This gives real keyring-backed
  storage on GNOME / XFCE / Cinnamon / most non-KDE distros (gnome-keyring,
  ksecretd, KeePassXC, …), so the "fallback storage" warning only appears when
  no keyring exists at all. Verified end-to-end (store/lookup round-trip) against
  a live `org.freedesktop.secrets` daemon.
- **Former stubs wired up (best-effort).**
  - **EAD host-check ack** — SSL VPN profiles gained a *“Send EAD host-check
    acknowledgement after login”* toggle (backend `--ead`). **Verified live**:
    auth still succeeds against `SSLVPN-Gateway/7.0` with it on. (Reverse-
    engineering `libInodeSecurityAuth.so` revised the standalone iMC posture
    verdict: it is **not** crypto-blocked — the UDP/9019 SEC packet is sealed
    only by a hardcoded keyed-MD5 seed `SC-EAD_Server$REQ&ShareKey@9019` and a
    static XTEA key, both recovered — and the OPSWAT collector does not sign the
    report at all — so a dummy posture is *feasible*; the
    remaining work is the result schema + SEC state machine, not breaking crypto.
    `EadProtocol`/docs now say so. Not yet built; no iMC server to test against.)
  - **SDP** — now a selectable protocol = SSL VPN preceded by a Single-Packet-
    Authorization knock. SPA *key / AID / ports* fields on the profile drive the
    RFC-4226-HOTP knock (`--spa-key/--spa-aid/--spa-ports/--spa-knock-port`;
    47-byte packet builder validated). The SDP *registration* that mints the
    per-client key/AID remains out of scope — supply them from an enrolled client.
  - **H3C Portal TLV dialect** — no longer rejected; `PortalProtocol::sendAuth()`
    appends the documented H3C **user-mac** TLV (`0x0A`) when the profile's
    dialect is *H3C TLV*. Best-effort and **untested against a live H3C Portal**;
    other TLVs need a packet capture to finalise.
- **GUI redesign.** A single **Connect ⇄ Disconnect** button that morphs and
  recolours with state; a **live connection panel** (replacing the separate
  badge / status-bar label / stats strip) showing IP, gateway, interface,
  uptime and live **↓↑ throughput with a sparkline**, plus an indeterminate
  progress bar while connecting; a **custom list delegate** rendering each
  profile as a state-dot + bold name + dim username/server subtitle + a
  right-aligned protocol pill; and **keyboard shortcuts** (Enter = connect the
  selected profile, Delete = remove).
- **GUI polish.** A **right-click context menu** on profiles (Connect /
  Disconnect / Edit / **Duplicate** / Remove), a **show/hide password** toggle in
  the profile editor, and a friendly empty-state hint when there are no profiles.
- **SSL VPN SHA-256 certificate pin in the GUI.** New per-profile *"Cert pin
  (SHA-256)"* field with a one-click **Fetch** button (reads the gateway's
  fingerprint via `openssl`). When set it passes `--pin-sha256` and overrides the
  trust mode. This is the secure way to trust a self-signed gateway whose cert CN
  doesn't match the host — previously only the CLI could do this, so the GUI
  failed such gateways with `CERTIFICATE_VERIFY_FAILED` on the default System-CA
  trust (the live `SSLVPN-Gateway/7.0` cert is `CN=HTTPS-Self-Signed-…`, no SAN).
- **SSL VPN split tunnel (enterprise).** New `--split-tunnel` backend flag and a
  per-profile *"Split tunnel"* checkbox (on by default). Only the gateway's own
  subnets are routed through the VPN; the host default route and system resolver
  are left untouched, so general internet traffic keeps using the physical link.
  **Verified end-to-end** against a live `SSLVPN-Gateway/7.0`: tunnel up on
  `inode0`, only the gateway's pushed corporate subnets routed, the host default
  route + `/etc/resolv.conf` left untouched, public HTTPS still reachable
  directly, and a corporate host reachable through the tunnel.
- **Modern "Mullvad" dark theme**, now the default. Deep-navy surfaces, flat
  rounded controls, a green *Connect* CTA / red *Disconnect* CTA, and a
  colour-coded connection-status badge that tracks state. Selectable alongside
  the existing themes in *Preferences → Theme*.
- **Static IP configuration is now applied** for 802.1X / WLAN profiles. The
  per-profile *IP mode* (Inherit / DHCP / Static) and the Static IP / netmask /
  gateway / DNS fields under *Advanced* were previously collected and persisted
  but never used. They are now programmed onto the interface after
  authentication and torn down on disconnect:
  - **Inherit** — no change (no extra privilege prompt)
  - **DHCP** — runs the existing DHCP renew path
  - **Static** — sets `ip addr` + default route and writes DNS to
    `/etc/resolv.conf` (original backed up, restored on disconnect)
  - New privileged helper `scripts/inode-ipcfg-helper`, polkit action
    `org.inode.ClientQt.ipcfg`, driven by `core/IpConfigurator`.

### Changed
- **H3C Portal dialect rewritten to match the binary.** Reverse-engineering
  `libInodePortalPt.so` (unstripped + DWARF) showed the previous "H3C TLV
  dialect" was wrong: it appended a `0x0A` *user-mac* TLV to standard Portal v2,
  but in the binary **`0x0A` is `ATTR_PORTAL_BAS_IP`** and `0x0F`/`0x13` are not
  wire attributes at all. The H3C dialect is a separate proprietary protocol —
  private opcode space (`LOGIN=0x64`, `LOGOUT=0x66`, `HANDSHAKE=0x68`, …) and a
  distinct attribute set (`USER_NAME=0x65`, `USER_PASSWORD=0x66`,
  `PRIVATE_IP=0x67`, `PUBLIC_IP=0x68`, `START_TIME=0x71`, …) over the shared
  32-byte header + `MD5(packet-auth-zeroed ‖ secret)` authenticator.
  `PortalProtocol` (dialect == 1) now builds a real `LOGIN_REQUEST(0x64)`,
  `HANDSHAKE(0x68)` keep-alive and `LOGOUT_REQUEST(0x66)`, and answers the
  anti-track hash challenge (`0x82` → `0x83`) best-effort. **Untested vs. a live
  H3C Portal.** The standard GB/T 28181 v2 path is unchanged.
- **SPA `declaredLen` endianness fixed.** `onKnockUDPMsg` stores `0x0110` in
  **native little-endian** (wire bytes `10 01`); `spa.py` was emitting it
  big-endian (`01 10`). Also re-confirmed via `generateOTP` @0x1bd70 that the
  HOTP counter is the **random** `rand()` value (not time/event-based) and is the
  same value byte-swapped into `pktID` — so the existing `pkt_id`-as-counter
  encoding is already byte-identical to the client. Documented the full 10-field
  `pc/userLogin` registration JSON.
- **SPA knock `portCount` corrected.** Reverse-engineering `libZeroTrust.so`
  (`onKnockUDPMsg`) confirmed `portCount = len(ports)`; the previous `(n//2)+1`
  guess was wrong for 3+ knock ports (1–2 port cases were unaffected). Also
  documented the verified SDP registration (rides on `pc/userLogin`, not a
  dedicated `/register` endpoint).
- **SSL VPN is no longer mislabeled a "stub".** The protocol dropdown now reads
  "SSL VPN" (was "SSL VPN (stub)") and the in-app *About* box lists it under
  *Working*. The protocol was already fully implemented via the bundled
  `h3csvpn` backend — only the UI strings were stale.
- **L2TP/IPSec credentials no longer reach the command line.** The PSK and
  password are streamed to `inode-l2tp-helper` on stdin (`--secrets-stdin`)
  instead of being passed as argv, so they no longer appear in `ps`/`/proc`.
  (The helper still accepts `--psk`/`--password` for manual CLI use.)
- **L2TP/IPSec privilege launch hardened.** Runs the helper directly when root,
  else `pkexec`, else `sudo -n` — so a missing polkit agent or TTY fails fast
  instead of blocking the UI. The helper wait is now bounded (≤120 s) rather
  than unbounded.

### Fixed
- **Security: CAPTCHA BMP decoder out-of-memory (the observed SIGKILL/137).**
  `decode_bmp` allocated a `width × height` pixel matrix from attacker-controlled
  BMP header dimensions before validating them, so a gateway (or on-path attacker
  when TLS verification is off) serving a tiny BMP that declares enormous
  dimensions made the process allocate many GB and get OOM-killed — on the
  default login path, pre-auth. Dimensions are now bounded (≤4096/side, ≤1M px)
  and checked against the body length before allocating. See
  [`docs/SECURITY-FINDINGS.md`](docs/SECURITY-FINDINGS.md) (C1).
- **Security: tunnel frame-reassembly buffer is now capped** (1 MiB) so a gateway
  dribbling never-completing partial frames can't grow it unbounded (slow OOM).
  (SECURITY-FINDINGS C2.)
- **Security: `inode-svpn-helper` hardened against root code-execution** via an
  unvalidated `--backend` — it now canonicalizes the path, refuses
  transient/world-writable dirs, and refuses any group/other-writable backend so
  a malicious `h3csvpn/` can't be loaded as root. (SECURITY-FINDINGS C3.)
- **Security: cert-pin comparison is now constant-time** (`hmac.compare_digest`).
- Added [`docs/SECURITY-FINDINGS.md`](docs/SECURITY-FINDINGS.md) documenting the
  H3C protocol-design weaknesses (EAD posture forgery, Portal logout/auth
  forgery, SPA replay, SSL VPN MITM) and this client's implementation findings.
- **Auto-reconnect no longer hammers permanent failures.** A failed connection
  caused by a bad certificate, wrong credentials, an exhausted CAPTCHA, or an
  unsupported protocol is no longer retried on a timer (it would never succeed);
  only unexpected drops of a previously-working session trigger a reconnect.
- **SSL VPN tunnel now actually establishes.** The live `SSLVPN-Gateway/7.0`
  returns the tunnel's network-config block in the `NET_EXTEND` *HTTP response
  headers* (`IPADDRESS`/`SUBNETMASK`/`ROUTES`/`GATEWAY`, `Content-Length: 0`).
  The backend only looked for it in the body and so failed with "did not receive
  a valid network-config frame"; it now parses the header form too.
- **`SUBNETMASK` as a prefix length is handled.** This gateway sends
  `SUBNETMASK: 24` (i.e. `/24`); the mask→prefix helper previously treated `24`
  as dotted-decimal and computed `/2`. A bare integer is now read as the prefix.
- **CAPTCHA solver needs far fewer retries.** Glyphs are isolated by colour +
  connected components (so two same-coloured glyphs no longer merge and force a
  wasted refetch), OCR'd with multi-render majority voting, and a best-effort
  4-char guess is now submitted on every round-trip instead of spinning on
  low-confidence refetches. When glyphs can't be cleanly isolated it now falls
  back to a whole-image OCR guess instead of returning nothing, and the GUI asks
  the backend for a generous retry budget (`--captcha-retries 40`) so success is
  near-certain (each attempt is a cheap round-trip the server adjudicates).
  (The gateway's noisy bitmap font still defeats tesseract on individual glyphs;
  a trained classifier is possible future work.)
- **"Store password" checkbox is now honored.** Previously a password typed into
  the profile editor was stored regardless of the checkbox. Unchecking it now
  removes any stored credential; checking it stores the password, overwriting
  only when a new one is actually entered.

### Known limitations
- The profile **Service** field is still collected but unused — none of the
  supported open backends (minieap / strongSwan / Portal / h3csvpn) accept a
  service / display-name parameter, so wiring it would be guesswork that could
  break auth.
- L2TP connect is bounded but still synchronous (a brief UI pause during
  `ipsec up`); a fully asynchronous flow is a possible follow-up.
