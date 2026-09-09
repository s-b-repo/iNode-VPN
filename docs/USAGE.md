# Usage Guide

Everyday use of the iNode VPN Client: the GUI, the CLI, profiles, trust
options, and what to do when something doesn't connect.

> Install first? See **[INSTALL.md](INSTALL.md)** — one command does it.
> Anything below assumes `./deploy.sh` (system install) or `./deploy.sh
> --local` (portable) has been run.

---

## Quick reference

| Task | Command |
|---|---|
| Launch GUI | `./iNode-VPN.sh` (portable) or `iNodeClient-Qt` (installed) |
| Start hidden in tray | `iNodeClient-Qt --minimized` |
| Connect a profile at launch | `iNodeClient-Qt --connect "Office"` |
| List profiles | `iNodeClient-Qt --list-profiles` |
| Connection status | `iNodeClient-Qt --status` → `<state>\t<profile>[\t<iface ip>]`; exit **0** connected, **2** idle, **3** not running |
| Disconnect the running instance | `iNodeClient-Qt --disconnect` (exit 3 if nothing runs) |
| Raise the running window | `iNodeClient-Qt` (a second launch never opens a duplicate) |
| Environment report | `iNodeClient-Qt --doctor` |
| Update to latest | `./deploy.sh --update` |
| CLI SSL VPN connect | `./svpn-connect.sh <gw>:<port> <user> [domain]` |
| CLI auth-only (no root) | `./svpn-connect.sh --auth-only <gw>:<port> <user> [domain]` |

---

## The GUI

```bash
./iNode-VPN.sh
```

1. **Add a profile** (＋ in the profile list) → give it a name.
2. Pick the **Protocol**:
   - **SSL VPN** — gateway host/port, username, domain (`RADIUS`, `system`,
     `local`, … — as your gateway calls it).
   - **802.1X / WLAN / L2TP-IPSec / Portal** — see the per-protocol fields in
     the editor; each stores its own credentials.
3. **Trust settings** (SSL VPN): for self-signed gateways set either a
   **SHA-256 pin** or a **CA file**. Verification is on by default; `--insecure`
   exists on the CLI but the GUI steers you to pinning.
4. Enter the password. **Store password** is ticked by default for new
   profiles, so it goes into the credential backend (KWallet / Secret
   Service / AES-256-GCM file — whichever is active, as shown by `--doctor`).
   Untick it and the password is kept in memory for this session only.
5. **Connect.** If no password is stored you are asked for it right there
   (with a *Remember* option). Tunnels request root through polkit only when
   needed; the tray icon shows state, and stats/log panes show live traffic
   + events.

Closing the window keeps the app in the tray when a tray is available; quit
from the tray menu. From any terminal, `iNodeClient-Qt --status`,
`--disconnect` and `--connect <name>` talk to the running instance over a
per-user socket (`$XDG_RUNTIME_DIR/iNodeClient-Qt-<uid>.sock`), so they work
in scripts and over SSH:

```bash
iNodeClient-Qt --status && echo "VPN is up"      # exit 0 only when connected
iNodeClient-Qt --connect "Office"; sleep 15; iNodeClient-Qt --status
iNodeClient-Qt --disconnect
```

---

## The CLI (SSL VPN)

`svpn-connect.sh` wraps the Python backend (`backends/h3csvpn`) and handles
`PYTHONPATH` + privilege escalation for you:

```bash
# Credentials only — verifies TLS + CAPTCHA + login, no tunnel, no root:
./svpn-connect.sh --auth-only vpn.example.com:443 alice RADIUS

# Full tunnel (TUN device; escalates via pkexec, falls back to sudo):
./svpn-connect.sh vpn.example.com:443 alice RADIUS

# Self-signed gateway — PIN IT (secure):
./svpn-connect.sh gw:443 alice -- --pin-sha256 AA:BB:CC:…

# Legacy gateway that really can't verify (opt-in, warned):
./svpn-connect.sh gw:443 alice -- --insecure

# Direct backend invocation (no wrapper):
PYTHONPATH=backends python3 -m h3csvpn gw:443 -u alice -d RADIUS -v
```

**Password handling:** read from `$H3C_SVPN_PASSWORD` if set, otherwise
prompted without echo — never on a command line, never in `ps`.
**Ctrl-C** = clean logout + tunnel teardown.

**Get a gateway's pin** (trust-on-first-use helper):

```bash
openssl s_client -connect HOST:PORT </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout
```

**CAPTCHA:** with `tesseract-ocr` installed the backend solves it
automatically (`--auto-captcha`, default on). Without it, solve manually:
`--show-captcha` renders the image, then pass `--vldcode <answer>`.

---

## Credential storage

Where saved passwords live depends on your system; the first available backend
wins (shown by `iNodeClient-Qt --doctor`):

1. **KWallet** — KDE, unlocked by login (KF6 build)
2. **Secret Service** — gnome-keyring, KeePassXC, ksecretd
3. **AES-256-GCM file** — master password chosen on first save, held in memory
   only, PBKDF2 (200k) + random salt, `secrets.enc` clamped to 0600.

The legacy **system GnuPG** backend (`secrets.gpg`) was removed in v0.3. If
you have one, it is re-sealed into the active backend automatically on first
use (gpg-agent/pinentry handle the passphrase for that one-time decrypt) and
the file is renamed `secrets.gpg.migrated`. No `gpg` installed? The file is
kept as-is and the app logs a note.

Forgetting a profile clears the entry from **all** backends.

---

## Troubleshooting

The complete list — every message the GUI, the helpers and the SSL VPN
backend can print, what causes it and how to fix it — is in
**[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**. The few below cover essentially
every failed *first* connect; work top-down.

### 1. "backend is group/other-writable; refusing to load it as root"

```
[INFO] helper: backend is group/other-writable; refusing to load it as root: .../backends
[ERR ] SSL VPN: backend exited with code 1
```

The root helper refuses to import Python from `backends/h3csvpn` while any
file or directory there is group/other-writable (so a malicious module can't
be swapped in). Typically caused by `umask 002` after unzipping/rebuilding,
or a stray `__pycache__`:

```bash
./deploy.sh --fix-perms                    # removes __pycache__, chmod -R go-w
find backends/h3csvpn -perm /022 -print    # must print nothing
```

`deploy.sh --local` does this automatically. (System installs are
unaffected — the installed copy lands root-owned.)

### 2. "No stored password for profile."

```
[ERR ] No stored password for profile.
```

Only seen on builds before v0.3.0. Since v0.3.0 the GUI asks for the
password at connect time whenever nothing is stored, and new profiles have
**Store password** ticked by default. If you still see this, update
(`./deploy.sh --update`) and connect again; if a keyring refuses to store
the password you get a warning dialog and the password is used for the
current session only — run `iNodeClient-Qt --doctor` to see which backend is
active. Without any keyring daemon the first save asks you to set a master
password (AES-256-GCM file fallback) — that's the backend, not a bug.

### 3. "sudo: a password is required"

```
[INFO] sudo: a password is required
[INFO] SSL VPN: backend exited with code 1
```

The tunnel needs root and `pkexec` wasn't found. Fixes:

- **Preferred:** install/keep `pkexec` and ensure a **polkit authentication
  agent** runs in your session (GNOME/KDE/XFCE ship one). The GUI then shows
  a proper authentication dialog — no sudoers rule needed.
- **Without pkexec:** allow only the helper, nothing else (double quotes so
  `$USER` expands!):

  ```bash
  echo "$(id -un) ALL=(root) NOPASSWD: /usr/libexec/iNodeClient-Qt/inode-svpn-helper *" \
    | sudo tee /etc/sudoers.d/inode-svpn-helper
  sudo chmod 440 /etc/sudoers.d/inode-svpn-helper
  sudo visudo -cf /etc/sudoers.d/inode-svpn-helper
  ```

  For portable mode use the repo path: `<repo>/scripts/inode-svpn-helper`.

### 4. Server-side login failures

*"incorrect username or password, authentication server error, or number of
users reaching the maximum allowed by an account"* — everything before the
password check (TLS, CAPTCHA, login round-trip) already succeeded. The
password is wrong/expired, the **domain** is wrong, or the account's
concurrent-login cap is in use. Isolate with:

```bash
./svpn-connect.sh --auth-only gw:443 user domain
```

### 5. Wrong credentials *after* a password change

The profile keeps using the stored (old) secret. Edit the profile → update
the password → save (overwrites the stored entry in the active backend).

### 6. A gpg/pinentry prompt appears once after upgrading

You upgraded from v0.2, which stored secrets in a GnuPG-sealed file. The
app decrypts it once (that's the pinentry), re-seals every entry into the
active backend and renames the file `secrets.gpg.migrated`. Cancelling the
prompt just postpones the migration to the next run. It never happens on a
fresh install.

### 7. `--doctor` says a tool is MISSING

`--doctor` `[MISSING]` items are optional per feature — see the table in
[INSTALL.md → Verify](INSTALL.md#6-verify-your-install). Install only what
your protocols need.

### 8. Anything else

[TROUBLESHOOTING.md](TROUBLESHOOTING.md) — organised by stage (install →
launch → credentials → polkit → SSL VPN → CAPTCHA → tunnel/DNS → 802.1X/WLAN
→ L2TP → Portal/EAD/SDP → reconnect/UI → update), one entry per message.

---

## Test-gateway etiquette

When validating against a real gateway, keep its address and account names
**out of any repository or screenshot** — use placeholders
(`vpn.example.com`, `<user>`, `<domain>`) and pass real values at runtime.
A full validation methodology (captures, pins, byte-diffs) lives in
[INTEROP.md](INTEROP.md).

## Limitations

- GM/SM2 (CNTLS / SKF USB-Key) gateways: not supported (TLS-layer only).
- Zero-Trust SDP registration: out of scope (SPA knock builder only).
- Tunnel is Linux-only (TUN + `ip`); the protocol itself is OS-agnostic.
- Without `tesseract-ocr`, CAPTCHAs are manual (`--show-captcha` + `--vldcode`).
