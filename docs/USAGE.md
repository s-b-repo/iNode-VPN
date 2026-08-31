# iNode VPN Client — ready-to-use package

A self-contained build of the Qt6 **iNode Client** with a **working H3C SSL VPN**
implementation. Nothing here needs installing — run it straight from this folder.

The SSL VPN is implemented by a bundled clean-room backend (`backends/h3csvpn`,
reverse-engineered from the Linux iNode 7.3 client and validated against a live
`SSLVPN-Gateway/7.0`) that the Qt app drives through a privileged helper.

## What's in here

```
iNode-VPN.sh        ← launch the GUI
svpn-connect.sh     ← quick SSL VPN connect from the command line (no GUI)
bin/iNodeClient-Qt  ← the application
backends/h3csvpn/   ← the SSL VPN protocol backend (Python)
scripts/            ← privileged helpers (run via pkexec/sudo for the tunnel)
docs/               ← protocol notes, security findings, CAPTCHA analysis
```

## Requirements

Already present on this machine:

- `qt6-base-dev`, `cmake`, `g++` — Qt/C++ toolchain
- `python3` with `bcrypt`, `cryptography`, `psutil` — SSL VPN backend extras
- `polkit` + a running polkit **authentication agent** — the GUI escalates to
  root through `pkexec`, which needs an agent to show the auth dialog
- `libpolkit-qt6-1-1` — GUI root-auth integration

Optional:

- `tesseract-ocr` — only for automatic CAPTCHA OCR. Without it the backend still
  works, but CAPTCHAs must be solved manually via `--show-captcha` + `--vldcode`.

## Building from source (only if you change the C++)

```bash
cd <repo-path>
rm -rf build && mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build . -j2
cp iNodeClient-Qt ../bin/           # place the binary next to the launch scripts
cd ..
chmod -R go-w backends              # see "group/other-writable" note below
```

## Running the GUI

```bash
./iNode-VPN.sh
```

`iNode-VPN.sh` resolves paths relative to the repo root, so the binary runs
without being system-installed. From the repo root, `./bin/iNodeClient-Qt` also
accepts the CLI flags (`--list-profiles`, `--connect <profile>`, `--status`, …).

## Running the SSL VPN backend (Python)

The backend is a normal Python package inside `backends/h3csvpn/`. It is **not**
installed into site-packages, so run it with `PYTHONPATH`/`PYTHONSAFEPATH`
pointed at the bundled directory:

```bash
cd <repo-path>

# Show help / verify the backend runs:
PYTHONPATH=backends PYTHONSAFEPATH=1 python3 -m h3csvpn --help

# Authenticate only — no tunnel, no root:
PYTHONPATH=backends PYTHONSAFEPATH=1 python3 -m h3csvpn <gateway[:port]> -u <user> [-d domain] --no-tunnel -v

# Full tunnel via shell wrapper (recommended):
./svpn-connect.sh <gateway[:port]> <username> [domain]
```

`PYTHONSAFEPATH=1` ensures Python only loads modules from the `PYTHONPATH`
directory, matching the backend's security expectations. `svpn-connect.sh`
already exports both env vars and handles privilege escalation (`pkexec`, then
`sudo`) when creating the TUN device.

## Quick connect examples

```bash
# Test credentials only — no tunnel, no root:
PYTHONPATH=backends PYTHONSAFEPATH=1 python3 -m h3csvpn vpn.example.com -u alice -d RADIUS --no-tunnel -v

# Full tunnel:
./svpn-connect.sh vpn.example.com:443 alice RADIUS

# Self-signed gateway — pin the cert (secure) or skip verification:
./svpn-connect.sh gw:443 alice -- --pin-sha256 AA:BB:CC:...
./svpn-connect.sh gw:443 alice -- --insecure
```

Get a self-signed gateway's pin:
```bash
openssl s_client -connect HOST:PORT </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout
```

## Password handling

The password is read from `$H3C_SVPN_PASSWORD` if set, otherwise prompted
securely (never echoed, never placed on a command line). Press **Ctrl-C** to
disconnect; the helper logs out and tears the tunnel down cleanly.

## GUI quick start

```bash
./iNode-VPN.sh
```

Add a profile → **Protocol = SSL VPN** → fill gateway host/port, username,
domain → under trust set a CA file or SHA-256 pin for self-signed gateways →
**Connect**. The GUI prompts for root via polkit when bringing the tunnel up.

## Troubleshooting the SSL VPN connection

The three errors below account for essentially every failed first connect. Work
through them in order.

### 1. "backend is group/other-writable; refusing to load it as root"

```
[INFO] helper: backend is group/other-writable; refusing to load it as root: .../backends
[INFO] SSL VPN backend exited with code 1
[ERR ] SSL VPN: backend exited with code 1
```

The privileged helper runs as root and imports Python from `backends/h3csvpn/`.
To stop a malicious module being swapped in, it **refuses** to load if any file
under that tree is group- or other-writable (`find … -perm /022`).

This trips right after unzipping `Archive.zip` or rebuilding, because this
system's default **`umask 002`** creates files group-writable (664/775). Fix the
tree — no `sudo` needed, it's owned by your user:

```bash
cd <repo-path>
chmod -R go-w backends                          # drop group/other write bits
find backends -type d -exec chmod 755 {} \;     # keep directories traversable
# verify (must print nothing):
find backends/h3csvpn -perm /022 -print
```

Because `umask 002` re-introduces group-write on regenerated files, **re-run
`chmod -R go-w backends` after every rebuild or re-extract.** (Making it durable:
`umask 022` in your `~/.zshrc` stops new files being group-writable in the first
place.)

### 2. "No stored password for profile."

```
[ERR ] No stored password for profile.
[WARN] not auto-reconnecting — this looks like a permanent error: No stored password for profile.
```

The GUI only reads the password from the system keyring — it does **not** prompt
at connect time. Open the profile for editing, type your password into
**Password**, tick **Store password (encrypted in the system keyring)**, and
save the profile before connecting.

### 3. "sudo: a password is required"

```
[INFO] sudo: a password is required
[INFO] SSL VPN backend exited with code 1
```

Creating the TUN device needs root. The GUI prefers `pkexec` and only falls back
to `sudo -n` (non-interactive) when `pkexec` is **not on PATH**. You hit this
only if `pkexec` is missing *and* there's no passwordless sudo rule. Pick one:

- **Use pkexec (recommended on this machine — it already works):** ensure a
  polkit authentication agent is running so `pkexec` can show its dialog. On this
  A desktop with a polkit authentication agent running (e.g. GNOME/KDE ships
  `polkit-kde-authentication-agent-1`), so the GUI
  authenticates through the graphical prompt and **no sudoers rule is needed.**

- **Passwordless sudo for the helper (only if you remove/lack pkexec):** restrict
  it to the helper script alone. Note two things the common snippet gets wrong —
  use **double quotes** so the username expands (single-quoted `'$USER …'` writes
  a literal `$USER` that never matches), and use this machine's **real path**
  (the repo path, matching where the GUI resolves the
  helper):

  ```bash
  echo "$(id -un) ALL=(root) NOPASSWD: <repo-path>/scripts/inode-svpn-helper *" \
    | sudo tee /etc/sudoers.d/inode-svpn-helper
  sudo chmod 440 /etc/sudoers.d/inode-svpn-helper
  sudo visudo -cf /etc/sudoers.d/inode-svpn-helper    # validate syntax
  ```

  Never grant unrestricted passwordless sudo — restrict it to the helper.

### CAPTCHA without `tesseract-ocr`

If automatic CAPTCHA solving is desired, install `tesseract-ocr`. Otherwise the
GUI/backend still work; solve CAPTCHAs manually with `--show-captcha` +
`--vldcode <answer>` where exposed.

## Notes on test gateways

When validating against your own test gateway, keep the address and any real
account names **out of the repository** — use placeholders (`vpn.example.com`,
`<user>`, `<domain>`) in examples and docs, and pass real values via
environment/CLI at runtime. If login is rejected with *"incorrect username or
password, authentication server error, or number of users reaching the maximum
allowed by an account"*, that is **server-side**: the password is
wrong/expired, the wrong domain was used, or the account's concurrent-login cap
is already in use. Everything up to that point — TLS, CAPTCHA, the login
round-trip — is confirmed working by the client.

## Limitations

- GM/SM2 (CNTLS / SKF USB-Key) gateways are not supported (TLS-layer only).
- Zero-Trust SDP registration is out of scope (only the SPA knock builder exists).
- Linux only for the tunnel (TUN + `ip`); the protocol itself is OS-agnostic.
- Without `tesseract-ocr`, CAPTCHA must be solved manually (`--show-captcha`
  + `--vldcode <answer>`) instead of `--auto-captcha`.
