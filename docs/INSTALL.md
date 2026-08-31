# Installation Guide

Three ways to install, pick one:

| Method | Needs root? | Best for |
|---|---|---|
| [1. One command](#1-one-command-recommended) | yes (install step only) | everyday use — full system install |
| [2. Portable](#2-portable-no-root) | **no** | try it out, USB sticks, no system changes |
| [3. Manual build](#3-manual-build) | optional | developers / custom prefixes |

After installing, everything is verified for you by the built-in environment
doctor (`--doctor`) — see [Verify](#5-verify-your-install).

---

## 1. One command (recommended)

```bash
git clone https://github.com/s-b-repo/iNode-VPN.git
cd iNode-VPN
./deploy.sh
```

`deploy.sh` does everything:

1. **Detects your distro** (Debian/Kali/Ubuntu, Fedora, Arch, openSUSE) and
   installs the build + runtime packages via its native package manager.
2. **Builds** the Qt6 GUI (`RelWithDebInfo`).
3. **Installs** system-wide:
   - GUI → `/usr/local/bin/iNodeClient-Qt`
   - privileged helpers + Python backend → `/usr/libexec/iNodeClient-Qt/`
   - polkit policy → `/usr/share/polkit-1/actions/` (registered so `pkexec`
     can authorize the tunnel helpers)
   - menu entry + icon → `/usr/local/share/applications`, `.../icons/hicolor`
4. **Runs `--doctor`** so you immediately see what works on your machine.

Useful flags:

```bash
PREFIX=/opt/inode ./deploy.sh   # custom prefix (policy is still mirrored
                                # to /usr/share so polkit finds it)
./deploy.sh --build-only        # stop after compiling
./deploy.sh --uninstall         # remove everything (user data in ~/.config kept)
./deploy.sh --doctor            # just print the environment report
```

> **Password prompt:** the install step needs root, so `deploy.sh` calls
> `sudo` once for `cmake --install`. Building itself is done as your user.

---

## 2. Portable (no root)

```bash
./deploy.sh --local
```

Builds into `bin/` and keeps everything self-contained in the repo folder:

```
iNode-VPN.sh        ← run the GUI (resolves all paths relative to itself)
svpn-connect.sh     ← CLI SSL VPN connect
bin/iNodeClient-Qt  ← the binary
backends/h3csvpn/   ← Python SSL VPN backend
scripts/            ← privileged helpers
```

Run it:

```bash
./iNode-VPN.sh                    # GUI
./svpn-connect.sh gw:443 alice    # CLI (escalates via pkexec/sudo per-run)
```

**Portable-mode notes**

- Tunnel creation still needs root *at connect time* — the helpers are invoked
  through `pkexec` (or `sudo`) each run, so you'll get an authentication prompt.
- The polkit policy is **not** registered in portable mode; `pkexec` will still
  work (it prompts as "run program"), you just don't get the friendly
  per-action descriptions. If you want them, do a system install later.
- If you rebuilt the Python backend, re-run `chmod -R go-w backends` — the
  root helper refuses to load a group/other-writable backend (see
  [Troubleshooting](#troubleshooting)).

---

## 3. Manual build

```bash
# 1. Dependencies (Debian/Kali/Ubuntu example — per-distro table below)
sudo apt install build-essential cmake qt6-base-dev python3 gnupg \
                 tesseract-ocr polkitd pkexec

# 2. Configure + build
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
                -DINODE_HELPER_DIR="/usr/libexec/iNodeClient-Qt"
cmake --build build -j$(nproc)     # use -j2 if RAM is tight

# 3a. System install (root; matches the polkit policy paths)
sudo cmake --install build

# 3b. …or portable
cp build/iNodeClient-Qt bin/ && ./iNode-VPN.sh
```

`-DINODE_HELPER_DIR` must match the exec paths inside
`src/resources/org.inode.ClientQt.policy` (default `/usr/libexec/iNodeClient-Qt`)
— otherwise pkexec refuses to run the helpers.

### Per-distro dependencies

| Distro | Core (GUI build) | Extras (optional) |
|---|---|---|
| **Debian / Kali / Ubuntu** | `build-essential cmake qt6-base-dev python3 gnupg tesseract-ocr polkitd pkexec` | KDE: `libkf6wallet-dev libkf6config-dev libkf6i18n-dev libkf6coreaddons-dev` |
| **Fedora** | `gcc-c++ cmake qt6-qtbase-devel python3 gnupg2 tesseract polkit` | KDE: `kf6-kwallet-devel kf6-kconfig-devel kf6-ki18n-devel kf6-kcoreaddons-devel` |
| **Arch** | `base-devel cmake qt6-base python gnupg tesseract polkit` | KDE: `kwallet kconfig ki18n kcoreaddons` |
| **openSUSE** | `gcc-c++ cmake qt6-base-devel python3 gpg2 tesseract polkit` | KDE: `kf6-kwallet-devel …` |

The Python SSL VPN backend needs **no packages at all** (stdlib only, Python
3.9+). Optional hardening extras:

```bash
pip install backends/h3csvpn/[secure,rsa]     # defusedxml (hardened XML), cryptography (RSA mode)
```

### Runtime dependencies (per feature)

| Feature | Needs | Missing it means |
|---|---|---|
| SSL VPN | `python3`, `pkexec` (or sudo) | tunnel can't be created |
| SSL VPN CAPTCHA auto-solve | `tesseract-ocr` | solve manually (`--show-captcha` + `--vldcode`) |
| 802.1X wired | `minieap` or `mentohust` | protocol unavailable |
| WLAN 802.1X | NetworkManager (`nmcli`) | protocol unavailable |
| L2TP/IPSec | `strongswan`, `xl2tpd`, `ppp` | protocol unavailable |
| Credential storage | one of: KWallet, a Secret Service daemon (gnome-keyring/KeePassXC), **gpg**, libcrypto | falls back; with none, saving secrets is refused |

---

## 4. Credential storage (GPG and friends)

Saved passwords never touch disk in plaintext. The app picks the first
available backend, in this order:

1. **KWallet** — KDE, unlocked by your login (needs the KF6 build)
2. **Secret Service** — gnome-keyring / KeePassXC / ksecretd
3. **system GnuPG** — recommended if you already run a PGP keyring
4. **AES-256-GCM file** — last resort, asks you to set a master password

The active backend is shown by `--doctor`. To use **GPG**:

```bash
gpg --full-gen-key            # once — if you don't have a key yet
iNodeClient-Qt --doctor       # should now report: [ok] GnuPG — GPG (key XXXX…)
```

How the GPG backend works:

- Credentials are sealed to your default **secret key** (`--trust-model always`).
- The passphrase is handled entirely by **gpg-agent + pinentry** (GUI prompt);
  this app never sees or stores it, and the agent caches the unlock like any
  other GPG use.
- No key yet or key deleted? It transparently falls back to **symmetric**
  encryption (pinentry asks for a passphrase on first save).
- On disk: a single 0600, atomically-replaced blob at
  `~/.config/iNodeClient-Qt/secrets.gpg`.

---

## 5. Verify your install

```bash
iNodeClient-Qt --doctor        # system install — or:
./bin/iNodeClient-Qt --doctor  # portable
```

Example output (yours will differ):

```
iNode Client (Qt) — environment doctor

Build / platform:
  [ok] Qt 6.10.2 (x86_64-bit, x86_64)
  [MISSING] KDE Frameworks 6 (not linked — KWallet unavailable)

Credential backends (in priority order):
  [ok] freedesktop Secret Service
  [ok] GnuPG — GPG (key 7C1C4275…)
  [ok] AES-256-GCM file (libcrypto via dlopen)
  active: Secret Service (login keyring)

External tools:
  [ok] python3 (SSL VPN backend runtime)
  [ok] pkexec (privileged helpers)
  ...

Privileged helpers + polkit:
  [ok] inode-svpn-helper
  ...

SSL VPN backend module:
  [ok] h3csvpn python package
```

`MISSING` lines are **not errors** — they list what you'd gain by installing
the optional piece (KF6 → KWallet, tesseract → auto-CAPTCHA, strongSwan →
L2TP, …). The things that must be `ok` for your use case:

- **SSL VPN:** `python3`, `pkexec`, the helper, the polkit action, the
  h3csvpn module.
- **Saving passwords:** any one credential backend `ok`.

---

## Troubleshooting

### "backend is group/other-writable; refusing to load it as root"

The root helper refuses to import Python from `backends/h3csvpn` if any file
there is group/other-writable (so a malicious module can't be swapped in).
Common right after unzipping/rebuilding with `umask 002`:

```bash
chmod -R go-w backends
find backends -type d -exec chmod 755 {} \;
find backends/h3csvpn -perm /022 -print    # must print nothing
```

Re-run after every rebuild/re-extract (or set `umask 022` in your shell rc).

### pkexec prompts don't appear / "sudo: a password is required"

- Tunnels need root. The GUI prefers `pkexec`; make sure a **polkit
  authentication agent** is running (GNOME/KDE/XFCE ship one in the session).
- No pkexec? Restrict passwordless sudo to the helper only:

  ```bash
  echo "$(id -un) ALL=(root) NOPASSWD: /usr/libexec/iNodeClient-Qt/inode-svpn-helper *" \
    | sudo tee /etc/sudoers.d/inode-svpn-helper
  sudo chmod 440 /etc/sudoers.d/inode-svpn-helper
  sudo visudo -cf /etc/sudoers.d/inode-svpn-helper      # validate
  ```

- GUI asks for root on *connect* even though it's installed: check
  `--doctor` shows the polkit action as `ok`.

### "No stored password for profile."

The GUI doesn't prompt for the password at connect time — it reads it from the
credential backend. Edit the profile, enter the password, tick **store
password**, save. (First save may trigger a pinentry/master-password prompt —
see [Credential storage](#4-credential-storage-gpg-and-friends).)

### Login fails server-side

*"incorrect username or password, authentication server error, or number of
users reaching the maximum allowed by an account"* — the client is fine; the
password is wrong/expired, the domain is wrong, or the account's
concurrent-login cap is hit. Test auth-only first:

```bash
./svpn-connect.sh --auth-only vpn.example.com:443 <user> <domain>
```

### Uninstall

```bash
./deploy.sh --uninstall     # removes binary, helpers, policy, menu entry
rm -rf ~/.config/iNodeClient-Qt   # optional: user data (profiles, secrets)
```
