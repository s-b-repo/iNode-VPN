# Installation Guide

Three ways to install, pick one:

| Method | Needs root? | Best for |
|---|---|---|
| [1. One command](#1-one-command-recommended) | yes (install step only) | everyday use — full system install |
| [2. Portable](#2-portable-no-root) | **no** | try it out, USB sticks, no system changes |
| [3. Manual build](#3-manual-build) | optional | developers / custom prefixes |

After installing, everything is verified for you by the built-in environment
doctor (`--doctor`) — see [Verify](#6-verify-your-install). Already
installed? Jump to [Updating](#4-updating).

> **Requirements:** Linux, a C++20 compiler, CMake ≥ 3.22, Qt ≥ 6.4,
> Python ≥ 3.9. `deploy.sh` installs all of these for you on Debian/Kali/
> Ubuntu, Fedora, Arch and openSUSE. No display is needed to build or to run
> `--doctor`, so it works over SSH.

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
./deploy.sh --update            # git pull → rebuild → reinstall (see §4)
./deploy.sh --build-only        # stop after compiling (binary in ./bin)
./deploy.sh --uninstall         # remove everything (user data in ~/.config kept)
./deploy.sh --doctor            # just print the environment report
./deploy.sh --fix-perms         # re-tighten backends/ + scripts/ (portable mode)
PREFIX=/opt/inode ./deploy.sh   # custom prefix (policy is still mirrored
                                # to /usr/share so polkit finds it)
JOBS=2 ./deploy.sh              # limit parallel compile jobs (low-RAM boxes)
NO_DEPS=1 ./deploy.sh           # never touch the package manager
```

> **Password prompt:** the install step needs root, so `deploy.sh` calls
> `sudo` (or `doas`) once for `cmake --install`, and once more for the
> package manager if build deps are missing. Building itself is done as your
> user.

> **Lost the exec bit?** (zip downloads sometimes do) — run `bash deploy.sh`
> instead; it restores `+x` on every script it ships.

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
- The root helper refuses to load a group/other-writable backend tree.
  `deploy.sh --local` tightens `backends/` and `scripts/` for you; if you
  later edit or re-extract the sources, run `./deploy.sh --fix-perms` (see
  [Troubleshooting](#troubleshooting)).

---

## 3. Manual build

```bash
# 1. Dependencies (Debian/Kali/Ubuntu example — per-distro table below)
sudo apt install build-essential cmake pkg-config qt6-base-dev python3 \
                 libxcb-cursor0 tesseract-ocr polkitd pkexec

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
| **Debian / Kali / Ubuntu** | `build-essential cmake pkg-config qt6-base-dev python3 libxcb-cursor0 tesseract-ocr polkitd pkexec` (Ubuntu ≤ 22.04: `policykit-1` instead of `polkitd pkexec`) | KDE: `libkf6wallet-dev libkf6config-dev libkf6i18n-dev libkf6coreaddons-dev`; translations: `qt6-tools-dev` |
| **Fedora** | `gcc-c++ make cmake qt6-qtbase-devel python3 xcb-util-cursor tesseract polkit` | KDE: `kf6-kwallet-devel kf6-kconfig-devel kf6-ki18n-devel kf6-kcoreaddons-devel`; translations: `qt6-linguist` |
| **Arch** | `base-devel cmake qt6-base python xcb-util-cursor tesseract polkit` | KDE: `kwallet kconfig ki18n kcoreaddons`; translations: `qt6-tools` |
| **openSUSE** | `gcc-c++ make cmake qt6-base-devel python3 libxcb-cursor0 tesseract-ocr polkit` | KDE: `kf6-kwallet-devel …`; translations: `qt6-linguist-devel` |

`deploy.sh` installs the first column unconditionally and the second column
package-by-package, skipping anything your release doesn't ship.

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
| Credential storage | one of: KWallet, a Secret Service daemon (gnome-keyring/KeePassXC), libcrypto | falls back; with none, saving secrets is refused |

---

## 4. Updating

```bash
cd iNode-VPN
./deploy.sh --update
```

This runs `git pull --ff-only`, rebuilds, and reinstalls in the **same mode
you used before** — system if `/usr/libexec/iNodeClient-Qt` exists, portable
otherwise. Your profiles and saved passwords (`~/.config/iNodeClient-Qt`,
keyring entries) are never touched.

- Installed from a **zip / release tarball** instead of git? Extract the new
  version over the old folder, then run `./deploy.sh --update` (it skips the
  pull and just rebuilds + reinstalls).
- `git pull` refuses because of local edits? `git stash`, update, `git stash
  pop`.
- Moved or copied the folder (a stale `build/` from another path)? Nothing to
  do — `deploy.sh` detects the mismatched CMake cache and starts a clean
  build directory.
- Upgrading from **v0.2** with saved passwords in the old GnuPG store: see
  [Credential storage](#5-credential-storage) — migration is automatic.

---

## 5. Credential storage

Saved passwords never touch disk in plaintext. The app picks the first
available backend, in this order:

1. **KWallet** — KDE, unlocked by your login (needs the KF6 build)
2. **Secret Service** — gnome-keyring / KeePassXC / ksecretd
3. **AES-256-GCM file** — last resort, asks you to set a master password

The active backend is shown by `--doctor`.

> **Removed in v0.3:** the **system GnuPG** backend (`secrets.gpg`) is gone.
> A leftover store is migrated automatically: on first use the app decrypts
> `~/.config/iNodeClient-Qt/secrets.gpg` (gpg-agent/pinentry handle the
> passphrase, exactly as before), re-seals every entry into the active
> backend and renames the file to `secrets.gpg.migrated`. If `gpg` is not
> installed, the file is kept untouched and the app logs a note — install
> `gnupg` once to let the migration run, or delete the file manually.

---

## 6. Verify your install

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
  [ok] AES-256-GCM file (libcrypto via dlopen)
  active: Secret Service (login keyring)

External tools:
  [ok] python3 (SSL VPN backend runtime)
  [ok] pkexec (privileged helpers)
  ...

Privileged helpers + polkit:
  [ok] inode-svpn-helper
  ...
  [ok] polkit action org.inode.ClientQt.* (/usr/share/polkit-1/actions)

SSL VPN backend module:
  [ok] h3csvpn python package
```

`MISSING` lines are **not errors** — they list what you'd gain by installing
the optional piece (KF6 → KWallet, tesseract → auto-CAPTCHA, strongSwan →
L2TP, …). The things that must be `ok` for your use case:

- **SSL VPN:** `python3`, `pkexec`, the helper, the polkit action, the
  h3csvpn module.
- **Saving passwords:** any one credential backend `ok`.

The polkit line is expected to be `MISSING` in portable mode (nothing is
registered system-wide); `pkexec` still works, it just prompts generically.

---

## Troubleshooting

The full catalogue — every message from `deploy.sh`, the helpers, the GUI and
the SSL VPN backend, with the fix — is **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**.
The install-time problems you are most likely to meet:

### Build fails: "The source directory … does not match the source used to generate cache"

A `build/` directory was copied along with the sources (zip snapshot, moved
checkout) and its CMake cache points at the old path. `deploy.sh` detects
this and wipes `build/` automatically; for a manual build do `rm -rf build`
and configure again.

### "This application failed to start because no Qt platform plugin could be initialized"

- On an **X11** desktop: install `libxcb-cursor0` (Debian/Ubuntu/Kali),
  `xcb-util-cursor` (Fedora/Arch) — required by Qt ≥ 6.5's xcb plugin. The
  one-command installer pulls it in for you.
- Over **SSH / headless**: `--doctor`, `--version`, `--help` and
  `--list-profiles` switch to the offscreen platform automatically. The GUI
  itself needs a display; forward one (`ssh -X`) or run it in your session.

### "Permission denied" while building, or chmod errors from deploy.sh

Almost always leftovers from running `sudo ./deploy.sh` once: `build/` and
`bin/` are then owned by root and every later run as your user fails.
`deploy.sh` now detects files in `build/`, `bin/`, `backends/` or
`scripts/` that you don't own and offers to `chown` them back (one sudo
prompt). Don't run the script with `sudo` — it asks for root only for the
install step. To fix by hand:

```bash
sudo chown -R "$(id -un)" .        # inside the iNode-VPN folder
./deploy.sh --fix-perms
```

A folder that isn't writable by you at all (extracted by root into
`/opt`, a read-only mount) is reported up front with the same fix.

### "backend is group/other-writable; refusing to load it as root"

The root helper refuses to import Python from `backends/h3csvpn` if any file
or directory there is group/other-writable (so a malicious module can't be
swapped in). Common after unzipping/rebuilding with `umask 002`, or when a
`__pycache__` was written into the tree:

```bash
./deploy.sh --fix-perms                    # removes __pycache__, chmod -R go-w
find backends/h3csvpn -perm /022 -print    # must print nothing
```

`deploy.sh` does this on every build (all modes) and forces `umask 022` for
everything it creates, so a fresh `git clone` on a system whose default
umask is `002` (Debian/Kali user-private groups) works without manual
chmod. System installs are unaffected — CMake installs the backend copy
root-owned with 644/755 regardless of the source tree's permissions.

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
  `--doctor` shows the polkit action as `ok`. polkit only scans
  `/usr/share/polkit-1/actions` — a policy under `/usr/local/share` is
  ignored; `./deploy.sh` mirrors it into the right place.

### "No stored password for profile."

The GUI doesn't prompt for the password at connect time — it reads it from the
credential backend. Edit the profile, enter the password, tick **store
password**, save. (With no keyring daemon, the first save asks you to set a
master password — see [Credential storage](#5-credential-storage).)

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

Anything else — connection errors, CAPTCHA, tunnel/DNS, 802.1X, L2TP, Portal —
is in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
