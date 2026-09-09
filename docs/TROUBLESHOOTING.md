# Troubleshooting

Every error the iNode VPN Client can show, what causes it, and how to fix
it. Organised by stage: work top-down from where the problem appears.

| Stage | Section |
|---|---|
| `./deploy.sh` fails or the build fails | [1. Install & build](#1-install--build) |
| The app won't start / CLI flags misbehave | [2. Launching the app](#2-launching-the-app) |
| Passwords aren't saved or found | [3. Credentials](#3-credentials) |
| Root / polkit / helper prompts and refusals | [4. Privileged helpers & polkit](#4-privileged-helpers--polkit) |
| SSL VPN won't connect (GUI or `svpn-connect.sh`) | [5. SSL VPN](#5-ssl-vpn) |
| CAPTCHA problems | [6. CAPTCHA](#6-captcha) |
| Tunnel is up but traffic/DNS is wrong | [7. Tunnel, routes & DNS](#7-tunnel-routes--dns) |
| 802.1X / WLAN | [8. 802.1X & WLAN](#8-8021x--wlan) |
| L2TP/IPSec | [9. L2TPIPSec](#9-l2tpipsec) |
| Portal / EAD / SDP | [10. Portal, EAD & SDP](#10-portal-ead--sdp) |
| Auto-reconnect, tray, notifications | [11. Reconnect, tray & UI](#11-reconnect-tray--ui) |
| Updating / uninstalling | [12. Update & uninstall](#12-update--uninstall) |
| Where logs and files live | [13. Logs & files](#13-logs--files) |

**First aid, always:**

```bash
iNodeClient-Qt --doctor          # or ./bin/iNodeClient-Qt --doctor (portable)
```

`[MISSING]` lines are optional pieces; the ones that matter per feature are
listed under each section. Every message below is quoted as it appears in the
GUI log pane, the terminal, or `~/.local/share/iNodeClient-Qt/logs/iNodeClient-Qt.log`.

---

## 1. Install & build

### `✗ no supported package manager (apt/dnf/pacman/zypper)`
`deploy.sh` only knows those four. Install the packages from the per-distro
table in [INSTALL.md](INSTALL.md#per-distro-dependencies) by hand, then run
`NO_DEPS=1 ./deploy.sh`.

### `✗ need root to install packages (no sudo/doas)` / `✗ system install needs root`
No `sudo` or `doas` on the box and you're not root. Either install one, run
the whole thing as root (`su -c ./deploy.sh` — it hands `build/` back to you
if `SUDO_USER` is set, otherwise `chown` afterwards), or use portable mode:
`./deploy.sh --local` needs no root at all.

### `✗ build deps missing and NO_DEPS=1 set`
You asked the script not to touch the package manager, but `cmake`, a C++
compiler, `make`, Qt6 dev files or `python3` is absent. Install them (table in
INSTALL.md) or drop `NO_DEPS=1`.

### `✗ still missing after package install: …`
The package manager ran but the tool still isn't found. Usual causes:
- **Qt6 dev** on an older release (Debian 11, Ubuntu 20.04) — Qt ≥ 6.4 is not
  packaged there. Use a newer release, the Qt online installer, or
  `CMAKE_PREFIX_PATH=/path/to/Qt/6.x/gcc_64 ./deploy.sh`.
- Package names differ on your derivative — install manually and re-run.

### `CMake Error … Could not find a package configuration file provided by "Qt6"`
Qt6 development files are missing or CMake can't see them. Debian/Ubuntu:
`qt6-base-dev`; Fedora: `qt6-qtbase-devel`; Arch: `qt6-base`; openSUSE:
`qt6-base-devel`. For a non-distro Qt: `-DCMAKE_PREFIX_PATH=<Qt>/lib/cmake`.

### `CMake Error: The source directory … does not match the source used to generate cache`
`build/` was copied along with the sources (zip snapshot, moved folder) and
its cache points at the old path. `deploy.sh` wipes and recreates `build/`
automatically. Manual build: `rm -rf build` and configure again.

### `c++: fatal error: Killed signal terminated program cc1plus` / build hangs, box swaps
Out of memory. Limit parallel jobs: `JOBS=2 ./deploy.sh` (or
`cmake --build build -j2`). The largest translation units need ~1 GB each.

### `error: cannot call member function … without object` or any other compile error
You are building a version older than 0.3.0, or a partially applied patch.
`./deploy.sh --update` (git) or re-extract a fresh release. If it still
fails, post the first `error:` line as an issue — it is a code bug, not
an environment problem.

### `Permission denied` while building, or `chmod`/`cp` errors from deploy.sh
Root-owned leftovers from running `sudo ./deploy.sh` once, or a checkout
extracted by root. `deploy.sh` now detects files in `build/`, `bin/`,
`backends/`, `scripts/` that you don't own and `chown`s them back after one
sudo prompt. By hand:

```bash
sudo chown -R "$(id -un)" .        # inside the iNode-VPN folder
./deploy.sh --fix-perms
```

`✗ … is not writable by <you>` means the whole folder is read-only for you
(extracted into `/opt` by root, read-only mount): same fix, or copy the
folder somewhere you own.

### `⚠ could not tighten permissions on backends/ or scripts/`
Same ownership problem as above, caught later. Apply the `chown` fix, then
`./deploy.sh --fix-perms`.

### `⚠ backends/h3csvpn is still group/other-writable`
After tightening, something in `backends/h3csvpn` is still writable by
group/others — typically an ACL or a filesystem that ignores mode bits
(FAT/NTFS/some network mounts). Move the checkout to a native Linux
filesystem (ext4/xfs/btrfs) or do a system install (`./deploy.sh`) — the
installed copy under `/usr/libexec` has fixed 644/755 permissions.

### `✗ git pull failed`
Local edits conflict with upstream. `git stash && ./deploy.sh --update &&
git stash pop`, or `git status` and commit/discard the changes.

### `⚠ Running via sudo`
Informational: you invoked `sudo ./deploy.sh`. The script continues and gives
`build/` and `bin/` back to your user at the end. Next time run it without
sudo — it asks for root only for the install step.

### `iNode-VPN.sh: not built yet — run: …/deploy.sh --local`
Portable launcher run before a build. Run the command it prints.

### `bash: ./deploy.sh: Permission denied`
Exec bit lost (zip download). `bash deploy.sh` — it restores `+x` on every
shipped script for next time.

### `dpkg: error … qt6-tools-dev` / a KF6 package "has no installation candidate"
Only optional packages; `deploy.sh` installs them one at a time and prints
`- <pkg> (not available, skipped)`. Nothing to do — the build proceeds
without KWallet/translations. Install KF6 dev packages later and rebuild if
you want KWallet on KDE.

---

## 2. Launching the app

### `This application failed to start because no Qt platform plugin could be initialized`
- **X11 desktop:** `qt.qpa.plugin: From 6.5.0, xcb-cursor0 or libxcb-cursor0
  is needed` → install `libxcb-cursor0` (Debian/Ubuntu/Kali) /
  `xcb-util-cursor` (Fedora/Arch). `deploy.sh` pulls it in on new installs.
- **SSH / headless / TTY:** the GUI needs a display. `--doctor`, `--version`,
  `--help`, `--list-profiles`, `--status` and `--disconnect` switch to the
  offscreen platform automatically; for anything else use `ssh -X`, run in
  your desktop session, or `QT_QPA_PLATFORM=offscreen` for scripting.
- **Wayland-only session and it still fails:** `QT_QPA_PLATFORM=wayland` (needs
  `qt6-wayland` / `qt6-qtwayland`).

### `kf.iconthemes: Icon theme "…" not found`
Harmless noise from the icon-theme lookup on non-KDE desktops. Ignore, or
install `breeze-icon-theme` / `adwaita-icon-theme` to silence it.

### `QThreadStorage: entry … destroyed before end of thread`
Harmless Qt shutdown message on some Qt 6.10 builds when exiting right after
a text-only command. Ignore.

### `iNodeClient-Qt: command not found` after a system install
`/usr/local/bin` (the default `PREFIX`) is not on your `PATH`, or you used a
custom `PREFIX`. Use the desktop menu entry, `/usr/local/bin/iNodeClient-Qt`,
or add the prefix's `bin` to `PATH`. `deploy.sh` prints a hint when this
happens.

### No menu entry / no icon after install
Caches not refreshed. `deploy.sh` runs `update-desktop-database` and
`gtk-update-icon-cache`; if your DE still doesn't show it, log out and in, or
run `update-desktop-database ~/.local/share/applications` for a user-local
copy. Custom `PREFIX`: make sure `$PREFIX/share` is in `XDG_DATA_DIRS`.

### `--status` prints `not running` (exit 3) although the window is open
The running instance could not create its control socket, or it was started
by a different user. Check the log pane for `control socket unavailable`:
`$XDG_RUNTIME_DIR` must exist and be writable (it is `/run/user/<uid>` on
systemd systems; falls back to `/tmp`). Restart the app after fixing.
`--status` exit codes: **0** connected, **2** running but not connected,
**3** no instance.

### A second window opens instead of raising the first
Same cause as above (control socket unavailable) — the new process could not
reach the running one. Fix the socket dir; meanwhile close the duplicate.

### `--connect "Name"` says `error: no profile named 'Name'`
Names are case-sensitive and must match exactly. `iNodeClient-Qt
--list-profiles` prints them.

### `--connect` from a terminal shows nothing and exits 0
An instance was already running, so the request was forwarded to it; the
running window is where the connection happens (and where errors show).
`--status` to check.

### `no profile named '…'` in the log at startup
`--connect` with a wrong name, or a stale autostart entry. Fix the name or
turn *Launch at login* off/on in Settings to rewrite the autostart file.

### App closes instead of minimizing to the tray
No system tray available (some GNOME setups without the AppIndicator
extension, Wayland compositors without StatusNotifier). Install a tray
extension, or run with `--minimized` and use `--status`/`--disconnect`. The
app deliberately quits on close when there is no tray to hide in.

### Window is blank / theme looks broken
Try *Settings → Theme → System default*. Custom themes are plain Qt style
sheets and can clash with some platform styles.

---

## 3. Credentials

### `⚠ Credentials cannot be saved: no keyring, and libcrypto is missing` (status bar)
No KWallet, no Secret Service daemon answered, and `libcrypto.so.3` could not
be loaded, so there is nowhere encrypted to keep passwords. Install
`libssl3` / `openssl-libs` / `openssl` (provides libcrypto) for the AES file
fallback, or start a keyring (`gnome-keyring-daemon`, KeePassXC with Secret
Service enabled, `ksecretd`). Until then you are asked for the password at
every connect; nothing is written in plaintext.

### `No stored password for profile.`
Only on builds before 0.3.0. Update; the GUI now asks at connect time
whenever nothing is stored. (Old fix: edit profile, type password, tick
*Store password*, save.)

### "Password not saved" dialog / `could not store secret '…' in …` in the log
The active backend refused the write. Per backend:
- **Secret Service (login keyring):** the keyring is locked (autologin
  sessions don't unlock it) — open *Passwords and Keys* (seahorse) or
  KeePassXC and unlock; or set the keyring password to empty for autologin
  boxes. `secret-tool store --label test a b` reproduces the failure outside
  the app.
- **KWallet:** wallet closed or the request was cancelled in the KWallet
  dialog. Open KWallet Manager, make sure the *Network wallet* opens.
- **AES-256-GCM file:** you cancelled the master-password prompt, or
  `~/.config/iNodeClient-Qt/secrets.enc` is unwritable — check permissions
  (must be yours, 0600).
The password typed is still used for the current session.

### Master-password prompt appears at every start
The AES file fallback is active (no keyring). It holds the key in memory
only, so it asks once per process. To stop the prompts, run a keyring
(above) — entries are re-created there the next time you save each profile.

### `Passwords did not match — no password set.`
Master-password confirmation mismatch on first use. Save the profile again
and type it twice identically.

### A gpg/pinentry prompt appears once after upgrading
Migration of the pre-0.3 GnuPG store: it is decrypted once and re-sealed
into the active backend, then renamed `secrets.gpg.migrated`. Cancelling
postpones it to the next run.

### `legacy GPG credential store found but gpg is not installed`
Install `gnupg` once so the migration can read the old file, or delete
`~/.config/iNodeClient-Qt/secrets.gpg` if you don't need those passwords.

### `could not decrypt legacy GPG credential store (agent refused or passphrase cancelled)`
gpg-agent could not unlock the key. Run `gpg --decrypt
~/.config/iNodeClient-Qt/secrets.gpg` in a terminal to see the real error,
then start the app again.

### `GPG store migration incomplete (n/m) — legacy file kept`
Some entries could not be written to the new backend (keyring locked
mid-way). Unlock the keyring and restart; the migration is idempotent.

### Wrong password used after you changed it on the server
The profile keeps the stored secret. Edit the profile, type the new
password, save — it overwrites the stored entry. Or *Forget* (remove and
re-add the profile) to clear every field.

### Which backend is in use?
`iNodeClient-Qt --doctor` → `active: …`. Order: KWallet (KF6 build) →
Secret Service → AES-256-GCM file. Forgetting a profile clears its entries
from **all** of them.

---

## 4. Privileged helpers & polkit

Tunnels, static IPs and 802.1X supplicants need root. The GUI runs a small
helper (`inode-svpn-helper`, `inode-l2tp-helper`, `inode-dot1x-helper`,
`inode-ipcfg-helper`) through `pkexec`, falling back to non-interactive
`sudo`, or directly when the app itself is root.

### No authentication dialog appears; log shows `pkexec` denied / `sudo: a password is required`
No **polkit authentication agent** is running in your session, so pkexec
cannot ask you. GNOME/KDE/XFCE/Cinnamon/MATE start one automatically;
minimal WMs (i3, sway, openbox) don't. Start one, e.g.
`/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1 &` or
`lxpolkit &` (package `policykit-1-gnome` / `lxpolkit` / `polkit-kde-agent-1`).
Alternative without an agent — allow only the helper, nothing else:

```bash
echo "$(id -un) ALL=(root) NOPASSWD: /usr/libexec/iNodeClient-Qt/inode-svpn-helper *" \
  | sudo tee /etc/sudoers.d/inode-svpn-helper
sudo chmod 440 /etc/sudoers.d/inode-svpn-helper
sudo visudo -cf /etc/sudoers.d/inode-svpn-helper
```

(Portable mode: use the repo path `<repo>/scripts/inode-svpn-helper`.)

### `[MISSING] polkit action org.inode.ClientQt.*` in `--doctor`
Portable mode (expected — pkexec still works, prompting generically), or a
system install whose policy did not reach `/usr/share/polkit-1/actions`.
polkit **only** scans that directory; a policy under `/usr/local/share` is
ignored. `./deploy.sh` mirrors it; by hand:
`sudo cp src/resources/org.inode.ClientQt.policy /usr/share/polkit-1/actions/`.

### pkexec prompt says "run program" / generic text instead of "manage the iNode … tunnel"
The policy isn't registered (see above) or the helper path differs from the
one hardcoded in the policy (`/usr/libexec/iNodeClient-Qt/…`). Cosmetic; a
system install fixes it.

### `Need root to create the VPN tunnel device, but neither pkexec nor sudo is available`
Install `pkexec` (`polkitd pkexec` on Debian ≥ 12/Ubuntu ≥ 23.04,
`policykit-1` on older Ubuntu, `polkit` elsewhere) or `sudo`.

### `helper: must be run as root (invoke via pkexec)`
You ran a helper directly as a normal user. They are not meant to be run by
hand; the GUI/`svpn-connect.sh` escalate for you. For manual use:
`pkexec /usr/libexec/iNodeClient-Qt/inode-svpn-helper …`.

### `helper: backend is group/other-writable; refusing to load it as root`
The root helper only imports Python from a tree nobody but the owner can
write to. Fix: `./deploy.sh --fix-perms` (or `chmod -R go-w backends`),
then verify `find backends/h3csvpn -perm /022` prints nothing. Causes:
umask 002 checkout, a stray `__pycache__`, files on FAT/NTFS. System
installs never hit this.

### `helper: refusing backend under a transient/world-writable dir`
The backend lives under `/tmp`, `/var/tmp`, `/dev/shm`, `/run` or `/proc`.
Move the checkout to your home or `/opt` and rebuild (`./deploy.sh --local`).

### `helper: backend not found at …` / `helper: backend path does not resolve`
`backends/h3csvpn/__init__.py` is missing at the path the GUI passed. In
portable mode the tree must stay intact next to `bin/`; in a system install
re-run `./deploy.sh`. `--doctor` shows whether the module is found.

### `helper: python3 not found`
Root's `PATH` has no `python3`. Install `python3` system-wide (not only in a
venv/conda for your user).

### `helper: invalid --name` / `--name required` / `unknown arg` / `unknown subcommand`
The GUI and helper versions disagree (helper updated while the GUI was old,
or vice-versa), or a hand-typed invocation. Rebuild + reinstall so both
match (`./deploy.sh --update`).

### `warning: stale pidfile (pid N is not the h3csvpn backend); not signalling`
A previous backend crashed and its PID was reused by an unrelated process.
Nothing was killed; the pidfile in `/run/inode-svpn/` was removed. Connect
again.

### `Neither minieap nor mentohust is installed.` (exit 127)
802.1X needs one supplicant. Build/install `minieap` (preferred) or
`mentohust` and make sure it is on root's `PATH` (`/usr/local/bin` is fine).

### Helpers `[MISSING]` in `--doctor`
Portable mode: `scripts/` must sit next to `bin/`. System install: re-run
`./deploy.sh`; helpers go to `/usr/libexec/iNodeClient-Qt/`.

---

## 5. SSL VPN

The GUI drives the bundled Python backend (`backends/h3csvpn`) through the
root helper. Backend errors appear in the log as `SSL VPN: <message>`; the
raw backend output (lines starting `[x]`, `[!]`, `[captcha]`, `[+]`) is
logged just above it. `svpn-connect.sh` shows the same lines directly.

**Isolate first** (no root, no tunnel — proves gateway, TLS, CAPTCHA and
credentials):

```bash
./svpn-connect.sh --auth-only vpn.example.com:443 <user> <domain>
```

Needed `--doctor` items: `python3`, `pkexec`, `inode-svpn-helper`,
`h3csvpn python package` (and `tesseract` for CAPTCHA gateways).

### Exit codes (backend → GUI fallback text)

| Exit | GUI fallback message | Meaning |
|---|---|---|
| 0 | — | clean logout / user disconnect |
| 2 | `authentication or connection failed (check username, password, domain and gateway)` | login phase failed; the backend's own `[x]` line above names the cause |
| 3 | `tunnel setup failed after a successful login` | login OK, `NET_EXTEND` failed |
| 4 | `the tunnel needs root privileges` | backend ran without CAP_NET_ADMIN |
| 5 | `connection lost (gateway closed the tunnel or no heartbeat response)` | tunnel was up, then died; also `ip`/TUN/route errors |
| 126/127 | `could not gain privileges (pkexec/sudo denied or no polkit agent running)` | you cancelled the polkit dialog, no agent, or sudo needs a password |
| other | `backend exited with code N` | helper `die()` (see §4) or a crash — read the lines above it |

### Profile pre-flight

| Message | Fix |
|---|---|
| `SSL VPN profile has no gateway host.` | Fill *Gateway* (host or host:port or https URL). |
| `Username is required.` | Fill *Username*. |
| `Bundled SSL VPN backend (h3csvpn) not found…` | Portable: keep `backends/` next to `bin/`. Installed: re-run `./deploy.sh`. `--doctor` shows the lookup result. |
| `python3 is required to run the SSL VPN backend.` | Install `python3` (≥ 3.9). |
| `Could not launch the SSL VPN helper.` | Helper not executable/missing: `./deploy.sh --fix-perms` (portable) or `./deploy.sh` (system). |

### `[x] connection error: …`
| Text | Fix |
|---|---|
| `[Errno -2] Name or service not known` / `-3 Temporary failure in name resolution` | DNS: check the hostname, `/etc/resolv.conf`, VPN-less connectivity. Try the IP. |
| `Connection refused` | Wrong port (H3C usually 443, sometimes 4430/8443) or the SSL VPN service is off. `curl -k https://gw:port/svpn/index.cgi -o /dev/null -w '%{http_code}'` should print 302/200. |
| `timed out` / `No route to host` | Firewall or the gateway only reachable from inside; SDP gateways need the SPA knock first (§10). |
| `Network is unreachable` | No default route on the host (Wi-Fi/Ethernet down). |

### `[x] protocol/TLS error: …`
| Text | Fix |
|---|---|
| `CERTIFICATE_VERIFY_FAILED … self signed certificate` / `certificate has expired` / `Hostname mismatch` | The gateway cert isn't trusted. **Pin it**: profile → *Fetch pin* (or `openssl s_client -connect HOST:PORT </dev/null 2>/dev/null \| openssl x509 -fingerprint -sha256 -noout`, then `--pin-sha256 AA:BB:…`). Or set *Trust → CA file* / `--cafile`. `--insecure` (CLI) disables verification — unsafe, last resort. The backend prints this same hint. |
| `certificate pin mismatch: peer=… expected=…` | The gateway's cert changed (renewed) or you are being intercepted. Verify out-of-band, then *Fetch pin* again. |
| `[SSL: WRONG_VERSION_NUMBER]` / `UNEXPECTED_EOF` | Not TLS on that port (plain HTTP, or a proxy banner). Check the port. |
| `[SSL: DH_KEY_TOO_SMALL]` / `SSLV3_ALERT_HANDSHAKE_FAILURE` / `NO_CIPHERS_AVAILABLE` | Ancient gateway ciphers. Pinning (`--pin-sha256`) or `--insecure` lowers OpenSSL's SECLEVEL automatically; also try `--min-tls 1.0`. |
| `bad status line: …` / `line/marker not found within 65536 bytes (hostile or non-HTTP response)` | Something that isn't an H3C gateway answered (captive portal, proxy, wrong host). Check the URL in a browser. |
| `response NNN has no Content-Length and is not chunked` / `declared body size … exceeds cap` / `too many chunks` | Broken or hostile HTTP from the gateway/proxy. Bypass any HTTP proxy (`unset https_proxy`), report the firmware version. |
| `load_cert_chain` / `PEM lib` errors | `--client-cert`/`--client-key` (profile *User certificate*) is not a valid unencrypted PEM pair. Convert: `openssl pkcs12 -in cert.p12 -out cert.pem -nodes`. |

### `[x] gateway sent an unreadable response: …`
The login reply wasn't parseable XML: wrong host/port, an HTML error page,
or a gateway sending DOCTYPE/ENTITY declarations (rejected on purpose).
Verify the URL; run with `-v` to see the exchange; if it is a real H3C
gateway, report the firmware.

### `[x] index.cgi returned 403 Forbidden` (or other status)
The gateway refused the capability probe. 403: client IP/geo restriction or
the SSL VPN service isn't enabled on that virtual host. 503: gateway
overloaded/maintenance. 302 after 10 hops: redirect loop — try the
`https://host:port/svpn/index.cgi` URL explicitly.

### `[x] authentication failed: result='Failed' msg='…'`
Everything before the password check worked. `msg` is the gateway's own
text:

| Gateway text (typical) | Meaning / fix |
|---|---|
| *incorrect username or password, authentication server error, or number of users reaching the maximum allowed by an account* | Wrong password/domain, expired account, or concurrent-login cap. Confirm with `--auth-only`; check the **Domain** field (`RADIUS`, `system`, `local` … as your admin calls it). Update the stored password after changing it. |
| *Verify code error* | CAPTCHA was wrong — see §6. |
| *user is locked* / *account disabled* | Ask the administrator. |
| `SSLVPN_NotSupportAuthPkt` | Gateway wants a different login packet (RSA-encrypted password variant): try `--rsa-pubkey <gateway public key>` (needs `pip install cryptography`). See [INTEROP.md](INTEROP.md). |
| *license* / *maximum users* | Gateway license exhausted; try later. |

### `[x] could not solve the CAPTCHA within N attempts …`
See §6.

### `[x] RSA password mode requires the 'cryptography' package`
`pip install cryptography` (or `pip install backends/h3csvpn/[rsa]`), or
drop `--rsa-pubkey`.

### `[x] cannot read --rsa-pubkey: …`
Path wrong or unreadable. Use an absolute path to a PEM/DER public key.

### `[x] invalid SPA env value: …`
`H3C_SPA_KEY`/`H3C_SPA_AID` must be hex, `H3C_SPA_PORTS` comma-separated
numbers (GUI: the SPA fields on the SSL VPN/SDP profile). See §10.

### `h3c-svpn: error: …` (usage errors, exit 2)
| Text | Fix |
|---|---|
| `invalid gateway: empty host in ':443'` | Type the host before the colon. |
| `invalid gateway: invalid literal for int() … 'abc'` | Port must be numeric. |
| `--ifname must be at most 15 bytes` | Linux interface names are ≤ 15 chars; keep `inode%d`. |
| `the following arguments are required: -u/--user` | `svpn-connect.sh <gw> <user>`; the GUI fills this from the profile. |
| `argument --language: invalid choice` | `cn` or `en`. |

### `[x] tunnel setup failed: did not receive a valid network-config frame`
Login worked; the gateway never sent an IP for the tunnel (20 s). Causes:
the account has no SSL VPN *IP access* resource assigned (only web/TCP
access) — ask the admin; a firmware that sends the config in a form we don't
parse — capture with `-vv` and report; a proxy in between. Also seen as
`[x] tunnel setup failed: tunnel socket closed during preamble`.

### `[x] tunnel needs root (CAP_NET_ADMIN) …` (exit 4)
The backend ran unprivileged. GUI/`svpn-connect.sh` normally escalate — if
you see this, the helper was bypassed (`sudo` rule pointing at the wrong
path?) or you ran `python3 -m h3csvpn` yourself. Use `sudo`, or
`--no-tunnel` to test auth only.

### `[x] the 'ip' command (iproute2) is required …`
Install `iproute2` (Debian/Ubuntu/Arch) or `iproute` (Fedora/openSUSE).
Minimal containers often lack it.

### `[x] /dev/net/tun is missing …`
`sudo modprobe tun`; make it persistent with `echo tun | sudo tee
/etc/modules-load.d/tun.conf`. Containers: run with `--device /dev/net/tun
--cap-add NET_ADMIN`. WSL2 needs a kernel with TUN (default kernels have it).

### `[x] tunnel I/O error: …`
| Text | Fix |
|---|---|
| `[Errno 1] Operation not permitted` on TUNSETIFF | No CAP_NET_ADMIN (container / hardened kernel / AppArmor). Run privileged or fix the profile. |
| `[Errno 16] Device or resource busy` | An interface with that name already exists from a crashed run: `sudo ip link delete inode0`. |
| `[Errno 2] … 'ip'` | Older builds; install iproute2 (above). |

### `[x] tunnel configuration error: …`
| Text | Fix |
|---|---|
| `` `ip addr add …` failed: RTNETLINK answers: File exists`` | Stale address from a previous run: `sudo ip link delete inode0`, reconnect. |
| `full-tunnel mode needs the original default gateway and the server IP …` | The gateway asked for redirect-all but the host has no default route (offline?) or the gateway hostname didn't resolve. Fix connectivity, or tick *Split tunnel* (`--split-tunnel`). |
| `VirtualNIC requires an IPv4 address` | Gateway pushed an IPv6-only config — unsupported; ask for an IPv4 pool. |
| `frame payload exceeds 65535 bytes` | MTU misconfiguration on the TUN; report with `-vv`. |

### `[x] connection lost: tunnel socket closed` (exit 5)
The gateway dropped the session: idle/absolute timeout, admin kick,
concurrent login elsewhere (`gateway forced log-off` in `-v` output),
gateway reboot, or 5 missed heartbeats (`heartbeat: no response, going
offline`) — i.e. the underlying network went away. Auto-reconnect (profile
option) handles the transient cases; for repeated drops on Wi-Fi, check
power management (`iw dev wlan0 set power_save off`).

### `[+] Connected` but nothing works
See §7.

### `warning: gateway looks like legacy V3` (with `-v`)
The gateway is the old V3 SSL VPN; this client implements V7. Login may
still work; the tunnel usually doesn't. Ask for a V7-capable gateway.

### `svpn-connect.sh`: `Need root (pkexec or sudo) to create the tunnel — or use --auth-only.`
Install `pkexec` or `sudo`, or test with `--auth-only`.

### GUI shows `Connected` for `--no-tunnel` tests
Expected: the backend prints `Authentication succeeded (--no-tunnel).`
which the GUI reads as success. Only the CLI uses `--no-tunnel`.

---

## 6. CAPTCHA

H3C gateways may require a 4-character image CAPTCHA. The backend fetches
it, OCRs it with `tesseract`, retries on `Verify code error`, and remembers
the toggles in `~/.config/h3csvpn/config.json`.

### `[captcha] no OCR (tesseract missing); manual entry.`
Install `tesseract-ocr` (Debian/Ubuntu/Kali), `tesseract` (Fedora/Arch),
`tesseract-ocr` (openSUSE). The GUI cannot type a CAPTCHA for you, so on
CAPTCHA gateways tesseract is effectively required for the GUI.

### `[!] CAPTCHA required but no input is available; enable --auto-captcha or pass --vldcode.`
Manual entry was needed but there is no terminal (GUI, or piped CLI).
Install tesseract (above) so it is solved automatically, or use the CLI in
a terminal: `./svpn-connect.sh --auth-only gw user domain -- --show-captcha`,
read the image, then pass `-- --vldcode ABCD`.

### `[x] could not solve the CAPTCHA within N attempts (OCR produced no confident read …)`
Every OCR attempt was low-confidence. Raise the budget (`-- --captcha-retries 20`),
solve manually (`--no-auto-captcha` + `--show-captcha` + `--vldcode`), or
install a newer tesseract (≥ 5 reads these images far better; `tesseract
--version`). Make sure the English data file is present
(`tesseract-ocr-eng` / `tesseract-data-eng`).

### `[captcha] rejected: 'Verify code error'` repeats until failure
OCR reads confidently but wrongly — usually a distorted font. Same fixes as
above; `--show-captcha` shows what the OCR saw.

### `[captcha] image:` shows garbage / nothing
The terminal lacks 24-bit colour or the BMP couldn't be decoded (gateway
served an HTML error page instead of an image — check the URL). Use a
modern terminal (kitty, GNOME Terminal, Konsole).

### Login is slow (10–20 s per attempt)
Each attempt fetches a fresh CAPTCHA and runs tesseract (20 s timeout each).
Normal; lower `--captcha-retries` if you'd rather fail fast.

### `[config] saved captcha settings to …` every run
Informational: you passed a persisted toggle. Nothing to fix.

### Settings don't persist / reset to defaults
`~/.config/h3csvpn/config.json` is unwritable or corrupt (it is silently
recreated). Check permissions or delete it.

---

## 7. Tunnel, routes & DNS

### Tunnel is up but the intranet is unreachable
```bash
ip addr show inode0          # has the IP from the connect line?
ip route                     # routes via inode0 for the corporate subnets?
ping -c1 <intranet ip>       # by IP first, then by name
```
- **No routes via `inode0`:** the gateway pushed none (only web resources
  assigned to your account) — ask the admin; or *Split tunnel* is on while
  the gateway expected redirect-all: turn it off.
- **Routes exist, ping fails:** the gateway's ACL/resource list doesn't
  include that host; or asymmetric routing on the corporate side. Check with
  the admin; compare with the official client on the same account.
- **Works by IP, not by name:** DNS — below.

### Names don't resolve while connected
The gateway pushed no DNS (connect line shows `dns=-`): configure the
corporate DNS on the profile side is not supported — use the IP, or add
the corporate resolver to `/etc/resolv.conf` manually.
`[!] could not back up /etc/resolv.conf … leaving DNS unchanged`: `/etc` is
read-only or `resolv.conf` is immutable (`lsattr /etc/resolv.conf`; `chattr
-i`). With **systemd-resolved**, the backend rewrites the real file behind
the symlink; if your resolver ignores it, add the DNS to the interface:
`resolvectl dns inode0 <ip>; resolvectl domain inode0 ~corp.example`.

### DNS stays broken after disconnect
The original `/etc/resolv.conf` is restored from
`/etc/resolv.conf.h3c-svpn.bak` on every clean exit and on the next
connect. After a hard crash: `sudo cp /etc/resolv.conf.h3c-svpn.bak
/etc/resolv.conf` or `sudo systemctl restart NetworkManager`.

### Internet stops working while connected
The gateway pushed a default route (redirect-all) and its own egress is
slow/filtered. Tick *Split tunnel* on the profile (`--split-tunnel`) to keep
only corporate subnets in the tunnel. Some policies forbid split tunnelling
— then it's by design.

### Everything routes into the tunnel, including the gateway itself (loop)
Fixed in the backend (the gateway IP is always excluded); if you still see
it, run with `-vv` and report the `ROUTES`/`EXCLUDE` block.

### MTU problems (large downloads stall, SSH hangs after login)
`sudo ip link set inode0 mtu 1300`. The gateway rarely pushes an MTU.

### `inode0` remains after disconnect
Crashed backend: `sudo ip link delete inode0`; the pidfile lives in
`/run/inode-svpn/`. Reconnect.

### IPv6
Only IPv4 tunnel addresses are supported; IPv6 routes pushed by the gateway
are installed best-effort. Disable IPv6 on the host if corporate IPv6
leaks matter to you.

---

## 8. 802.1X & WLAN

Needed: `minieap` (preferred) or `mentohust` in root's PATH, `pkexec`,
`inode-dot1x-helper`; WLAN additionally `nmcli` (NetworkManager).

| Message | Fix |
|---|---|
| `No network interface selected for 802.1X profile.` | Pick the interface on the profile (Advanced tab). |
| `Neither minieap nor mentohust found in PATH.` | Build/install one: https://github.com/updateing/minieap (`make && sudo make install`). |
| `pkexec is required to run the 802.1X supplicant …` | Install polkit/`pkexec` (802.1X has no sudo fallback) or run the client as root. |
| `The 802.1X helper (inode-dot1x-helper) was not found.` | Re-run `./deploy.sh` (system) or keep `scripts/` next to `bin/` (portable). |
| `802.1X authentication rejected by the switch: …` | Wrong username/password/domain, wrong *Auth mode* (try HC-CHAPv2 ↔ EAP-MD5 ↔ PEAP), or the port isn't 802.1X-enabled. Campus builds may need extra `--rjv3`/carrier flags in *Extra args* — compare with a capture of the official client (PROTOCOLS.md). |
| `802.1X supplicant exited with code N before authenticating` | Interface down/unplugged, wrong interface, or supplicant flags rejected — read its output above. `ip link set <if> up`. |
| `Process error: N` | 0 = failed to start (helper/supplicant missing or not executable), 1 = crashed, 2 = timed out. |
| Authenticated but no IP | 802.1X only opens the port. Set *IP mode* on the profile: DHCP (renews via nmcli/dhclient) or Static. `dhcp: no nmcli or dhclient found` → install one. `dhcp: … timed out` → the DHCP server isn't answering on that VLAN. |
| `static IP: need root but neither pkexec nor sudo is available` / `helper timed out` | Same privilege fixes as §4; check `ip addr` for a conflicting address. |
| `IP config: Static mode but no address set; skipping` | Fill the static IP fields or switch to DHCP. |
| `WLAN requires nmcli (NetworkManager) …` | Install NetworkManager or leave the SSID empty to reuse an already-associated interface. |
| `Wi-Fi association failed (nmcli exited with code N)` | Wrong SSID/passphrase (nmcli exit 4 = wrong password), out of range (exit 10 = no such SSID), interface unmanaged (`nmcli device`), or a hidden SSID (tick *Hidden SSID*). Run `nmcli device wifi list` and `nmcli device wifi connect <ssid> --ask` by hand. |
| Disconnects every few minutes | Switch re-auth timer; enable the heartbeat option on the profile (`-r`/`-t` for minieap/mentohust) or lower its interval. |

---

## 9. L2TP/IPSec

Needed: `strongswan` (`ipsec` command), `xl2tpd`, `ppp`, `pkexec`,
`inode-l2tp-helper`. The helper writes fragments under
`/etc/ipsec.conf.d/` and `/etc/xl2tpd/xl2tpd.conf.d/`.

| Message | Fix |
|---|---|
| `L2TP/IPSec requires a server host and PSK.` | Fill *Server* and *PSK*. |
| `Need root for L2TP/IPSec, but neither pkexec nor sudo is available.` | §4. |
| `Could not start the L2TP/IPSec helper.` | Helper missing/not executable — reinstall. |
| `L2TP/IPSec helper timed out.` (120 s up / 30 s down) | IKE never completed: UDP 500/4500 blocked, wrong PSK (strongSwan logs `AUTHENTICATION_FAILED`), server down. `sudo ipsec statusall`, `journalctl -u strongswan -u xl2tpd`. |
| `L2TP/IPSec bring-up failed — see the ipsec/xl2tpd output above.` | Read the helper output: `helper: xl2tpd control socket not present` → xl2tpd isn't running (`systemctl start xl2tpd`); `helper: ppp0 did not come up` → PPP auth failed (wrong username/password) or the server rejected the L2TP session; `invalid --server` → hostname with spaces/control chars. |
| `helper: invalid --psk (quote/backslash not supported)` | The helper refuses PSKs containing `"` or `\`; change the PSK or escape at the server. |
| Connects, no traffic | PPP up but no routes: add them by hand (`ip route add 10.0.0.0/8 dev ppp0`); the helper doesn't install routes beyond what pppd sets. |
| Works once, then never again | Stale IPsec SA/xl2tpd session: Disconnect (runs `down`), `sudo ipsec down inode-<name>`, `sudo systemctl restart xl2tpd`. |
| iMC/EIA server that needs H3C's IKE vendor-ID exchange | Not supported (PROTOCOLS.md). |

---

## 10. Portal, EAD & SDP

### Portal (v2 / H3C dialect)
| Message | Fix |
|---|---|
| `Portal requires a server host.` / `Username is required.` | Fill the fields. |
| `Portal: failed to bind UDP socket: …` | Another process holds every port? Rare; check `ss -ulnp`. |
| `Portal: DNS resolution failed for …` | Use the BAS IP instead of a name. |
| `Portal: no response from server (timeout).` | Wrong server/port (2000 default, 50100 on some iMC), UDP blocked, or you are not on the portal VLAN. `nc -u <bas> 2000` reachability; try the other port. |
| `Portal: challenge rejected (code N)` / `Portal: auth rejected (code N)` | Wrong **shared secret** (defaults `h3c`, `huawei3com`, `portalsecret`; ask the admin), wrong password, or wrong dialect (switch v2 ↔ H3C). Code 1 = rejected, 2 = link established already, 3 = already logged in elsewhere, 4 = busy — retry. |
| `Portal: ACK_CHALLENGE contained no challenge attribute` | Server in PAP mode: set *Auth mode* to PAP on the profile. |
| `Portal(H3C): login rejected (code N)` | The H3C dialect is experimental; the anti-track hash reply is best-effort (`answered anti-track hash challenge (best-effort…)`). Try the v2 dialect first. |
| Logged in but dropped after ~5 min | Keep-alive rejected; check the shared secret (the MD5 authenticator on heartbeats fails silently). |

### EAD posture
| Message | Fix |
|---|---|
| `EAD requires a posture server (eadServer or serverHost).` | Fill *EAD server* (iMC EIA, UDP 9019). |
| `EAD: DNS resolution failed for …` | Use the IP. |
| `EAD: no response from posture server after 3 attempts.` | UDP 9019 blocked / wrong server; you may not need EAD at all — untick *EAD required*. |
| `EAD: posture rejected by server (SEC_CHECK_FAIL).` | The server's policy failed the (synthetic, always-compliant) posture; the protocol is implemented from RE and untested live — see SECURITY-FINDINGS P1 and PROTOCOLS.md. Report the server's reply with a capture. |
| `EAD: bad packet head id` / `short packet` | Something else answered on 9019; wrong server. |

### SDP / Zero-Trust (SPA knock + SSL VPN)
| Symptom | Fix |
|---|---|
| `[x] connection error: timed out` on an SDP gateway | The knock wasn't accepted so port 443 stayed closed. Verify *SPA key* (hex), *AID* (hex), *ports*; the knock goes to UDP **8000** by default — check it isn't filtered. |
| `[x] invalid SPA env value` | Key/AID must be hex, ports numeric. |
| Knock accepted yesterday, refused today | Registration expired/rotated — the per-client key comes from SDP registration, which this client does **not** do (out of scope); take the fresh key/AID from an enrolled official client. |

---

## 11. Reconnect, tray & UI

### `not auto-reconnecting — this looks like a permanent error: …`
The last error matched the permanent list (bad credentials, certificate,
CAPTCHA, missing tool/helper, missing password, privilege denied, gateway
verdicts). Fix the cause; reconnect manually.

### `auto-reconnect: giving up after N attempts`
Retry budget (profile *Max retries*, default 5, exponential back-off capped
at 60 s) exhausted. Raise it, or fix the underlying drop (§5/§7).

### Reconnect keeps trying although the error is obviously permanent
Please report the exact message; the heuristic is a keyword list
(`MainWindow::isPermanentError`).

### No notifications
*Settings → Show desktop notifications* and a running notification daemon
(`notify-send test` should pop something). Without a tray, errors appear as
dialogs instead.

### Tray icon missing
See §2 "App closes instead of minimizing to the tray".

### `Import from official install` finds nothing
`No profiles were imported from …`: the folder must contain
`custom/clientfiles/locations.xml` (default install:
`/opt/apps/com.client.inode.amd/files`). `locations.xml not found` /
`failed to parse locations.xml` in the log name the exact problem.
Imported profiles have no credentials — edit each.

### `profiles: cannot write … — changes are not persisted`
`~/.config/iNodeClient-Qt/profiles.json` is unwritable (permissions, full
disk, read-only home). Fix and save again. A corrupt file loads as an
empty list — restore from backup or recreate profiles.

### "Launch at login" doesn't stick
`~/.config/autostart/iNodeClient-Qt.desktop` couldn't be written (stderr:
`iNode: cannot write autostart entry`). Check permissions of
`~/.config/autostart`.

### "Fetch pin" fails
`openssl is not installed.` → install `openssl`. `Could not read a
certificate from the gateway.` → wrong host/port or unreachable (it uses
`openssl s_client`; try that by hand). `Timed out contacting the gateway.`
(15 s) → firewall. `Could not parse a host from the gateway URL.` → type
`host:port` or `https://host:port`.

### "Renew DHCP" complains
`Select a profile with a configured interface, or connect first.` → the
button needs an interface (profile *Interface* or an active session).
`DHCP renew on X could not be started.` → no `nmcli`/`dhclient`, or no
privileges — see §8.

### Language / theme changes don't apply
Language takes effect on next launch. Themes are Qt style sheets; *System
default* resets.

---

## 12. Update & uninstall

### `./deploy.sh --update` says `Not a git checkout — skipping pull`
You installed from a zip/tarball. Download the new version, extract it
**over** this folder, run `--update` again (it rebuilds + reinstalls).

### After updating, the GUI still shows the old version (`--version`)
- System install but you launch the portable `./iNode-VPN.sh` (or vice
  versa): `which iNodeClient-Qt` vs `./bin/iNodeClient-Qt --version`.
- A running instance is the old binary: quit it (tray → Quit, or
  `iNodeClient-Qt --disconnect` then close), relaunch.

### Helpers refuse after an update (`helper: unknown arg …`)
GUI and helpers out of sync — one updated, the other not. `./deploy.sh`
(system) reinstalls both; portable mode uses the tree's `scripts/`.

### Uninstall leaves things behind
`./deploy.sh --uninstall` removes the binary, helpers, backend copy, policy,
menu entry and icon. It keeps:
- `~/.config/iNodeClient-Qt/` (profiles, `secrets.enc`) — `rm -rf` it if
  you want a clean slate; keyring entries: remove "iNode Client — …" items
  in Seahorse/KWallet Manager.
- `~/.config/h3csvpn/config.json`, `~/.local/share/iNodeClient-Qt/logs/`.
- `/etc/sudoers.d/inode-svpn-helper` if you created it; the L2TP
  fragments under `/etc/ipsec.conf.d/` and `/etc/xl2tpd/xl2tpd.conf.d/`.

### Downgrading
Profiles are forward-compatible JSON; secrets stored by 0.3 are in the
keyring/AES file and readable by 0.3+ only.

---

## 13. Logs & files

| What | Where |
|---|---|
| GUI log (same as the log pane) | `~/.local/share/iNodeClient-Qt/logs/iNodeClient-Qt.log` (Settings → Logging; level 0–5) |
| Profiles | `~/.config/iNodeClient-Qt/profiles.json` (no secrets inside) |
| Encrypted secrets (fallback backend) | `~/.config/iNodeClient-Qt/secrets.enc` (0600) |
| Keyring entries | Secret Service items labelled `iNode Client — <uuid>/<field>`; KWallet folder `iNodeClient-Qt` |
| Backend CAPTCHA settings | `~/.config/h3csvpn/config.json` |
| Control socket | `$XDG_RUNTIME_DIR/iNodeClient-Qt-<uid>.sock` (falls back to `/tmp`) |
| SSL VPN pidfiles (root) | `/run/inode-svpn/<name>.pid` |
| resolv.conf backup (root) | `/etc/resolv.conf.h3c-svpn.bak` |
| L2TP fragments (root) | `/etc/ipsec.conf.d/`, `/etc/xl2tpd/xl2tpd.conf.d/` |
| Installed files | `/usr/local/bin/iNodeClient-Qt`, `/usr/libexec/iNodeClient-Qt/` (helpers + `backends/`), `/usr/share/polkit-1/actions/org.inode.ClientQt.policy`, `/usr/local/share/applications/`, `…/icons/hicolor/` |
| Autostart entry | `~/.config/autostart/iNodeClient-Qt.desktop` |

**Getting a useful report together:**

```bash
iNodeClient-Qt --version; iNodeClient-Qt --doctor
./svpn-connect.sh --auth-only gw:443 user domain -- -vv 2>&1 | sed 's/password=[^&]*/password=***/'
tail -50 ~/.local/share/iNodeClient-Qt/logs/iNodeClient-Qt.log
```

Strip gateway hostnames, usernames and pins before posting (see
[USAGE.md → Test-gateway etiquette](USAGE.md#test-gateway-etiquette)).
