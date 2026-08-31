# iNode VPN Client

An open-source, interoperable VPN client that speaks the **H3C iNode** protocol
suite: a Qt6/KF6 desktop GUI plus a standalone pure-Python CLI backend for the
H3C SSL VPN ("V7"), with 802.1X, WLAN, L2TP/IPSec, Portal, EAD posture and
Zero-Trust SPA on top.

![Screenshot](docs/screenshot.png)

**Why:** a complete, working alternative to the proprietary H3C iNode
Intelligent Client (closed-source, ~71 MB, Qt5, Ubuntu-only, bundles ancient
OpenSSL 1.1). This project speaks the same wire protocols (reverse-engineered
from the official unstripped Linux client), runs anywhere Qt6 + Python 3.9+
run, is 100% FOSS (GPL-3.0 + MIT), and contains no vendor code.

## Protocols

| Protocol | Status | Backend |
|---|---|---|
| **SSL VPN** (H3C SVPN "V7") | Working | `backends/h3csvpn` (Python, clean-room) |
| **802.1X** (wired HC-CHAPv2) | Working | `minieap` / `mentohust` |
| **WLAN** (wireless 802.1X) | Working | NetworkManager + 802.1X |
| **Portal v2** (GB/T 28181) | Working | Native Qt UDP client |
| **L2TP/IPSec** | Working | strongSwan + xl2tpd |
| **EAD posture** | Implemented (untested vs live iMC) | Native UDP/9019 SEC protocol |
| **H3C Portal** (proprietary) | Experimental (faithful framing) | Native Qt UDP |
| **SDP** (Zero-Trust) | Experimental | SPA knock (RFC-4226 HOTP) + SSL VPN |

## Install

**One command** (detects your distro, installs deps, builds, installs
system-wide, registers polkit, then runs an environment self-check):

```bash
./deploy.sh
```

```bash
./deploy.sh --local       # portable build in ./bin — no root, run ./iNode-VPN.sh
./deploy.sh --uninstall   # remove the system install
./deploy.sh --doctor      # environment report only
```

Full guide with per-distro packages, manual build steps, GPG keyring setup,
and troubleshooting: **[docs/INSTALL.md](docs/INSTALL.md)**.

## Use

### GUI

```bash
./iNode-VPN.sh                     # portable tree
iNodeClient-Qt                     # system install
iNodeClient-Qt --connect "Office"  # auto-connect a profile
iNodeClient-Qt --list-profiles     # CLI control: also --status / --disconnect
```

Add a profile → pick a protocol → fill gateway/username/domain → for
self-signed gateways set a **SHA-256 pin** or CA file → **Connect** (root is
requested via polkit only when the tunnel needs it).

### CLI (SSL VPN, no GUI)

```bash
./svpn-connect.sh --auth-only vpn.example.com:443 alice RADIUS   # auth test, no root
./svpn-connect.sh vpn.example.com:443 alice RADIUS               # full tunnel
./svpn-connect.sh gw:443 alice -- --pin-sha256 AA:BB:CC:…        # trust a self-signed cert
```

Password is prompted (never echoed/argv) or read from `$H3C_SVPN_PASSWORD`.
Ctrl-C tears the tunnel down cleanly. More recipes:
**[docs/USAGE.md](docs/USAGE.md)**.

### Check your environment

```bash
iNodeClient-Qt --doctor
```

Reports Qt/KF6 build, all four credential backends, external tools, privileged
helpers + polkit registration, and the Python backend module — with `[ok]` /
`[MISSING]` per item and the **active** credential backend called out.

## Credential storage (at rest)

Saved passwords are encrypted, never plaintext on disk. Backends are tried in
order; the active one is shown by `--doctor`:

1. **KWallet** (KF6 build) — unlocked by your login session
2. **Secret Service** — gnome-keyring / KeePassXC / ksecretd
3. **system GnuPG** — sealed to *your* GPG key (or symmetric via pinentry if
   you have none); gpg-agent owns the passphrase, this app never sees it
4. **AES-256-GCM file** — master-password fallback (PBKDF2 200k, 0600 file)

```bash
gpg --full-gen-key        # optional — enables the GPG backend
```

See **[docs/INSTALL.md → Credential storage](docs/INSTALL.md#4-credential-storage-gpg-and-friends)**.

## Security

- TLS verification **on by default**; `--insecure` is opt-in and warns loudly.
- **Certificate pinning** (`--pin-sha256`) is the recommended way to trust
  self-signed gateways.
- Gateway responses are untrusted: XML parsing hardened against
  XXE / entity expansion; size caps throughout.
- Privileged helpers run through polkit and validate every argument
  (no injection paths); the Python backend is loaded only from a
  non-writable tree.
- Full audit — protocol weaknesses in H3C's protocols and every
  implementation issue found & fixed in this client (C1–C12):
  **[docs/SECURITY-FINDINGS.md](docs/SECURITY-FINDINGS.md)**.

## Documentation

| Document | Contents |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Install (3 methods), per-distro deps, GPG setup, troubleshooting |
| [docs/USAGE.md](docs/USAGE.md) | Daily use: GUI + CLI, profiles, pins, CAPTCHA, troubleshooting |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Full reverse-engineered SSL VPN wire spec |
| [docs/PROTOCOLS.md](docs/PROTOCOLS.md) | Implementation status per protocol plugin |
| [docs/SECURITY-FINDINGS.md](docs/SECURITY-FINDINGS.md) | Security audit (vendor protocol flaws + client fixes) |
| [docs/CAPTCHA.md](docs/CAPTCHA.md) | CAPTCHA analysis + OCR methodology |
| [docs/INTEROP.md](docs/INTEROP.md) | Validating against a live gateway |

## How the SSL VPN works

Reverse-engineered from the official H3C iNode 7.3 Linux client (unstripped,
DWARF symbols). Flow: *(optional SPA knock)* → TLS → gatewayinfo → *(CAPTCHA)*
→ login XML → *(challenge/2FA loop)* → kick-old → NET_EXTEND → network-config
frame → program TUN/routes/DNS → raw IP in 4-byte frames + heartbeat → logout.
Full spec: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Building from source

```bash
./deploy.sh --build-only
# or fully manual:
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j$(nproc)     # -j2 if RAM is tight
```

Sanity checks:

```bash
./bin/iNodeClient-Qt --doctor                        # environment report
PYTHONPATH=backends python3 -m h3csvpn --help        # backend module loads
./svpn-connect.sh --auth-only <gw>:<port> <user> <domain>   # auth-only test
```

## License

- **Qt/C++ application**: GPL-3.0-or-later (`LICENSE`)
- **Python SSL VPN backend** (`backends/h3csvpn/`): MIT (`backends/h3csvpn/LICENSE.MIT`)

This is an independent interoperability implementation. It is **not affiliated
with, endorsed by, or supported by H3C / New H3C Technologies**. "H3C" and
"iNode" are trademarks of their respective owners.
