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
docs/               ← README + protocol notes
```

## Requirements (already present on this machine)

- **Qt 6.5+** runtime (system libraries).
- **python3** (standard library only for the core path).
- **tesseract** — solves the gateway's login CAPTCHA automatically.
- **pkexec** (polkit) or **sudo** — the tunnel creates a TUN device, which needs root.
- Optional: `python3-defusedxml` (hardened XML), `python3-cryptography` (RSA password variant).

## Quick start — command line

```bash
# 1) Test credentials only — no tunnel, no root needed:
./svpn-connect.sh --auth-only 102.134.120.103:3000 <username>

# 2) Full VPN tunnel (asks for root via pkexec/sudo to create the TUN device):
./svpn-connect.sh 102.134.120.103:3000 <username>

# With an auth domain:
./svpn-connect.sh 102.134.120.103:3000 <username> system

# Self-signed gateway — pin its certificate (secure) or skip verification:
./svpn-connect.sh gw:443 <username> -- --pin-sha256 AA:BB:CC:...
./svpn-connect.sh gw:443 <username> -- --insecure
```

The password is read from `$H3C_SVPN_PASSWORD` if set, otherwise prompted
(never echoed, never placed on a command line). Press **Ctrl-C** to disconnect;
the client logs out of the gateway and tears the tunnel down cleanly.

Get a self-signed gateway's pin:
```bash
openssl s_client -connect HOST:PORT </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout
```

## Quick start — GUI

```bash
./iNode-VPN.sh
```

Add a profile → set **Protocol = SSL VPN**, fill in the gateway host/port,
username, domain, and (under trust) a CA file or pin for a self-signed gateway →
**Connect**. The GUI prompts for root (pkexec) when it brings the tunnel up.

## Notes on the test gateway (102.134.120.103:3000)

The gateway's local SSL VPN accounts are `sslvpn`, `test`, `vpn` (service
"SSL VPN") in the `system` domain. If login is rejected with *"incorrect
username or password, authentication server error, or number of users reaching
the maximum allowed by an account"*, that is **server-side**: the password is
wrong/expired, the wrong domain was used, or the account's concurrent-login cap
is already in use. Everything up to that point — TLS, CAPTCHA, the login
round-trip — is confirmed working by the client.

## Limitations

- GM/SM2 (CNTLS / SKF USB-Key) gateways are not supported (TLS-layer only).
- Zero-Trust SDP registration is out of scope (only the SPA knock builder exists).
- Linux only for the tunnel (TUN + `ip`); the protocol itself is OS-agnostic.
