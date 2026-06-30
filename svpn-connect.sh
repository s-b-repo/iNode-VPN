#!/usr/bin/env bash
# svpn-connect.sh — quick H3C SSL VPN connect from the command line (no GUI),
# using the bundled clean-room backend. Self-contained: everything is resolved
# relative to this folder.
#
#   svpn-connect.sh [--auth-only] <gateway[:port]> <username> [domain] [-- <extra backend args>]
#
# Examples:
#   # Authenticate only — no tunnel, no root (best for testing credentials):
#   ./svpn-connect.sh --auth-only 102.134.120.103:3000 sslvpn
#
#   # Full tunnel (creates a TUN device; needs root via pkexec/sudo):
#   ./svpn-connect.sh 102.134.120.103:3000 sslvpn
#
#   # Self-signed gateway — pin the cert (secure) or skip verification:
#   ./svpn-connect.sh gw:443 user -- --pin-sha256 AA:BB:CC:...
#   ./svpn-connect.sh gw:443 user -- --insecure
#
# Password: taken from $H3C_SVPN_PASSWORD if set, otherwise prompted (never
# echoed, never placed on a command line / in `ps`).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$DIR/backends"
HELPER="$DIR/scripts/inode-svpn-helper"

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 1; }

case "${1:-}" in -h|--help) usage;; esac
AUTH_ONLY=0
[ "${1:-}" = "--auth-only" ] && { AUTH_ONLY=1; shift; }

GW="${1:-}"; USER="${2:-}"
[ -n "$GW" ] && [ -n "$USER" ] || usage
shift 2

DOMAIN=""
if [ $# -gt 0 ] && [ "${1:-}" != "--" ]; then DOMAIN="$1"; shift; fi
[ "${1:-}" = "--" ] && shift
EXTRA=( "$@" )

PW="${H3C_SVPN_PASSWORD:-}"
if [ -z "$PW" ]; then read -rsp "Password: " PW; echo; fi

PYARGS=( "$GW" -u "$USER" --auto-captcha -v )
[ -n "$DOMAIN" ] && PYARGS+=( -d "$DOMAIN" )
[ ${#EXTRA[@]} -gt 0 ] && PYARGS+=( "${EXTRA[@]}" )

# ---- auth-only: run the backend directly, no privileges, no tunnel ----
if [ "$AUTH_ONLY" -eq 1 ]; then
    export PYTHONPATH="$BACKEND" PYTHONSAFEPATH=1 H3C_SVPN_PASSWORD="$PW"
    exec python3 -m h3csvpn "${PYARGS[@]}" --no-tunnel
fi

# ---- full tunnel: needs root; go through the privileged helper ----
NAME="cli-$$"
LAUNCH=()
if [ "$(id -u)" -ne 0 ]; then
    if   command -v pkexec >/dev/null 2>&1; then LAUNCH=(pkexec)
    elif command -v sudo   >/dev/null 2>&1; then LAUNCH=(sudo)
    else echo "Need root (pkexec or sudo) to create the tunnel — or use --auth-only." >&2; exit 1; fi
fi

stop() { "${LAUNCH[@]}" "$HELPER" stop --name "$NAME" 2>/dev/null || true; }
trap stop EXIT INT TERM

printf '%s\n' "$PW" | "${LAUNCH[@]}" "$HELPER" connect \
    --name "$NAME" --backend "$BACKEND" --with-password -- "${PYARGS[@]}"
