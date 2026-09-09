#!/usr/bin/env bash
# svpn-connect.sh — quick H3C SSL VPN connect from the command line (no GUI),
# using the bundled clean-room backend. Self-contained: everything is resolved
# relative to this folder.
#
#   svpn-connect.sh [--auth-only] <gateway[:port]> <username> [domain] [-- <extra backend args>]
#
# Examples:
#   # Authenticate only — no tunnel, no root (best for testing credentials):
#   ./svpn-connect.sh --auth-only vpn.example.com:443 <user>
#
#   # Full tunnel (creates a TUN device; needs root via pkexec/sudo):
#   ./svpn-connect.sh vpn.example.com:443 <user>
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

usage() {
    cat <<'USAGE'
svpn-connect.sh — quick H3C SSL VPN connect from the command line

  svpn-connect.sh [--auth-only] <gateway[:port]> <username> [domain] [-- <extra backend args>]

  --auth-only     authenticate only — no tunnel, no root
  Full tunnel     creates a TUN device; needs root via pkexec/sudo
  Self-signed gw  pass -- --pin-sha256 AA:BB:... (secure) or -- --insecure

  Password comes from $H3C_SVPN_PASSWORD, else is prompted (never echoed,
  never placed on a command line / visible in `ps`).
USAGE
    exit 1
}

case "${1:-}" in -h|--help) usage;; esac
AUTH_ONLY=0
[ "${1:-}" = "--auth-only" ] && { AUTH_ONLY=1; shift; }

GW="${1:-}"; USER_NAME="${2:-}"
[ -n "$GW" ] && [ -n "$USER_NAME" ] || usage
shift 2

DOMAIN=""
if [ $# -gt 0 ] && [ "${1:-}" != "--" ]; then DOMAIN="$1"; shift; fi
[ "${1:-}" = "--" ] && shift
EXTRA=( "$@" )

PW="${H3C_SVPN_PASSWORD:-}"
if [ -z "$PW" ]; then read -rsp "Password: " PW; echo; fi

PYARGS=( "$GW" -u "$USER_NAME" --auto-captcha -v )
[ -n "$DOMAIN" ] && PYARGS+=( -d "$DOMAIN" )
[ ${#EXTRA[@]} -gt 0 ] && PYARGS+=( "${EXTRA[@]}" )

# ---- auth-only: run the backend directly, no privileges, no tunnel ----
if [ "$AUTH_ONLY" -eq 1 ]; then
    # PYTHONDONTWRITEBYTECODE: a __pycache__ written here with umask 002 would
    # make backends/ group-writable and the root helper would then refuse it.
    export PYTHONPATH="$BACKEND" PYTHONSAFEPATH=1 PYTHONDONTWRITEBYTECODE=1 \
           H3C_SVPN_PASSWORD="$PW"
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

stop() {
    # Guard the empty-array expansion for bash < 4.4 under `set -u` (root case).
    [ ${#LAUNCH[@]} -gt 0 ] || return 0
    "${LAUNCH[@]}" "$HELPER" stop --name "$NAME" 2>/dev/null || true
}
trap stop EXIT INT TERM

printf '%s\n' "$PW" | "${LAUNCH[@]}" "$HELPER" connect \
    --name "$NAME" --backend "$BACKEND" --with-password -- "${PYARGS[@]}"
