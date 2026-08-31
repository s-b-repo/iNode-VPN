#!/usr/bin/env bash
# Launch the iNode Client (Qt GUI). This folder is self-contained: the SSL VPN
# backend (backends/) and the privileged helpers (scripts/) are resolved
# relative to the binary, so the app works without being installed.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/bin/iNodeClient-Qt" "$@"
