#!/usr/bin/env bash
# deploy.sh — one-shot build + deploy for iNode Client (Qt).
#
#   ./deploy.sh               # deps → build → system install → doctor
#   ./deploy.sh --local       # build portable tree (./bin + ./scripts), no root
#   ./deploy.sh --uninstall   # remove the system install
#   ./deploy.sh --doctor      # only run the environment probe
#
# System install puts the GUI in /usr/local/bin (override with PREFIX=),
# helpers + policy where the polkit rules expect them, and registers the
# desktop entry. Portable mode is fully self-contained in this folder.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/bin/iNodeClient-Qt"
PREFIX="${PREFIX:-/usr/local}"
HELPER_DIR="/usr/libexec/iNodeClient-Qt"

C_BLACK='\033[0m'; C_RED='\033[31m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'
say()  { printf '%b\n' "$2$1$C_BLACK"; }
die()  { printf '%b\n' "$C_RED✗ $1$C_BLACK" >&2; exit 1; }

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi

# ---------------------------------------------------------------- uninstall
uninstall() {
    [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ] || die "uninstall needs root"
    for f in \
        "$PREFIX/bin/iNodeClient-Qt" \
        "$PREFIX/share/applications/org.inode.ClientQt.desktop" \
        "$PREFIX/share/icons/hicolor/scalable/apps/org.inode.ClientQt.svg" \
        "$PREFIX/share/polkit-1/actions/org.inode.ClientQt.policy" \
        "/usr/share/polkit-1/actions/org.inode.ClientQt.policy"; do
        $SUDO rm -f "$f" && say "removed $f" "$C_GREEN"
    done
    $SUDO rm -rf "$HELPER_DIR" && say "removed $HELPER_DIR" "$C_GREEN"
    say "Uninstalled. User data (~/.config/iNodeClient-Qt) left intact." "$C_GREEN"
    exit 0
}

# ------------------------------------------------------------------- doctor
doctor() {
    local exe="$BIN"
    [ -x "$exe" ] || exe="$PREFIX/bin/iNodeClient-Qt"
    [ -x "$exe" ] || exe="iNodeClient-Qt"
    exec "$exe" --doctor
}

# ----------------------------------------------------------------- packages
PKG=""
detect_pm() {
    if command -v apt-get >/dev/null 2>&1; then PKG="apt"
    elif command -v dnf >/dev/null 2>&1; then PKG="dnf"
    elif command -v pacman >/dev/null 2>&1; then PKG="pacman"
    elif command -v zypper >/dev/null 2>&1; then PKG="zypper"
    else die "no supported package manager (apt/dnf/pacman/zypper) — install deps manually (see README)"
    fi
}

install_deps() {
    detect_pm
    say "→ Installing build deps via $PKG (sudo password may be asked)" "$C_YELLOW"
    case "$PKG" in
        apt)
            $SUDO apt-get update -qq
            $SUDO apt-get install -y --no-install-recommends \
                build-essential cmake qt6-base-dev qt6-tools-dev-tools \
                python3 gnupg tesseract-ocr polkitd pkexec \
                libkf6wallet-dev libkf6config-dev libkf6i18n-dev \
                libkf6coreaddons-dev \
                || $SUDO apt-get install -y --no-install-recommends \
                     build-essential cmake qt6-base-dev python3 gnupg tesseract-ocr
            ;;
        dnf)
            $SUDO dnf install -y gcc-c++ cmake qt6-qtbase-devel qt6-linguist \
                python3 gnupg2 tesseract polkit \
                kf6-kwallet-devel kf6-kconfig-devel kf6-ki18n-devel kf6-kcoreaddons-devel \
                || $SUDO dnf install -y gcc-c++ cmake qt6-qtbase-devel python3 gnupg2 tesseract
            ;;
        pacman)
            $SUDO pacman -Sy --needed --noconfirm base-devel cmake qt6-base python \
                gnupg tesseract polkit \
                kwallet kconfig ki18n kcoreaddons \
                || $SUDO pacman -Sy --needed --noconfirm base-devel cmake qt6-base python gnupg tesseract
            ;;
        zypper)
            $SUDO zypper install -y gcc-c++ cmake qt6-base-devel python3 gpg2 tesseract \
                polkit kf6-kwallet-devel kf6-kconfig-devel kf6-ki18n-devel kf6-kcoreaddons-devel \
                || $SUDO zypper install -y gcc-c++ cmake qt6-base-devel python3 gpg2 tesseract
            ;;
    esac
}

# -------------------------------------------------------------------- build
build() {
    say "→ Configuring (RelWithDebInfo)" "$C_YELLOW"
    cmake -S "$HERE" -B "$HERE/build" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
          -DINODE_HELPER_DIR="$HELPER_DIR"
    say "→ Building ($(nproc) jobs)" "$C_YELLOW"
    cmake --build "$HERE/build" -j"$(nproc)"
    mkdir -p "$HERE/bin"
    cp -f "$HERE/build/iNodeClient-Qt" "$BIN"
    chmod +x "$HERE"/scripts/inode-* "$BIN"
}

# ------------------------------------------------------------ system install
install_system() {
    [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ] || die "system install needs root (run via sudo) — try: ./deploy.sh --local"
    say "→ Installing to $PREFIX + $HELPER_DIR" "$C_YELLOW"
    $SUDO cmake --install "$HERE/build" --prefix "$PREFIX"
    # polkit only reads actions from /usr/share/polkit-1/actions (and distro
    # patches thereof) — a non-/usr PREFIX would install the policy somewhere
    # polkit never scans, and pkexec would then refuse every helper. Mirror
    # the policy into the canonical dir when needed.
    if [ "$PREFIX" != "/usr" ] && [ ! -f /usr/share/polkit-1/actions/org.inode.ClientQt.policy ]; then
        $SUDO mkdir -p /usr/share/polkit-1/actions
        $SUDO cp -f "${PREFIX}/share/polkit-1/actions/org.inode.ClientQt.policy" \
                    /usr/share/polkit-1/actions/
        say "  (policy mirrored to /usr/share/polkit-1/actions for pkexec)" "$C_YELLOW"
    fi
    # Refresh caches so the menu entry + icons appear without a relogin.
    $SUDO update-desktop-database "${PREFIX}/share/applications" 2>/dev/null || true
    $SUDO gtk-update-icon-cache -f -t "${PREFIX}/share/icons/hicolor" 2>/dev/null || true
}

# ------------------------------------------------------------- local deploy
install_local() {
    say "→ Portable deploy into $HERE (no root needed)" "$C_YELLOW"
    # Everything the app resolves at runtime relative to its own location:
    #   bin/iNodeClient-Qt  ../scripts/inode-*  ../backends/h3csvpn  ../resources
    [ -x "$BIN" ] || die "not built yet — run: ./deploy.sh --local --build-only"
    say "Portable tree ready. Launch with: $HERE/iNode-VPN.sh" "$C_GREEN"
    say "NOTE (portable mode): privileged helpers run via pkexec/sudo from $HERE/scripts;" "$C_YELLOW"
    say "the polkit policy is only registered by system install." "$C_YELLOW"
}

case "${1:-}" in
    --uninstall) uninstall ;;
    --doctor)    doctor ;;
    --local)     MODE="local" ;;
    --build-only) MODE="build" ;;
    "")          MODE="system" ;;
    *) die "usage: $0 [--local|--build-only|--uninstall|--doctor]" ;;
esac

command -v cmake >/dev/null 2>&1 || install_deps
command -v g++   >/dev/null 2>&1 || install_deps
# qt6 present? qmake6 or the Qt6 cmake config.
{ command -v qmake6 >/dev/null 2>&1 || pkg-config --exists Qt6Core 2>/dev/null; } || install_deps

build

case "$MODE" in
    build) say "✓ Build complete: $BIN" "$C_GREEN" ;;
    local) install_local ;;
    system)
        install_system
        say "✓ Deployed. Run 'iNodeClient-Qt' or the menu entry, or $HERE/iNode-VPN.sh" "$C_GREEN"
        ;;
esac

say "→ Environment check:" "$C_YELLOW"
"$BIN" --doctor || true
