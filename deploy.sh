#!/usr/bin/env bash
# deploy.sh — one-shot build + deploy for iNode Client (Qt).
#
#   ./deploy.sh               # deps → build → system install → doctor
#   ./deploy.sh --local       # build portable tree (./bin + ./scripts), no root
#   ./deploy.sh --update      # git pull → rebuild → reinstall (same mode as before)
#   ./deploy.sh --build-only  # compile only, leave the binary in ./bin
#   ./deploy.sh --uninstall   # remove the system install (user data kept)
#   ./deploy.sh --doctor      # only run the environment probe
#   ./deploy.sh --fix-perms   # re-tighten backends/ + scripts/ (portable mode)
#
# Env overrides:  PREFIX=/opt/inode   ./deploy.sh      (default /usr/local)
#                 JOBS=2              ./deploy.sh      (default: nproc)
#                 NO_DEPS=1           ./deploy.sh      (never touch the package manager)
#
# System install puts the GUI in $PREFIX/bin, helpers + policy where the polkit
# rules expect them (/usr/libexec/iNodeClient-Qt, /usr/share/polkit-1/actions),
# and registers the desktop entry. Portable mode is fully self-contained here.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/bin/iNodeClient-Qt"
PREFIX="${PREFIX:-/usr/local}"
HELPER_DIR="/usr/libexec/iNodeClient-Qt"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

# Everything this script creates (build/, bin/, any __pycache__) must not be
# group/other-writable: the root helper refuses such a backend tree, and a
# user umask of 002 (Debian/Kali default for user-private groups) would
# otherwise produce exactly that.
umask 022

C_RESET='\033[0m'; C_RED='\033[31m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'
say()  { printf '%b\n' "$2$1$C_RESET"; }
die()  { printf '%b\n' "${C_RED}✗ $1${C_RESET}" >&2; exit 1; }

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then SUDO="sudo"
    elif command -v doas >/dev/null 2>&1; then SUDO="doas"
    fi
fi

# ------------------------------------------------------------------ helpers
# Run the GUI binary for text-only output even on a headless box / over SSH.
run_cli() {
    local exe="$1"; shift
    if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
        QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}" "$exe" "$@"
    else
        "$exe" "$@"
    fi
}

# The root helper refuses to import the Python backend from a group/other-
# writable tree (so nobody can plant a module that runs as root). A checkout
# made with umask 002, or a `python3 -m h3csvpn` run that left a __pycache__
# behind, trips that check — fix it here so portable mode works out of the box.
fix_perms() {
    find "$HERE/backends" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
    if ! chmod -R go-w "$HERE/backends" "$HERE/scripts" 2>/dev/null; then
        say "⚠ could not tighten permissions on backends/ or scripts/ (not owned by you?)" "$C_YELLOW"
        say "  fix with: sudo chown -R $(id -un) '$HERE' && ./deploy.sh --fix-perms" "$C_YELLOW"
    fi
    chmod +x "$HERE"/scripts/inode-* "$HERE"/*.sh 2>/dev/null || true
    [ -f "$BIN" ] && chmod +x "$BIN" 2>/dev/null || true
    # Prove it: the root helper runs exactly this test before importing.
    if [ -n "$(find "$HERE/backends/h3csvpn" -perm /022 -print -quit 2>/dev/null)" ]; then
        say "⚠ backends/h3csvpn is still group/other-writable — SSL VPN connects from this" "$C_YELLOW"
        say "  folder will be refused by the root helper until that is fixed." "$C_YELLOW"
    fi
}

# Is a system install present? (used by --update to pick the same mode)
system_installed() {
    [ -x "$HELPER_DIR/inode-svpn-helper" ] || [ -x "$PREFIX/bin/iNodeClient-Qt" ]
}

# Ownership sanity. Two classic ways a checkout ends up half root-owned:
#   * someone ran `sudo ./deploy.sh` once — build/ and bin/ are now root's and
#     every later run as the user fails with "Permission denied";
#   * the folder was extracted/cloned by root into the user's home.
# Fix what we can (chown back via sudo), explain what we can't.
check_ownership() {
    local me; me="$(id -u)"
    if [ "$me" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        say "⚠ Running via sudo — deploy.sh only needs root for the install step and" "$C_YELLOW"
        say "  asks for it itself. Continuing, but build/ and bin/ will be handed back" "$C_YELLOW"
        say "  to $SUDO_USER at the end so plain './deploy.sh' keeps working." "$C_YELLOW"
        RESTORE_OWNER="$SUDO_USER"
        return 0
    fi
    [ "$me" -ne 0 ] || return 0
    [ -w "$HERE" ] || die "$HERE is not writable by $(id -un) — fix with: sudo chown -R $(id -un) '$HERE'"
    local foreign=()
    local p
    for p in "$HERE/build" "$HERE/bin" "$HERE/backends" "$HERE/scripts"; do
        [ -e "$p" ] || continue
        if find "$p" ! -user "$me" -print -quit 2>/dev/null | grep -q .; then foreign+=("$p"); fi
    done
    [ ${#foreign[@]} -gt 0 ] || return 0
    say "→ Files not owned by you in: ${foreign[*]} (leftovers from 'sudo ./deploy.sh'?)" "$C_YELLOW"
    [ -n "$SUDO" ] || die "cannot fix ownership without sudo — run: chown -R $(id -un) '$HERE' as root"
    $SUDO chown -R "$me:$(id -g)" "${foreign[@]}" \
        && say "  ownership restored to $(id -un)" "$C_GREEN" \
        || die "could not chown ${foreign[*]}"
}
RESTORE_OWNER=""
restore_ownership() {
    [ -n "$RESTORE_OWNER" ] || return 0
    chown -R "$RESTORE_OWNER" "$HERE/build" "$HERE/bin" 2>/dev/null || true
}

# ---------------------------------------------------------------- uninstall
uninstall() {
    [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ] || die "uninstall needs root (no sudo/doas found)"
    for f in \
        "$PREFIX/bin/iNodeClient-Qt" \
        "$PREFIX/share/applications/org.inode.ClientQt.desktop" \
        "$PREFIX/share/icons/hicolor/scalable/apps/org.inode.ClientQt.svg" \
        "$PREFIX/share/polkit-1/actions/org.inode.ClientQt.policy" \
        "/usr/share/polkit-1/actions/org.inode.ClientQt.policy"; do
        [ -e "$f" ] || continue
        $SUDO rm -f "$f" && say "removed $f" "$C_GREEN"
    done
    if [ -d "$HELPER_DIR" ]; then
        $SUDO rm -rf "$HELPER_DIR" && say "removed $HELPER_DIR" "$C_GREEN"
    fi
    $SUDO update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
    $SUDO gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" 2>/dev/null || true
    say "Uninstalled. User data (~/.config/iNodeClient-Qt) left intact." "$C_GREEN"
    exit 0
}

# ------------------------------------------------------------------- doctor
doctor() {
    local exe="$BIN"
    [ -x "$exe" ] || exe="$PREFIX/bin/iNodeClient-Qt"
    [ -x "$exe" ] || exe="$(command -v iNodeClient-Qt 2>/dev/null || true)"
    [ -n "$exe" ] && [ -x "$exe" ] || die "no built binary found — run ./deploy.sh (or --local) first"
    run_cli "$exe" --doctor
    exit $?
}

# ----------------------------------------------------------------- packages
PKG=""
detect_pm() {
    if   command -v apt-get >/dev/null 2>&1; then PKG="apt"
    elif command -v dnf     >/dev/null 2>&1; then PKG="dnf"
    elif command -v pacman  >/dev/null 2>&1; then PKG="pacman"
    elif command -v zypper  >/dev/null 2>&1; then PKG="zypper"
    else PKG=""
    fi
}

# Do we have everything the build needs? (compiler, cmake, Qt6 dev, python3)
have_qt6_dev() {
    command -v qmake6 >/dev/null 2>&1 && return 0
    pkg-config --exists Qt6Core 2>/dev/null && return 0
    # Qt6Config.cmake is what CMake actually needs; look where distros put it.
    local d
    for d in /usr/lib/*/cmake/Qt6 /usr/lib64/cmake/Qt6 /usr/lib/cmake/Qt6 \
             /usr/local/lib/cmake/Qt6 /usr/local/opt/qt@6/lib/cmake/Qt6 \
             /opt/homebrew/opt/qt@6/lib/cmake/Qt6; do
        [ -f "$d/Qt6Config.cmake" ] && return 0
    done
    [ -n "${CMAKE_PREFIX_PATH:-}" ] && [ -f "$CMAKE_PREFIX_PATH/lib/cmake/Qt6/Qt6Config.cmake" ] && return 0
    return 1
}

missing_build_deps() {
    local miss=()
    command -v cmake >/dev/null 2>&1 || miss+=(cmake)
    { command -v g++ >/dev/null 2>&1 || command -v clang++ >/dev/null 2>&1; } || miss+=(c++ compiler)
    command -v make >/dev/null 2>&1 || command -v ninja >/dev/null 2>&1 || miss+=(make)
    have_qt6_dev || miss+=("Qt6 dev")
    command -v python3 >/dev/null 2>&1 || miss+=(python3)
    [ ${#miss[@]} -eq 0 ] && return 1
    printf '%s\n' "${miss[@]}"
    return 0
}

# Install one optional package at a time; a missing/renamed optional must not
# take the whole dependency step down with it (e.g. polkitd vs policykit-1,
# KF6 -dev packages that only exist on newer releases).
pm_install_each() {
    local p
    for p in "$@"; do
        case "$PKG" in
            apt)    $SUDO apt-get install -y -qq --no-install-recommends "$p" >/dev/null 2>&1 ;;
            dnf)    $SUDO dnf install -y -q "$p" >/dev/null 2>&1 ;;
            pacman) $SUDO pacman -S --needed --noconfirm "$p" >/dev/null 2>&1 ;;
            zypper) $SUDO zypper --non-interactive install "$p" >/dev/null 2>&1 ;;
        esac && say "    + $p" "$C_GREEN" || say "    - $p (not available, skipped)" "$C_YELLOW"
    done
}

install_deps() {
    [ -z "${NO_DEPS:-}" ] || die "build deps missing and NO_DEPS=1 set — install them manually (docs/INSTALL.md)"
    detect_pm
    [ -n "$PKG" ] || die "no supported package manager (apt/dnf/pacman/zypper) — install deps manually (docs/INSTALL.md)"
    [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ] || die "need root to install packages (no sudo/doas) — install deps manually (docs/INSTALL.md)"
    say "→ Installing build deps via $PKG (a sudo password may be asked)" "$C_YELLOW"
    case "$PKG" in
        apt)
            $SUDO apt-get update -qq
            $SUDO apt-get install -y --no-install-recommends \
                build-essential cmake pkg-config qt6-base-dev python3
            say "  optional extras:" "$C_YELLOW"
            pm_install_each qt6-tools-dev qt6-tools-dev-tools libxcb-cursor0 \
                tesseract-ocr polkitd pkexec policykit-1 \
                libkf6wallet-dev libkf6config-dev libkf6i18n-dev libkf6coreaddons-dev
            ;;
        dnf)
            $SUDO dnf install -y gcc-c++ make cmake pkgconf-pkg-config qt6-qtbase-devel python3
            say "  optional extras:" "$C_YELLOW"
            pm_install_each qt6-linguist xcb-util-cursor tesseract polkit \
                kf6-kwallet-devel kf6-kconfig-devel kf6-ki18n-devel kf6-kcoreaddons-devel
            ;;
        pacman)
            $SUDO pacman -Sy --needed --noconfirm base-devel cmake pkgconf qt6-base python
            say "  optional extras:" "$C_YELLOW"
            pm_install_each qt6-tools xcb-util-cursor tesseract tesseract-data-eng polkit \
                kwallet kconfig ki18n kcoreaddons
            ;;
        zypper)
            $SUDO zypper --non-interactive install gcc-c++ make cmake pkgconf-pkg-config \
                qt6-base-devel python3
            say "  optional extras:" "$C_YELLOW"
            pm_install_each qt6-linguist-devel libxcb-cursor0 tesseract-ocr polkit \
                kf6-kwallet-devel kf6-kconfig-devel kf6-ki18n-devel kf6-kcoreaddons-devel
            ;;
    esac
    if m="$(missing_build_deps)"; then
        die "still missing after package install: $(echo "$m" | tr '\n' ' ')— see docs/INSTALL.md"
    fi
}

ensure_deps() {
    local m
    if m="$(missing_build_deps)"; then
        say "→ Missing build deps: $(echo "$m" | tr '\n' ' ')" "$C_YELLOW"
        install_deps
    fi
}

# -------------------------------------------------------------------- build
build() {
    # A build/ dir copied along with the sources (zip snapshot, moved checkout)
    # carries a CMakeCache.txt that points at the OLD source path; CMake then
    # refuses to configure. Detect and wipe it instead of failing.
    if [ -f "$HERE/build/CMakeCache.txt" ]; then
        local cached
        cached="$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$HERE/build/CMakeCache.txt")"
        if [ -n "$cached" ] && [ "$cached" != "$HERE" ]; then
            say "→ Stale build cache from $cached — starting a fresh build dir" "$C_YELLOW"
            rm -rf "$HERE/build"
        fi
    fi
    say "→ Configuring (RelWithDebInfo)" "$C_YELLOW"
    cmake -S "$HERE" -B "$HERE/build" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
          -DINODE_HELPER_DIR="$HELPER_DIR" -DCMAKE_INSTALL_PREFIX="$PREFIX"
    say "→ Building ($JOBS jobs)" "$C_YELLOW"
    cmake --build "$HERE/build" -j"$JOBS"
    mkdir -p "$HERE/bin"
    cp -f "$HERE/build/iNodeClient-Qt" "$BIN"
    fix_perms
}

# ------------------------------------------------------------ system install
install_system() {
    [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ] || die "system install needs root (no sudo/doas) — try: ./deploy.sh --local"
    say "→ Installing to $PREFIX + $HELPER_DIR" "$C_YELLOW"
    $SUDO cmake --install "$HERE/build" --prefix "$PREFIX"
    # polkit only reads actions from /usr/share/polkit-1/actions — a non-/usr
    # PREFIX would install the policy somewhere polkit never scans, and pkexec
    # would then refuse every helper. Mirror the policy into the canonical dir.
    if [ "$PREFIX" != "/usr" ]; then
        $SUDO mkdir -p /usr/share/polkit-1/actions
        $SUDO cp -f "$PREFIX/share/polkit-1/actions/org.inode.ClientQt.policy" \
                    /usr/share/polkit-1/actions/
        say "  (policy mirrored to /usr/share/polkit-1/actions for pkexec)" "$C_YELLOW"
    fi
    # Refresh caches so the menu entry + icon appear without a relogin.
    $SUDO update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
    $SUDO gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" 2>/dev/null || true
    case ":$PATH:" in
        *":$PREFIX/bin:"*) ;;
        *) say "  note: $PREFIX/bin is not on your PATH — use the menu entry or $HERE/iNode-VPN.sh" "$C_YELLOW" ;;
    esac
}

# ------------------------------------------------------------- local deploy
install_local() {
    say "→ Portable deploy into $HERE (no root needed)" "$C_YELLOW"
    [ -x "$BIN" ] || die "build failed — no binary at $BIN"
    fix_perms
    say "Portable tree ready. Launch with: $HERE/iNode-VPN.sh" "$C_GREEN"
    say "NOTE (portable mode): privileged helpers run via pkexec/sudo from $HERE/scripts;" "$C_YELLOW"
    say "the polkit policy is only registered by a system install (./deploy.sh)." "$C_YELLOW"
}

# ------------------------------------------------------------------- update
update_sources() {
    if [ -d "$HERE/.git" ] && command -v git >/dev/null 2>&1; then
        say "→ Pulling latest sources (git pull --ff-only)" "$C_YELLOW"
        if ! git -C "$HERE" pull --ff-only; then
            die "git pull failed — commit/stash local changes (git status) and re-run ./deploy.sh --update"
        fi
    else
        say "→ Not a git checkout — skipping pull, rebuilding the sources present here" "$C_YELLOW"
        say "  (download the latest release/zip over this folder, then run --update again)" "$C_YELLOW"
    fi
}

# -------------------------------------------------------------------- main
MODE="system"
case "${1:-}" in
    -h|--help)    usage 0 ;;
    --uninstall)  uninstall ;;
    --doctor)     doctor ;;
    --fix-perms)  fix_perms; say "✓ permissions tightened on backends/ and scripts/" "$C_GREEN"; exit 0 ;;
    --local)      MODE="local" ;;
    --build-only) MODE="build" ;;
    --update)     MODE="update" ;;
    "")           MODE="system" ;;
    *)            say "unknown option: $1" "$C_RED"; usage 1 ;;
esac

if [ "$MODE" = "update" ]; then
    update_sources
    if system_installed; then MODE="system"; else MODE="local"; fi
    say "→ Update: reinstalling in $MODE mode" "$C_YELLOW"
fi

check_ownership
ensure_deps
build
trap restore_ownership EXIT

case "$MODE" in
    build)  say "✓ Build complete: $BIN" "$C_GREEN" ;;
    local)  install_local ;;
    system)
        install_system
        say "✓ Deployed. Run 'iNodeClient-Qt', use the menu entry, or $HERE/iNode-VPN.sh" "$C_GREEN"
        ;;
esac

say "→ Environment check:" "$C_YELLOW"
run_cli "$BIN" --doctor || true
