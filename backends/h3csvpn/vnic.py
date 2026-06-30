"""Virtual NIC: TUN device + address/route/DNS programming (PROTOCOL.md §6.6).

The real ``libvnic.so`` opens ``/dev/net/tun`` (IFF_TUN|IFF_NO_PI), sets the
address with ``SIOCSIFADDR``/``SIOCSIFNETMASK`` ioctls and routes with rtnetlink.
For a readable, dependency-free reference we open the TUN device with the exact
ioctl the client uses, but program the address/routes with the ``ip`` command
(equivalent, and easy to audit).  DNS is written to ``/etc/resolv.conf`` with the
same marker line the client emits, and everything is restored on close.

Requires root (CAP_NET_ADMIN) to create the device and change routes.
"""
from __future__ import annotations

import fcntl
import os
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from . import constants as C
from .tunnel import NetworkConfig


def _ip(*args: str, check: bool = True) -> int:
    cmd = ["ip", *args]
    res = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
    if check and res.returncode != 0:
        raise RuntimeError(f"`{' '.join(cmd)}` failed: "
                           f"{res.stderr.decode(errors='replace').strip()}")
    return res.returncode


def _mask_to_prefix(mask: str) -> int:
    try:
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except ValueError:
        return 32


RESOLV_BAK = C.RESOLV_CONF + ".h3c-svpn.bak"


@dataclass
class VirtualNIC:
    name_template: str = C.IFNAME_TEMPLATE
    _fd: int = -1
    ifname: str = ""
    _dns_changed: bool = False
    # routes we added, as (family, cidr) so cleanup uses the right `ip` family.
    _added_routes: list[tuple[str, str]] = field(default_factory=list)
    _opened: bool = False

    # -- device ------------------------------------------------------------
    def open(self) -> int:
        """Create the TUN device and return its fd (also a select()able)."""
        self._fd = os.open(C.TUN_DEVICE, os.O_RDWR)
        flags = C.IFF_TUN | C.IFF_NO_PI
        # struct ifreq is 40 bytes on 64-bit; zero-pad the whole thing
        # (matches the client's memset(&ifr,0,sizeof)) instead of relying on
        # CPython copying a short immutable buffer.
        ifr = struct.pack("16sH", self.name_template.encode("ascii"),
                          flags).ljust(40, b"\x00")
        res = fcntl.ioctl(self._fd, C.TUNSETIFF, ifr)
        self.ifname = res[:16].split(b"\x00", 1)[0].decode("ascii")
        self._opened = True
        return self._fd

    @property
    def fd(self) -> int:
        return self._fd

    # -- addressing --------------------------------------------------------
    def configure(self, cfg: NetworkConfig, server_ip: Optional[str] = None) -> None:
        """Program address, routes and DNS.

        ``server_ip`` is the gateway's own IP: in full-tunnel mode it MUST keep
        bypassing the tunnel (via the original default gateway) or the encrypted
        TLS connection would route into itself and deadlock.
        """
        if not self.ifname:
            raise RuntimeError("device not open")
        prefix = cfg.prefixlength or (str(_mask_to_prefix(cfg.subnetmask))
                                      if cfg.subnetmask else "32")
        _ip("addr", "flush", "dev", self.ifname, check=False)
        _ip("addr", "add", f"{cfg.ipaddress}/{prefix}", "dev", self.ifname)
        _ip("link", "set", "dev", self.ifname, "up")
        if cfg.ipv6address:
            v6p = cfg.prefixlength if ":" in (cfg.prefixlength or "") else "64"
            _ip("-6", "addr", "add", f"{cfg.ipv6address}/{v6p}",
                "dev", self.ifname, check=False)

        self._program_routes(cfg, server_ip)
        self._program_dns(cfg)

    def _add_route(self, family6: bool, *args: str) -> None:
        pre = ["-6"] if family6 else []
        if _ip(*pre, "route", "add", *args, check=False) == 0:
            self._added_routes.append(("6" if family6 else "4", args[0]))

    def _program_routes(self, cfg: NetworkConfig, server_ip: Optional[str]) -> None:
        orig_gw = _original_default_gw()
        full_tunnel = cfg.default_gateway and not cfg.routes

        # 1) keep the gateway IP and explicit exclusions OFF the tunnel.
        bypass = list(cfg.exclude_routes)
        if full_tunnel and server_ip:
            bypass.append(f"{server_ip}/32")
        for r in bypass:
            net = _normalize_cidr(r)
            if not net:
                continue
            if orig_gw:
                self._add_route(False, net, "via", orig_gw)
            # else: best effort — without a known gateway we cannot carve out.

        # 2) IPv4 tunnel routes.
        if full_tunnel:
            for net in ("0.0.0.0/1", "128.0.0.0/1"):  # split-default
                self._add_route(False, net, "dev", self.ifname)
        for r in cfg.routes:
            net = _normalize_cidr(r)
            if net:
                self._add_route(False, net, "dev", self.ifname)

        # 3) IPv6 routes (tracked for cleanup; full-tunnel split if needed).
        if cfg.ipv6address and cfg.default_gateway and not cfg.ipv6routes:
            for net in ("::/1", "8000::/1"):
                self._add_route(True, net, "dev", self.ifname)
        for r in cfg.ipv6routes:
            net = r.strip()
            if net:
                self._add_route(True, net, "dev", self.ifname)

    def _program_dns(self, cfg: NetworkConfig) -> None:
        servers = list(cfg.dns) + list(cfg.ipv6dns)
        if not servers:
            return
        # Idempotent + crash-safe: if a previous run left our marker / a backup,
        # restore the real original first so we never capture our own file.
        self._restore_dns_if_stale()
        try:
            original = open(C.RESOLV_CONF, "rb").read()
        except OSError:
            original = b""
        try:
            with open(RESOLV_BAK, "wb") as bak:  # on-disk backup survives a crash
                bak.write(original)
        except OSError:
            return  # can't back up safely -> don't touch resolv.conf
        body = "\n".join([C.RESOLV_MARKER] + [f"nameserver {s}" for s in servers]) + "\n"
        _atomic_write(C.RESOLV_CONF, body.encode("utf-8"))
        self._dns_changed = True

    def _restore_dns_if_stale(self) -> None:
        try:
            cur = open(C.RESOLV_CONF, "rb").read()
        except OSError:
            return
        if C.RESOLV_MARKER.encode() in cur and os.path.exists(RESOLV_BAK):
            try:
                _atomic_write(C.RESOLV_CONF, open(RESOLV_BAK, "rb").read())
            except OSError:
                pass

    # -- teardown ----------------------------------------------------------
    def close(self) -> None:
        for family, net in reversed(self._added_routes):
            pre = ["-6"] if family == "6" else []
            _ip(*pre, "route", "del", net, check=False)
        self._added_routes.clear()
        if self._dns_changed:
            try:
                if os.path.exists(RESOLV_BAK):
                    _atomic_write(C.RESOLV_CONF, open(RESOLV_BAK, "rb").read())
                    os.unlink(RESOLV_BAK)
            except OSError:
                pass
            self._dns_changed = False
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
        self._opened = False

    def __enter__(self) -> "VirtualNIC":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _normalize_cidr(route: str) -> str:
    """Accept ``ip``, ``ip/len`` or ``ip mask`` and return ``ip/len``."""
    route = route.strip()
    if not route:
        return ""
    if "/" in route:
        return route
    parts = route.split()
    if len(parts) == 2:  # "ip mask"
        return f"{parts[0]}/{_mask_to_prefix(parts[1])}"
    return f"{route}/32"


def _original_default_gw() -> str:
    """The IPv4 default gateway BEFORE we touch routing (so the tunnel's own
    traffic and excluded networks keep using the physical path)."""
    res = subprocess.run(["ip", "route", "show", "default"],
                         capture_output=True, text=True)
    for tok in res.stdout.split():
        if tok == "via":
            idx = res.stdout.split().index("via")
            parts = res.stdout.split()
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return ""


def _atomic_write(path: str, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically (O_EXCL tmp + os.replace)."""
    import tempfile
    dirname = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=dirname, prefix=".h3c-tmp.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def have_root() -> bool:
    return os.geteuid() == 0


def have_ip_cmd() -> bool:
    return shutil.which("ip") is not None
