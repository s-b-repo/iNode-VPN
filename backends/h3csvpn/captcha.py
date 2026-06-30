"""CAPTCHA handling for the H3C iNode SSL VPN ("V7") gateway.

This gateway (``supportvldimg=true``) gates login on a small BMP validation
image served from ``/vldimg.cgi`` and bound to the ``svpnginfo=vld@...`` cookie.
The image is weak: 4 glyphs, each a solid, saturated, *distinct colour* on a
near-white background, spatially separated, no warping — so it is trivially
segmented and OCR'd.

This module provides, with **no third-party Python dependencies**:

  * ``decode_bmp``     — minimal BMP reader (24/32/8-bit, uncompressed)
  * ``render_ansi``    — show the captcha in the terminal (truecolor half-blocks)
  * ``solve``          — optional auto-solver; shells out to the ``tesseract``
                         binary if present, else returns ``None`` (manual entry)

Keeping it stdlib-only preserves the project's "auditable / dependency-light"
property; ``tesseract`` is the only (optional) external piece.
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from typing import List, Optional, Tuple

Pixel = Tuple[int, int, int]
Grid = List[List[bool]]

WHITE_CUTOFF = 200           # a pixel with all channels > this is "background"
MIN_BLOB = 6                 # connected components smaller than this px = speckle
WHITELIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


# --------------------------------------------------------------------------
# BMP decoding (pure stdlib)
# --------------------------------------------------------------------------
def decode_bmp(data: bytes) -> Tuple[int, int, List[List[Pixel]]]:
    """Decode an uncompressed BMP into ``(width, height, rows)`` where
    ``rows[y][x] == (r, g, b)`` and row 0 is the TOP of the image."""
    if data[:2] != b"BM":
        raise ValueError("not a BMP image")
    pix_off = struct.unpack_from("<I", data, 10)[0]
    dib = struct.unpack_from("<I", data, 14)[0]
    width = struct.unpack_from("<i", data, 18)[0]
    height = struct.unpack_from("<i", data, 22)[0]
    bpp = struct.unpack_from("<H", data, 28)[0]
    compression = struct.unpack_from("<I", data, 30)[0]
    if compression not in (0,):
        raise ValueError(f"unsupported BMP compression {compression}")
    top_down = height < 0
    h = abs(height)

    palette: List[Pixel] = []
    if bpp <= 8:
        ncol = struct.unpack_from("<I", data, 46)[0] or (1 << bpp)
        poff = 14 + dib
        for i in range(ncol):
            b, g, r = data[poff + i * 4], data[poff + i * 4 + 1], data[poff + i * 4 + 2]
            palette.append((r, g, b))

    row_size = ((bpp * width + 31) // 32) * 4
    rows: List[List[Pixel]] = []
    for ry in range(h):
        src = ry if top_down else (h - 1 - ry)
        base = pix_off + src * row_size
        row: List[Pixel] = []
        if bpp == 24:
            for x in range(width):
                o = base + x * 3
                row.append((data[o + 2], data[o + 1], data[o]))
        elif bpp == 32:
            for x in range(width):
                o = base + x * 4
                row.append((data[o + 2], data[o + 1], data[o]))
        elif bpp == 8:
            for x in range(width):
                row.append(palette[data[base + x]])
        else:
            raise ValueError(f"unsupported BMP depth {bpp}")
        rows.append(row)
    return width, h, rows


# --------------------------------------------------------------------------
# terminal preview
# --------------------------------------------------------------------------
def render_ansi(rows: List[List[Pixel]], max_width: int = 96) -> str:
    """Render the captcha as truecolor Unicode half-blocks (two vertical pixels
    per character cell). Falls back to plain shapes if the terminal ignores
    colour. Downscales (nearest) if wider than ``max_width``."""
    h = len(rows)
    w = len(rows[0]) if h else 0
    if w == 0:
        return ""
    step = max(1, (w + max_width - 1) // max_width)

    def at(y: int, x: int) -> Pixel:
        if 0 <= y < h and 0 <= x < w:
            return rows[y][x]
        return (255, 255, 255)

    out = []
    for y in range(0, h, 2 * step):
        line = []
        for x in range(0, w, step):
            top = at(y, x)
            bot = at(y + step, x)
            line.append(f"\x1b[38;2;{top[0]};{top[1]};{top[2]}m"
                        f"\x1b[48;2;{bot[0]};{bot[1]};{bot[2]}m▀")
        line.append("\x1b[0m")
        out.append("".join(line))
    return "\n".join(out)


# --------------------------------------------------------------------------
# segmentation / OCR
# --------------------------------------------------------------------------
def _ink_grid(rows: List[List[Pixel]]) -> Grid:
    return [[not (r > WHITE_CUTOFF and g > WHITE_CUTOFF and b > WHITE_CUTOFF)
             for (r, g, b) in row] for row in rows]


def _denoise(grid: Grid, min_blob: int = MIN_BLOB) -> Grid:
    """Drop connected components smaller than ``min_blob`` px (8-connectivity).
    Removes speckle without eroding thin glyph strokes."""
    h, w = len(grid), len(grid[0])
    seen = [[False] * w for _ in range(h)]
    keep = [[False] * w for _ in range(h)]
    for sy in range(h):
        for sx in range(w):
            if not grid[sy][sx] or seen[sy][sx]:
                continue
            stack, comp = [(sy, sx)], []
            seen[sy][sx] = True
            while stack:
                y, x = stack.pop()
                comp.append((y, x))
                for dy in (-1, 0, 1):
                    for dx in (-1, 0, 1):
                        ny, nx = y + dy, x + dx
                        if (0 <= ny < h and 0 <= nx < w and grid[ny][nx]
                                and not seen[ny][nx]):
                            seen[ny][nx] = True
                            stack.append((ny, nx))
            if len(comp) >= min_blob:
                for (y, x) in comp:
                    keep[y][x] = True
    return keep


def _segment(grid: Grid) -> List[Tuple[int, int]]:
    """Split into character column-bands using the vertical x-projection."""
    h, w = len(grid), len(grid[0])
    cols = [sum(grid[y][x] for y in range(h)) for x in range(w)]
    bands, start, in_run = [], 0, False
    for x in range(w):
        if cols[x] > 0 and not in_run:
            in_run, start = True, x
        elif cols[x] == 0 and in_run:
            in_run = False
            if x - start >= 2:
                bands.append((start, x))
    if in_run:
        bands.append((start, w))
    return bands


def _crop_rows(grid: Grid) -> Tuple[int, int]:
    h = len(grid)
    ys = [y for y in range(h) if any(grid[y])]
    return (ys[0], ys[-1] + 1) if ys else (0, h)


def _crop_cols(grid: Grid) -> Tuple[int, int]:
    w = len(grid[0])
    xs = [x for x in range(w) if any(grid[y][x] for y in range(len(grid)))]
    return (xs[0], xs[-1] + 1) if xs else (0, w)


def _color_clusters(rows: List[List[Pixel]], k: int = 4, min_count: int = 8,
                    sep: int = 60) -> List[Pixel]:
    """Find up to ``k`` dominant glyph colours. Each captcha character is a
    single saturated colour, so the most common well-separated non-white colours
    are the glyphs (speckle is sparse and filtered by ``min_count``)."""
    from collections import Counter
    hist: Counter = Counter()
    for row in rows:
        for (r, g, b) in row:
            if r > WHITE_CUTOFF and g > WHITE_CUTOFF and b > WHITE_CUTOFF:
                continue
            hist[(r >> 4, g >> 4, b >> 4)] += 1        # 16-level quantise
    centers: List[Pixel] = []
    for q, c in hist.most_common():
        if c < min_count:
            break
        col = (q[0] << 4, q[1] << 4, q[2] << 4)
        if all((col[0] - cc[0]) ** 2 + (col[1] - cc[1]) ** 2
               + (col[2] - cc[2]) ** 2 > sep * sep for cc in centers):
            centers.append(col)
        if len(centers) >= k:
            break
    return centers


def _glyph_masks_by_color(rows: List[List[Pixel]], centers: List[Pixel],
                          max_dist: int = 110) -> List[Grid]:
    """Assign every ink pixel to its nearest dominant colour, yielding one mask
    per glyph; denoise, drop empties, and return left-to-right by centroid."""
    h, w = len(rows), len(rows[0])
    masks = [[[False] * w for _ in range(h)] for _ in centers]
    md2 = max_dist * max_dist
    for y in range(h):
        for x in range(w):
            r, g, b = rows[y][x]
            if r > WHITE_CUTOFF and g > WHITE_CUTOFF and b > WHITE_CUTOFF:
                continue
            best, bd = -1, md2
            for i, (cr, cg, cb) in enumerate(centers):
                d = (r - cr) ** 2 + (g - cg) ** 2 + (b - cb) ** 2
                if d < bd:
                    bd, best = d, i
            if best >= 0:
                masks[best][y][x] = True
    out: List[Tuple[float, Grid]] = []
    for m in masks:
        dm = _denoise(m, MIN_BLOB)
        xs = [x for y in range(h) for x in range(w) if dm[y][x]]
        if len(xs) >= MIN_BLOB:
            out.append((sum(xs) / len(xs), dm))
    out.sort(key=lambda t: t[0])
    return [m for _, m in out]


def _ocr_glyph(mask: Grid, paths: List[str]) -> str:
    """OCR a single-glyph mask (psm 10). Returns one character or ''."""
    y0, y1 = _crop_rows(mask)
    x0, x1 = _crop_cols(mask)
    p = _write_pgm(mask, y0, y1, x0, x1, 12)
    paths.append(p)
    ch = _tesseract(p, 10)
    return ch[:1] if ch else ""


def _write_pgm(grid: Grid, y0: int, y1: int, x0: int, x1: int, scale: int,
               pad: int = 6) -> str:
    """Write a scaled, padded P5 (grayscale) PNM of grid[y0:y1, x0:x1] and
    return the temp path. Black ink (0) on white (255)."""
    y0, x0 = max(0, y0), max(0, x0)
    y1, x1 = min(len(grid), y1), min(len(grid[0]), x1)
    gw, gh = (x1 - x0), (y1 - y0)
    W, H = gw * scale + 2 * pad * scale, gh * scale + 2 * pad * scale
    buf = bytearray(b"\xff" * (W * H))
    for y in range(gh):
        for x in range(gw):
            if grid[y0 + y][x0 + x]:
                for sy in range(scale):
                    oy = (pad * scale + y * scale + sy) * W
                    row = oy + pad * scale + x * scale
                    for sx in range(scale):
                        buf[row + sx] = 0
    fd, path = tempfile.mkstemp(suffix=".pgm")
    with os.fdopen(fd, "wb") as f:
        f.write(b"P5\n%d %d\n255\n" % (W, H))
        f.write(bytes(buf))
    return path


def _tesseract(path: str, psm: int) -> str:
    try:
        out = subprocess.run(
            ["tesseract", path, "stdout", "--psm", str(psm),
             "-c", "tessedit_char_whitelist=" + WHITELIST],
            capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip().replace(" ", "").replace("\n", "")


def have_solver() -> bool:
    return shutil.which("tesseract") is not None


def solve(bmp_bytes: bytes, *, expect_len: int = 4) -> Optional[str]:
    """Auto-solve the captcha. Returns the code, or ``None`` if ``tesseract`` is
    unavailable or no confident read was produced (caller falls back to manual)."""
    if not have_solver():
        return None
    try:
        _w, _h, rows = decode_bmp(bmp_bytes)
    except Exception:
        return None
    paths: List[str] = []
    try:
        grid = _denoise(_ink_grid(rows))
        y0, y1 = _crop_rows(grid)

        # 1) per-char by x-projection gaps (the proven path)
        bands = _segment(grid)
        if len(bands) == expect_len:
            out = ""
            for (x0, x1) in bands:
                p = _write_pgm(grid, y0, y1, max(0, x0 - 1),
                               min(len(grid[0]), x1 + 1), 12)
                paths.append(p)
                ch = _tesseract(p, 10)
                out += (ch[:1] if ch else "?")
            if "?" not in out and len(out) == expect_len:
                return out.upper()

        # 2) per-glyph by colour (handles touching/overlapping glyphs)
        masks = _glyph_masks_by_color(rows, _color_clusters(rows, expect_len))
        if len(masks) == expect_len:
            out = "".join(_ocr_glyph(m, paths) or "?" for m in masks)
            if "?" not in out and len(out) == expect_len:
                return out.upper()

        # 3) whole-word OCR — accept ONLY an exact ``expect_len`` read.  We must
        #    not submit low-confidence guesses: the captcha is single-use with a
        #    short TTL, so a wrong guess wastes the window. Return None instead.
        p = _write_pgm(grid, y0, y1, 0, len(grid[0]), 10)
        paths.append(p)
        for psm in (8, 7, 6):
            c = _tesseract(p, psm).upper()
            if len(c) == expect_len:
                return c
        return None
    finally:
        for p in paths:
            try:
                os.remove(p)
            except OSError:
                pass
