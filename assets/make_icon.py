#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Генератор иконки Mine Checker без внешних библиотек.
Рисует щит с галочкой на тёмном фоне и собирает icon.icns (macOS) и icon.ico (Windows).

    python3 assets/make_icon.py
"""

from __future__ import annotations

import math
import os
import struct
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SS = 3  # сглаживание: рендерим в 3 раза крупнее и усредняем

BG_TOP = (0x1E, 0x27, 0x3A)
BG_BOT = (0x0C, 0x0F, 0x16)
SHIELD = (0x5B, 0x8C, 0xFF)
SHIELD_D = (0x3B, 0x6A, 0xDF)
CHECK = (0xFF, 0xFF, 0xFF)


def _png(w, h, rgba: bytes) -> bytes:
    raw = b"".join(b"\x00" + rgba[y * w * 4:(y + 1) * w * 4] for y in range(h))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def _rounded(px, py, r=0.22):
    """Точка внутри скруглённого квадрата [0..1]?"""
    x = min(px, 1 - px)
    y = min(py, 1 - py)
    if x >= r or y >= r:
        return True
    return (x - r) ** 2 + (y - r) ** 2 <= r * r


def _shield(px, py):
    """Щит в координатах [0..1]. Верх — прямой, низ сходится в точку."""
    x = (px - 0.5) / 0.30          # полуширина щита 0.30
    y = (py - 0.20) / 0.62         # щит от 0.20 до 0.82 по высоте
    if not (0.0 <= y <= 1.0):
        return False
    if y < 0.45:
        half = 1.0
        if y < 0.06:               # скругление верхних углов
            half = math.sqrt(max(0.0, 1 - ((0.06 - y) / 0.06) ** 2 * 0.35))
    else:
        t = (y - 0.45) / 0.55
        half = math.sqrt(max(0.0, 1 - t * t))
    return abs(x) <= half


def _seg_dist(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    L = dx * dx + dy * dy
    t = 0.0 if L == 0 else max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / L))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def _check(px, py):
    th = 0.045
    return (_seg_dist(px, py, 0.395, 0.505, 0.470, 0.585) < th
            or _seg_dist(px, py, 0.470, 0.585, 0.625, 0.400) < th)


def render(size: int) -> bytes:
    big = size * SS
    buf = bytearray(big * big * 4)
    for j in range(big):
        py = (j + 0.5) / big
        gt = py
        bg = tuple(int(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * gt) for i in range(3))
        for i in range(big):
            px = (i + 0.5) / big
            o = (j * big + i) * 4
            if not _rounded(px, py):
                continue
            if _check(px, py):
                c, a = CHECK, 255
            elif _shield(px, py):
                k = min(1.0, max(0.0, (py - 0.20) / 0.62))
                c = tuple(int(SHIELD[m] + (SHIELD_D[m] - SHIELD[m]) * k) for m in range(3))
                a = 255
            else:
                c, a = bg, 255
            buf[o:o + 4] = bytes((c[0], c[1], c[2], a))

    # даунсэмплинг
    out = bytearray(size * size * 4)
    for y in range(size):
        for x in range(size):
            r = g = b = a = 0
            for dy in range(SS):
                base = ((y * SS + dy) * big + x * SS) * 4
                for dx in range(SS):
                    o = base + dx * 4
                    r += buf[o]; g += buf[o + 1]; b += buf[o + 2]; a += buf[o + 3]
            n = SS * SS
            o = (y * size + x) * 4
            out[o:o + 4] = bytes((r // n, g // n, b // n, a // n))
    return _png(size, size, bytes(out))


def build_icns():
    iconset = os.path.join(HERE, "icon.iconset")
    os.makedirs(iconset, exist_ok=True)
    plan = [(16, "16x16"), (32, "16x16@2x"), (32, "32x32"), (64, "32x32@2x"),
            (128, "128x128"), (256, "128x128@2x"), (256, "256x256"),
            (512, "256x256@2x"), (512, "512x512"), (1024, "512x512@2x")]
    cache = {}
    for size, label in plan:
        if size not in cache:
            cache[size] = render(size)
        with open(os.path.join(iconset, f"icon_{label}.png"), "wb") as f:
            f.write(cache[size])
    icns = os.path.join(HERE, "icon.icns")
    try:
        subprocess.check_call(["iconutil", "-c", "icns", iconset, "-o", icns])
        print("[✓]", icns)
    except Exception as e:
        print("[!] iconutil недоступен:", e)
    return cache


def build_ico(cache):
    sizes = [16, 32, 48, 64, 128, 256]
    images = []
    for s in sizes:
        images.append((s, cache.get(s) or render(s)))
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for s, data in images:
        entries += struct.pack("<BBBBHHII", 0 if s >= 256 else s, 0 if s >= 256 else s,
                               0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    path = os.path.join(HERE, "icon.ico")
    with open(path, "wb") as f:
        f.write(header + entries + blobs)
    print("[✓]", path)


def main():
    print("[i] Рисую иконку…")
    cache = build_icns() if sys.platform == "darwin" else {}
    if not cache:
        cache = {s: render(s) for s in (16, 32, 48, 64, 128, 256)}
    build_ico(cache)
    png = os.path.join(HERE, "icon.png")
    with open(png, "wb") as f:
        f.write(cache.get(256) or render(256))
    print("[✓]", png)


if __name__ == "__main__":
    main()
