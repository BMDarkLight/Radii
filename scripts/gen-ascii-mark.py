# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 BMDarkLight
#
# This file is part of Radii.
#
# Radii is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version. See the LICENSE file for the full text and
# additional terms.
#
# NOTE: the artwork this script produces is Radii branding, which is NOT
# covered by the licence above — see the Trademark Notice in the root README.
"""Regenerate the terminal cuts of the Radii mark.

Rasterise the vector once, then read that image two different ways — the jp2a
approach. Placing characters by hand does not work: the grid cannot express the
mark's 30 degree radius, and eyeballing tone gets you noise.

    python scripts/gen-ascii-mark.py

Writes assets/brand/ascii/mark-braille.txt and mark-ascii.txt, which
crates/cli/src/brand.rs embeds with include_str!. Needs Pillow.
"""
import io
import os
import sys

try:
    from PIL import Image, ImageDraw
except ImportError:  # pragma: no cover
    sys.exit("this script needs Pillow: pip install Pillow")

# --- the mark, in its 64-unit viewBox ---------------------------------------
# Kept in step with assets/brand/radii-mark.svg by hand; if the vector moves,
# move these with it and re-run.
HUB = (10.0, 54.0)
STROKE = 3.0
HUB_R = 3.4
RADII = [(56.0, 54.0), (49.84, 31.0), (33.0, 14.16), (10.0, 8.0)]
SPIRALS = [
    [(28.0, 54.0), (25.59, 45.0), (19.0, 38.41), (10.0, 36.0)],
    [(43.0, 54.0), (38.58, 37.5), (26.5, 25.42), (10.0, 21.0)],
]

# Cropped to the baseline rather than to the hub's overhang below it, so the
# horizontal radius lands on whole rows instead of straddling two — which is
# what made earlier attempts read as a smear. The hub merges into the baseline,
# which is where it sits anyway. The crop is then square, so a 2:1 character
# grid comes out with the aspect right by construction.
BBOX = (6.6, 4.6, 57.5, 55.5)

COLS = 28  # rows are half of this; both cuts share the grid
SS = 8  # supersample factor, for antialiasing

# Braille cells are a 2x4 dot matrix, so a cell that is 1 wide by 2 tall makes
# those dots square: 8x the resolution of one character, and the geometry
# survives. Below this threshold a pixel becomes a raised dot; 150 keeps the
# 3-unit stroke about 3 dots thick, which reads solid without flooding.
BRAILLE_THRESHOLD = 150
BRAILLE_DOTS = [[0x01, 0x08], [0x02, 0x10], [0x04, 0x20], [0x40, 0x80]]

# The fallback ramp, darkest first, for terminals that cannot be trusted with
# Unicode at all. Gamma pushes partial stroke coverage toward the denser end;
# without it thin strokes wash out.
ASCII_RAMP = "@%#*+=-:. "
ASCII_GAMMA = 1.25


def render(px=1200):
    """Black mark on white, antialiased by drawing big and shrinking."""
    w = h = px * SS
    s = min(w / (BBOX[2] - BBOX[0]), h / (BBOX[3] - BBOX[1]))
    ox = (w - (BBOX[2] - BBOX[0]) * s) / 2 - BBOX[0] * s
    oy = (h - (BBOX[3] - BBOX[1]) * s) / 2 - BBOX[1] * s

    def m(p):
        return (p[0] * s + ox, p[1] * s + oy)

    img = Image.new("L", (w, h), 255)
    d = ImageDraw.Draw(img)
    lw = max(1, int(round(STROKE * s)))
    r = lw / 2.0

    def polyline(points):
        pts = [m(p) for p in points]
        d.line(pts, fill=0, width=lw, joint="curve")
        for x, y in (pts[0], pts[-1]):  # round caps
            d.ellipse([x - r, y - r, x + r, y + r], fill=0)

    for end in RADII:
        polyline([HUB, end])
    for spiral in SPIRALS:
        polyline(spiral)

    hx, hy = m(HUB)
    hr = HUB_R * s
    d.ellipse([hx - hr, hy - hr, hx + hr, hy + hr], fill=0)

    return img.resize((px, px), Image.LANCZOS)


def _cells(img, cols, rows):
    """Downsample to a grid and return the raw bytes. Mode "L" is one byte per
    pixel in row order; getdata() is deprecated from Pillow 14."""
    return img.resize((cols, rows), Image.LANCZOS).tobytes()


def to_braille(img, cols):
    """One braille cell per character, each carrying 2x4 thresholded dots."""
    rows = cols // 2
    w, h = cols * 2, rows * 4
    px = _cells(img, w, h)

    lines = []
    for cr in range(rows):
        line = ""
        for cc in range(cols):
            bits = 0
            for r in range(4):
                for c in range(2):
                    if px[(cr * 4 + r) * w + cc * 2 + c] < BRAILLE_THRESHOLD:
                        bits |= BRAILLE_DOTS[r][c]
            line += chr(0x2800 + bits)
        lines.append(line.rstrip())
    return lines


def to_ascii(img, cols):
    """One character per cell, chosen by the cell's mean luminance."""
    rows = cols // 2
    px = _cells(img, cols, rows)
    lo, hi = min(px), max(px)
    span = max(1, hi - lo)
    n = len(ASCII_RAMP)

    lines = []
    for r in range(rows):
        line = ""
        for c in range(cols):
            v = (px[r * cols + c] - lo) / span
            v = max(0.0, min(1.0, v)) ** ASCII_GAMMA
            line += ASCII_RAMP[min(n - 1, int(v * n))]
        lines.append(line.rstrip())
    return lines


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(here, os.pardir, "assets", "brand", "ascii")
    img = render()
    for name, cut in (("braille", to_braille), ("ascii", to_ascii)):
        art = cut(img, COLS)
        path = os.path.join(out_dir, "mark-%s.txt" % name)
        with io.open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(u"\n".join(art) + u"\n")
        print("%s  %dx%d" % (os.path.normpath(path), COLS, len(art)))


if __name__ == "__main__":
    main()
