# Terminal cuts of the mark

Generated, not drawn. `scripts/gen-ascii-mark.py` rasterises the vector once, then reads
that image two different ways. Placing characters by hand does not work here: the grid
cannot express the mark's 30° radius, and eyeballing tone gets you noise rather than a mark.

```bash
python scripts/gen-ascii-mark.py
```

Both cuts are 28×14 characters off the same raster. They are plain text so
`crates/cli/src/brand.rs` can `include_str!` them, but **edit the script, not these
files** — a hand edit is lost on the next run.

| File | How | When |
|---|---|---|
| `mark-braille.txt` | 2×4 thresholded dots per cell | default |
| `mark-ascii.txt` | one char per cell off `@%#*+=-:. ` | terminals that cannot be trusted with Unicode |
| *(none)* | — | `stdout` is not a TTY, or `TERM=dumb` |

Print no banner in the third case. A banner in a log file is litter, and bare
`radii --help` is the only place any of this belongs.

## Why braille carries the mark

A braille cell is a 2×4 dot matrix, and a terminal cell is roughly 1 wide to 2 tall — so
those dots come out **square**, giving 8× the resolution of a single character. A luminance
ramp at this size cannot compete: block elements render the mark as chunky blobs and an
ASCII ramp softens every edge. Braille is the only way to get 56×56 real pixels out of a
28×14 banner.

Threshold 150 rather than a mid-grey 128: it keeps the 3-unit stroke about 3 dots thick,
which reads solid without flooding the gaps between the spiral and the radii. No dithering —
it adds exactly the noise this is trying to avoid.

## Two details that decide whether it reads

**Crop to the baseline, not to the artwork.** The hub bulges below the horizontal radius, so
cropping to the full bounding box leaves the baseline straddling rows and it renders as a
smear instead of a line. The script crops to y=55.5 — the bottom of the baseline stroke —
and lets the hub merge into it, which is where the hub sits anyway. The crop is then square,
so rows are exactly half the columns and the aspect is right by construction.

**Gamma, for the ASCII cut only.** Thin strokes only partially cover a cell, so a straight
luminance map washes them out. 1.25 pushes partial coverage toward the denser end of the
ramp without flooding the background. Braille thresholds instead, so it needs none.

## Detection

A UTF-8 locale does not promise the font actually has the braille block, so the CLI takes a
best guess — `WT_SESSION`, any `TERM_PROGRAM`, or a UTF-8 `LC_ALL`/`LC_CTYPE`/`LANG` — and
falls back to the ASCII cut. `RADII_BANNER=braille|ascii|none` overrides the lot; that is
the escape hatch for a terminal where the guess is wrong.

## Colour

Strokes take the default foreground. The hub is Reach `#16C79A`, the same colour that means
*reachable* in a route table. Neither cut can separate the hub from the baseline it sits on
— they share cells — so the tint covers the two cells the hub occupies. `NO_COLOR` drops the
tint, not the glyph.
