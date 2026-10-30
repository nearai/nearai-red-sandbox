"""README heading mark and dune divider as SVGs drawn at one unit per CSS pixel.

The mark copies a terminal's shade ramp: four 8x16 cells of 25%, 50% and 75%
stipple and a solid block. The divider is a row of rounded dunes, a solid crest
over stipple that thins toward the base. Both use the hero's sand colour.

    python3 scripts/splash/readme_assets.py [OUT_DIR]

Writes ramp.svg and dunes.svg to docs/assets by default.
"""
import math
import pathlib
import sys

SAND = "#A1977F"
out = sys.argv[1] if len(sys.argv) > 1 else str(pathlib.Path(__file__).resolve().parents[2] / "docs/assets")


def on(density, x, y):
    if density >= 4:
        return True
    if density == 3:
        return not (x % 2 and y % 2)
    if density == 2:
        return (x + y) % 2 == 0
    return x % 2 == 0 and y % 2 == 0


def runs(pixels, w, h):
    """Merge lit pixels into horizontal runs, one rect each."""
    parts = []
    for y in range(h):
        x = 0
        while x < w:
            if pixels(x, y):
                x0 = x
                while x < w and pixels(x, y):
                    x += 1
                parts.append(f"M{x0} {y}h{x - x0}v1h{x0 - x}z")
            else:
                x += 1
    return "".join(parts)


def svg(w, h, path):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'shape-rendering="crispEdges"><path fill="{SAND}" d="{path}"/></svg>\n')


# heading mark: ░ ▒ ▓ █ as 8x16 cells
open(f"{out}/ramp.svg", "w").write(svg(32, 16, runs(lambda x, y: on(1 + x // 8, x, y), 32, 16)))

# divider: dunes 672 wide (the hero's width), 16 high
W, H = 672, 16
DUNES = [(34, 22, 5), (102, 30, 9), (168, 20, 4), (248, 38, 13), (330, 24, 6), (400, 30, 10), (468, 20, 4),
         (540, 34, 11), (614, 24, 6), (660, 16, 3)]


def height(x):
    return max(min(H - 1, sum(h * math.exp(-((x - c) / w) ** 2) for c, w, h in DUNES)), 1.0)


def dune(x, y):
    crest = H - height(x + 0.5)
    if y + 1 <= crest:
        return False
    depth = y - math.floor(crest)
    return on(4 if depth < 1 else 3 if depth < 3 else 2 if depth < 6 else 1, x, y)


open(f"{out}/dunes.svg", "w").write(svg(W, H, runs(dune, W, H)))
print("wrote ramp.svg and dunes.svg")
