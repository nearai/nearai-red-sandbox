"""Render the README's splash GIF from the demo's own terminal frames.

    python3 scripts/splash/render_gif.py [OUT.gif]

Writes docs/assets/sandbox-splash.gif by default. Needs Pillow and the Menlo font
that ships with macOS.
"""
import importlib.util, pathlib, re, sys
from PIL import Image, ImageDraw, ImageFont

HERE = pathlib.Path(__file__).resolve().parent
src = HERE / "sandbox_demo.py"
out = sys.argv[1] if len(sys.argv) > 1 else str(HERE.parent.parent / "docs/assets/sandbox-splash.gif")
spec = importlib.util.spec_from_file_location("demo", src)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

CW, CH, PAD = 8, 16, 16
BG = (22, 23, 27)
TEXT_FG = (193, 193, 193)  # the terminal's default text colour, as SILVER
font = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 13)
sp = m.Splash(80, 24)
TOKEN = re.compile(r"\x1b\[([0-9;]*)([A-Za-z])|(.)", re.S)


def cells(frame):
    """Parse one frame's ANSI into rows of (char, fg, bg); rows start at newlines or CUP moves."""
    rows, row, fgc, bgc = [], [], None, None
    for params, cmd, ch in TOKEN.findall(frame):
        if cmd == "H":
            if row:
                rows.append(row)
            row = []
            continue
        if cmd:
            if cmd != "m":
                continue
            p = params.split(";") if params else ["0"]
            i = 0
            while i < len(p):
                if p[i] == "38" and p[i + 1] == "2":
                    fgc = tuple(int(v) for v in p[i + 2:i + 5]); i += 5; continue
                if p[i] == "48" and p[i + 1] == "2":
                    bgc = tuple(int(v) for v in p[i + 2:i + 5]); i += 5; continue
                if p[i] in ("0",):
                    fgc = bgc = None
                elif p[i] == "49":
                    bgc = None
                elif p[i] == "39":
                    fgc = None
                i += 1
        elif ch == "\n":
            rows.append(row); row = []
        else:
            row.append((ch, fgc, bgc))
    rows.append(row)
    return rows[: sp.H]


def draw(rows):
    img = Image.new("RGB", (PAD * 2 + 80 * CW, PAD * 2 + sp.H * CH), BG)
    d = ImageDraw.Draw(img)
    for r, row in enumerate(rows):
        for c, (ch, fgc, bgc) in enumerate(row):
            x, y = PAD + c * CW, PAD + r * CH
            if bgc:
                d.rectangle([x, y, x + CW - 1, y + CH - 1], fill=bgc)
            if ch == " ":
                continue
            fgc = fgc or TEXT_FG
            if ch == "▀":
                d.rectangle([x, y, x + CW - 1, y + CH // 2 - 1], fill=fgc)
            elif ch == "▄":
                d.rectangle([x, y + CH // 2, x + CW - 1, y + CH - 1], fill=fgc)
            elif ch == "█":
                d.rectangle([x, y, x + CW - 1, y + CH - 1], fill=fgc)
            elif ch in "░▒":
                step = 2 if ch == "▒" else 3
                for yy in range(y, y + CH):
                    for xx in range(x + ((yy - y) % step), x + CW, step):
                        d.point((xx, yy), fill=fgc)
            else:
                d.text((x + CW / 2, y + CH / 2), ch, font=font, fill=fgc, anchor="mm")
    return img


T = 312
frames = [draw(cells(sp.frame(k, loop=T))) for k in range(0, T, 3)]
pal = frames[100].quantize(colors=64, method=Image.Quantize.MEDIANCUT)
quant = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
quant[0].save(out, save_all=True, append_images=quant[1:], duration=70, loop=0, optimize=True, disposal=1)
print(len(frames), "frames ->", out)
