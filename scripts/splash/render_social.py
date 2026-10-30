"""Render the SandBox terminal UI into social post media.

    python3 scripts/splash/render_social.py [OUT_DIR]

Plays the demo's real ANSI output through a small terminal emulator and draws the
screen inside a plain terminal window. Writes to docs/marketing/<latest posts>:
  splash-x-1200x675.gif            looping splash, 16:9 (X, LinkedIn landscape)
  session-linkedin-1080x1350.png   prompt, splash and launch log, 4:5
Needs Pillow and macOS's Menlo font, like render_gif.py.
"""
import builtins
import importlib.util
import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parents[2]
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "docs/marketing/2026-10-30-sandbox-launch-posts"
spec = importlib.util.spec_from_file_location("demo", REPO / "scripts/splash/sandbox_demo.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

CANVAS = (11, 11, 13)
WINDOW = (21, 20, 27)
TITLEBAR = (30, 29, 37)
DOT = (62, 61, 72)
TEXT_FG = (205, 205, 210)
MENLO = "/System/Library/Fonts/Menlo.ttc"
TOKEN = re.compile(r"\x1b\[([0-9;?]*)([A-Za-z])|\x1b\][^\x07]*\x07|(.)", re.S)


class Screen:
    """Just enough of a VT100 for the demo: SGR colours, CUP, clears, CR/LF."""

    def __init__(self, cols, rows):
        self.cols, self.rows = cols, rows
        self.cells = [[(" ", None, None)] * cols for _ in range(rows)]
        self.r = self.c = 0
        self.fg = self.bg = None

    def feed(self, text):
        for params, cmd, ch in TOKEN.findall(text):
            if cmd:
                self._csi(params, cmd)
            elif ch == "\r":
                self.c = 0
            elif ch == "\n":
                self.r, self.c = min(self.rows - 1, self.r + 1), 0
            elif ch:
                if self.c < self.cols:
                    self.cells[self.r][self.c] = (ch, self.fg, self.bg)
                self.c += 1

    def _csi(self, params, cmd):
        p = params.lstrip("?")
        if cmd == "m":
            parts = p.split(";") if p else ["0"]
            i = 0
            while i < len(parts):
                if parts[i] in ("38", "48") and parts[i + 1] == "2":
                    v = tuple(int(x) for x in parts[i + 2:i + 5])
                    if parts[i] == "38":
                        self.fg = v
                    else:
                        self.bg = v
                    i += 5
                    continue
                if parts[i] == "0":
                    self.fg = self.bg = None
                elif parts[i] == "39":
                    self.fg = None
                elif parts[i] == "49":
                    self.bg = None
                i += 1
        elif cmd == "H":
            nums = [int(x) for x in p.split(";") if x] or [1]
            self.r, self.c = nums[0] - 1, (nums[1] - 1 if len(nums) > 1 else 0)
        elif cmd == "J" and p == "2":
            self.cells = [[(" ", None, None)] * self.cols for _ in range(self.rows)]
        elif cmd == "K":
            self.cells[self.r] = [(" ", None, None)] * self.cols
        elif cmd == "F":
            self.r, self.c = max(0, self.r - int(p or 1)), 0
        elif cmd == "E":
            self.r, self.c = min(self.rows - 1, self.r + int(p or 1)), 0


def draw_cells(img, x0, y0, cells, cw, ch_, font):
    d = ImageDraw.Draw(img)
    for r, row in enumerate(cells):
        for c, (ch, fg, bg) in enumerate(row):
            x, y = x0 + c * cw, y0 + r * ch_
            if bg:
                d.rectangle([x, y, x + cw - 1, y + ch_ - 1], fill=bg)
            if ch == " ":
                continue
            fg = fg or TEXT_FG
            code = ord(ch)
            if ch == "▀":
                d.rectangle([x, y, x + cw - 1, y + ch_ // 2 - 1], fill=fg)
            elif ch == "▄":
                d.rectangle([x, y + ch_ // 2, x + cw - 1, y + ch_ - 1], fill=fg)
            elif 0x2581 <= code <= 0x2588:
                h = round(ch_ * (code - 0x2580) / 8)
                d.rectangle([x, y + ch_ - h, x + cw - 1, y + ch_ - 1], fill=fg)
            elif ch in "░▒▓":
                keep = {"░": lambda a, b: a % 2 == 0 and b % 2 == 0, "▒": lambda a, b: (a + b) % 2 == 0,
                        "▓": lambda a, b: not (a % 2 and b % 2)}[ch]
                for yy in range(ch_ // 2):
                    for xx in range(cw // 2):
                        if keep(xx, yy):
                            d.rectangle([x + 2 * xx, y + 2 * yy, x + 2 * xx + 1, y + 2 * yy + 1], fill=fg)
            else:
                d.text((x + cw / 2, y + ch_ / 2), ch, font=font, fill=fg, anchor="mm")


def window(size, cols, rows, cw, ch_, title, pad=16, bar=34):
    """Canvas with a centred terminal window; returns the image and the text origin."""
    img = Image.new("RGB", size, CANVAS)
    d = ImageDraw.Draw(img)
    w, h = cols * cw + 2 * pad, rows * ch_ + 2 * pad + bar
    x0, y0 = (size[0] - w) // 2, (size[1] - h) // 2
    d.rounded_rectangle([x0, y0, x0 + w - 1, y0 + h - 1], radius=12, fill=WINDOW)
    d.rounded_rectangle([x0, y0, x0 + w - 1, y0 + bar + 12], radius=12, fill=TITLEBAR)
    d.rectangle([x0, y0 + bar, x0 + w - 1, y0 + bar + 12], fill=WINDOW)
    for i in range(3):
        cx = x0 + 22 + i * 20
        d.ellipse([cx - 6, y0 + bar // 2 - 6, cx + 6, y0 + bar // 2 + 6], fill=DOT)
    tf = ImageFont.truetype(MENLO, 13)
    d.text((x0 + w / 2, y0 + bar / 2), title, font=tf, fill=(128, 128, 136), anchor="mm")
    return img, x0 + pad, y0 + bar + pad


PROMPT = m.fg(m.PEWTER) + "~/research " + "\x1b[0m" + "$ rts launch"


def splash_gif(path, size=(1200, 675), cw=11, ch_=22, step=3, T=312):
    font = ImageFont.truetype(MENLO, 18)
    sp = m.Splash(80, 24)
    frames = []
    for k in range(0, T, step):
        s = Screen(80, 24)
        s.feed(PROMPT + sp.frame(k, 2, loop=T))
        img, tx, ty = window(size, 80, 24, cw, ch_, "~/research — rts launch")
        draw_cells(img, tx, ty, s.cells, cw, ch_, font)
        frames.append(img)
    pal = frames[70].quantize(colors=64, method=Image.Quantize.MEDIANCUT)
    q = [f.quantize(palette=pal, dither=Image.Dither.NONE) for f in frames]
    q[0].save(path, save_all=True, append_images=q[1:], duration=70, loop=0, optimize=True, disposal=1)


def session_png(path, size=(1080, 1350), cw=12, ch_=22):
    """The whole mock session: prompt, settled splash, launch and teardown log."""
    buf = []

    class Out:
        def write(self, s):
            buf.append(s)

        def flush(self):
            pass

    m.OUT = Out()
    m.time.sleep = lambda s: None
    builtins.input = lambda *a: ""
    m.shutil.get_terminal_size = lambda fallback=None: (80, 24)
    emit = m.emit
    m.emit = lambda segs, used=0: "" if segs and segs[0][0].startswith("press Enter") else emit(segs, used)
    m.main()
    s = Screen(80, 80)
    s.feed("".join(buf).replace("SandBox CLI demo · mock data · press Enter to play", ""))
    rows = [row for row in s.cells]
    while rows and all(c[0] == " " for c in rows[-1]):
        rows.pop()
    # drop the blank row the press-Enter prompt left behind
    used = [i for i, row in enumerate(rows) if any(c[0] != " " for c in row)]
    rows = rows[used[0]:]
    font = ImageFont.truetype(MENLO, 19)
    img, tx, ty = window(size, 80, len(rows), cw, ch_, "~/research — rts launch", pad=18)
    draw_cells(img, tx, ty, rows, cw, ch_, font)
    img.save(path)
    return len(rows)


OUT.mkdir(parents=True, exist_ok=True)
splash_gif(OUT / "splash-x-1200x675.gif")
n = session_png(OUT / "session-linkedin-1080x1350.png")
print("session rows:", n)
