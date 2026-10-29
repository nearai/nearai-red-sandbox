#!/usr/bin/env python3
"""SandBox splash and a styled `rts launch` session, in truecolor ANSI.

Mock data only: nothing here calls the real launcher. The splash is drawn
inline and left-aligned, on the terminal's own background. Terminals of at
least 80x24 get the full splash; narrower ones get a compact layout with the
cube on the left and the lockup beside it.
"""
import math
import shutil
import sys
import time

OUT = sys.stdout


def hexc(h):
    return (int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16))


VOID, TOP, FRONT, SIDE = hexc("#070708"), hexc("#E9E7E1"), hexc("#B7B7BB"), hexc("#76767D")
CREASE, INK, RED, WHITE = hexc("#2B2B30"), hexc("#272727"), hexc("#EB1924"), hexc("#FAFAF7")
PEWTER, LIGHT = hexc("#808088"), hexc("#D9D9DC")
S0, S1, S2, PILE = hexc("#3B362D"), hexc("#A1977F"), hexc("#EEE5D1"), hexc("#D6CAB0")
# Field cells use the terminal's own background (SGR 49) and body text its own
# foreground (TEXT, SGR 39), so they follow light and dark themes. xterm.js-based
# terminals cache one atlas glyph per character and colour pair, and some stop
# drawing new glyphs once that cache overflows, so the palette stays small and
# sand over the cube is drawn as background tint, which needs no glyph.
DEFBG = "\x1b[49m"
TEXT = None

MARK = ["....RRRR....", "...RRRRR....", "..RRRR####..", "..RR..#####.", "##RR.....###", "##RR.....###",
        "###.....####", "###.....####", ".#####..##..", "..########..", "....#####...", "....####...."]
WM = ["110111100001111100000111110011011110000022000022000222222000000000000022",
      "111111110011111110001111111011111110000222200022000222222200000000000022",
      "111000110011000011011100011011100000000222200022000220002200222200022222",
      "110000110110000011000000011011100000002200220022000220002202222220222222",
      "110000110110111111001111011011100000002200220022000222222202200220220022",
      "110000110110000000011000011011100000002222220022000222222002222220220022",
      "110000110111000011011000111011100000022222222022000220022002200000220022",
      "110000110011111110011111111011100000022000022022000220002202222220222222",
      "110000110001111100001111001011000000022000022022000220002200222200022222"]
# grains by density; only ASCII, the middle dot and stipple blocks, which every
# terminal draws (rarer dot glyphs broke some renderers)
GRAINS = " .·::░░▒▒"
KANA = "ｱｶｻﾀﾅﾊﾏﾔﾗﾜｦﾝｷｼﾁﾆ"
SESSION = "3f9a1c2b7e04"
MACHINE = "rts-" + SESSION


def clamp(v, a, b):
    return a if v < a else b if v > b else v


def ease(t):
    return t * t * (3 - 2 * t)


def sst(a, b, x):
    return ease(clamp((x - a) / (b - a), 0.0, 1.0))


def mix(a, b, t):
    return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t)


def sand(b):
    return mix(S0, S1, b * 2) if b < 0.5 else mix(S1, S2, (b - 0.5) * 2)


SAND4 = [sand(i / 3) for i in range(4)]


def sand_q(b):
    """Nearest of four fixed sand shades, to keep the terminal's glyph cache small."""
    return SAND4[int(clamp(round(b * 3), 0, 3))]


def fg(c):
    if c is None:
        return "\x1b[39m"
    return f"\x1b[38;2;{int(c[0])};{int(c[1])};{int(c[2])}m"


def bg(c):
    return f"\x1b[48;2;{int(c[0])};{int(c[1])};{int(c[2])}m"


def hash2(i, j):
    h = (i * 374761393 + j * 668265263) & 0xFFFFFFFF
    h = ((h ^ (h >> 13)) * 1274126177) & 0xFFFFFFFF
    return (h ^ (h >> 16)) / 4294967296


def vn(x, y):
    xi, yi = math.floor(x), math.floor(y)
    xf, yf = x - xi, y - yi
    u, v = xf * xf * (3 - 2 * xf), yf * yf * (3 - 2 * yf)
    a, b = hash2(xi, yi), hash2(xi + 1, yi)
    c, d = hash2(xi, yi + 1), hash2(xi + 1, yi + 1)
    return a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v


def fbm(x, y, octaves=3):
    s, a, f = 0.0, 0.5, 1.0
    for _ in range(octaves):
        s += a * vn(x * f, y * f)
        f *= 2.03
        a *= 0.5
    return s


def g1(x, c, w, h):
    q = (x - c) / w
    return h * math.exp(-q * q)


class Splash:
    """The splash scene for one terminal size: full at 80x24 and up, else compact."""

    def __init__(self, cols, rows):
        self.full = cols >= 80 and rows >= 24
        if self.full:
            self.W, self.H, self.fx = 80, 23, 32
        else:
            self.W, self.H, self.fx = min(cols, 60), 14, 7
        self.fy, self.s, self.d = 6, 20, 4
        self.f = self.W / 80
        self.pw, self.ph = self.W, 2 * self.H
        self.base = [None] * (self.pw * self.ph)
        self.text = {}
        self._cube()
        if self.full:
            for y, row in enumerate(WM):
                for x, ch in enumerate(row):
                    if ch != "0":
                        self._put(4 + x, 28 + y, WHITE if ch == "1" else RED)
            self._place(20, [("Cybersecurity Program", TEXT)])
            self._place(22, [(" ".join("SANDBOX"), PEWTER)])
            self.center = (40, 22)
            self.boxes = [(0, 13, 25, 55), (14, 18, 3, 76), (20, 20, 28, 52), (22, 22, 30, 50)]
        else:
            c = self.fx + self.s + 3
            self._place(5, [("near ", TEXT), ("AI Red", RED)], c)
            self._place(7, [("Cybersecurity Program", TEXT)], c)
            self._place(9, [(" ".join("SANDBOX"), PEWTER)], c)
            self.center = (self.fx + 10, 14)
            self.boxes = [(0, 13, 1, self.fx + self.s + 2), (4, 10, c - 1, self.W - 1)]

    def _put(self, x, y, c):
        if 0 <= x < self.pw and 0 <= y < self.ph:
            self.base[y * self.pw + x] = c

    def _cube(self):
        fx, fy, s, d = self.fx, self.fy, self.s, self.d
        for y in range(fy, fy + s):
            for x in range(fx, fx + s):
                self._put(x, y, FRONT)
        for y in range(fy - d, fy):
            o = fy - y
            for x in range(fx - o, fx + s - o):
                self._put(x, y, TOP)
        for x in range(fx - d, fx):
            o = fx - x
            for y in range(fy - o, fy + s - o):
                self._put(x, y, SIDE)
        for x in range(fx - 1, fx + s - 1):
            self._put(x, fy - 1, CREASE)
        for y in range(fy - 1, fy + s - 1):
            self._put(fx - 1, y, CREASE)
        for o in range(1, d + 1):
            self._put(fx - o, fy - o, CREASE)
        for j, row in enumerate(MARK):
            for i, ch in enumerate(row):
                if ch != ".":
                    self._put(fx + 4 + i, fy + 4 + j, RED if ch == "R" else INK)

    def _place(self, r, segments, col=None, bold=False):
        c = (self.W - sum(len(t) for t, _ in segments)) // 2 if col is None else col
        for t, colour in segments:
            for ch in t:
                if ch != " ":
                    self.text[(r, c)] = (ch, colour, bold)
                c += 1

    def quiet(self, r, c):
        return any(r0 <= r <= r1 and c0 <= c <= c1 for r0, r1, c0, c1 in self.boxes)

    # storm density, the clearing around the lockup, and the drift at the cube's base
    def raw(self, x, y, t):
        X, Y = x * 0.05 + t * 0.9, y * 0.1
        qx = fbm(X * 0.6 + 3.1 + t * 0.12, Y * 0.6 - 1.7, 2)
        qy = fbm(X * 0.6 - 2.3, Y * 0.6 + 4.2 + t * 0.1, 2)
        n = fbm(X + 2.2 * qx, Y + qy)
        gust = 0.18 * math.sin(x * 0.09 + t * 3.1 + y * 0.04 + 2 * qx)
        return clamp((n - 0.17) * 2.4 + gust, 0, 1) * (0.85 + 0.3 * y / self.ph)

    def env(self, k, x, y, d):
        cx, cy = self.center
        dist = math.hypot(x - cx, (y - cy) * 1.3)
        m_end = sst(30 * self.f, 60 * self.f, dist)

        def settled(clr):
            m = 1 - (1 - m_end) * clr
            return d * (0.1 + 0.9 * m) * (1 - 0.58 * clr)

        if k < 48:
            return d
        if k < 144:
            return settled(sst(0, 0.6, ease((k - 48) / 96) * 1.6 - dist / (49 * self.f) * 0.9))
        if k < 240:
            return settled(1)
        # the storm rolls back in from the right (used for the looping README GIF)
        front = (86 - (k - 240) / 72 * 125) * self.f
        return max(settled(1), d * sst(front - 12, front + 6, x))

    def piles(self, a):
        fx, s, d = self.fx, self.s, self.d
        hc = [0.0] * (2 * self.W)
        for X in range(2 * self.W):
            x = (X + 0.5) / 2
            h = g1(x, fx - 2, 3.5, 3.4) + g1(x, fx + s + 1.5, 4.5, 5)
            h += 1.3 * sst(fx - d - 4, fx - d + 2, x) * (1 - sst(fx + s + 4, fx + s + 13, x))
            h += 0.7 * (vn(x * 0.55, 3.3) - 0.5)
            hc[X] = max(0.0, h * a)
        return hc

    def frame(self, k, row0=1, loop=None):
        """One frame at step k. With loop=T the last 24 steps blend into step 0, so a GIF repeats cleanly."""
        t = k / 24
        a = 0.45 + 0.15 * k / 48 if k < 48 else 0.6 + 0.4 * ease(min(1, (k - 48) / 96))
        w, t0 = 0.0, t
        if loop:
            a -= 0.55 * sst(240, loop, k)
            w, t0 = sst(loop - 24, loop, k), (k - loop) / 24
        hc = self.piles(a)
        base_y = self.fy + self.s
        LC, LR = self.W // 2 + 1, self.H // 2 + 1

        def storm(x, y):
            d = self.raw(x, y, t)
            return d + w * (self.raw(x, y, t0) - d) if w else d

        lat = [[self.env(k, 2 * i + 0.5, 4 * j + 1, storm(2 * i + 0.5, 4 * j + 1)) for i in range(LC)]
               for j in range(LR)]

        def dens(fx, fy):
            fx, fy = clamp(fx, 0, LC - 1.001), clamp(fy, 0, LR - 1.001)
            i, j = int(fx), int(fy)
            tx, ty = fx - i, fy - j
            return (lat[j][i] * (1 - tx) * (1 - ty) + lat[j][i + 1] * tx * (1 - ty)
                    + lat[j + 1][i] * (1 - tx) * ty + lat[j + 1][i + 1] * tx * ty)

        rows = []
        for r in range(self.H):
            line, cur = [f"\x1b[{row0 + r};1H"], None
            for c in range(self.W):
                d = dens(c / 2, r / 2)
                top, bot = self.base[2 * r * self.pw + c], self.base[(2 * r + 1) * self.pw + c]
                tx = self.text.get((r, c))
                quiet = self.quiet(r, c)
                solid = tx or top or bot or quiet
                ns = npile = 0
                for dy in range(4):
                    for dx in range(2):
                        X, Y = 2 * c + dx, 4 * r + dy
                        dd = dens((X + 0.5) / 4 - 0.25, (Y + 0.5) / 8 - 0.125)
                        tg = t0 if w and hash2(X * 7 + 3, Y * 13 + 1) < w else t
                        if hash2(X + int(tg * (30 + 34 * hash2(Y, 77))), Y) < dd * 1.05 - 0.04:
                            ns += 1
                        if hc[X] > 0.2:
                            y, top_y = (Y + 0.5) / 2, base_y - hc[X]
                            if top_y <= y < base_y + 1.2 and hash2(X * 3 + 11, Y * 7 + 5) < 0.5 + 0.45 * clamp((y - top_y) / 2.5, 0, 1):
                                npile += 1
                # over the cube and wordmark, sand is one stipple colour on the art's own
                # colour: two glyphs per art colour instead of every shade and grain
                under = mix(top or bot, bot or top, 0.5) if top or bot else None
                if ns and (d > 0.42 or (d > 0.08 and not solid)):
                    dl = dens((c - 1) / 2, (r - 1) / 2)
                    b = clamp(0.22 + 0.62 * d + 0.9 * (d - dl), 0, 1)
                    if under and d < 0.6:
                        style, ch = fg(S1) + bg(under), "░" if ns + npile < 5 else "▒"
                    else:
                        style, ch = fg(sand_q(b)) + DEFBG, GRAINS[min(8, ns + npile)]
                elif npile:
                    if under:
                        style, ch = fg(PILE) + bg(under), "░" if npile < 5 else "▒"
                    else:
                        style, ch = fg(PILE) + DEFBG, GRAINS[npile]
                elif tx:
                    style, ch = ("\x1b[1m" if tx[2] else "\x1b[22m") + fg(tx[1]) + DEFBG, tx[0]
                elif top and bot:
                    style, ch = fg(top) + bg(bot), "▀"
                elif top:
                    style, ch = fg(top) + DEFBG, "▀"
                elif bot:
                    style, ch = fg(bot) + DEFBG, "▄"
                elif ns and not quiet:
                    style, ch = fg(sand_q(0.3 + d * 2)) + DEFBG, GRAINS[ns]
                else:
                    style, ch = DEFBG, " "
                if style != cur:
                    line.append(("\x1b[22m" if cur and "\x1b[1m" in cur else "") + style)
                    cur = style
                line.append(ch)
            line.append("\x1b[0m")
            rows.append("".join(line))
        return "".join(rows)


# ── the launch session ───────────────────────────────────────────────────
LW = 80


def write(s):
    OUT.write(s)
    OUT.flush()


def emit(segments, used=0):
    """A line on the explicit field colour, padded to LW (`used` columns already drawn)."""
    n = used + sum(len(t) for t, _ in segments)
    return DEFBG + "".join(fg(c) + t for t, c in segments) + DEFBG + " " * max(0, LW - n) + "\x1b[0m"


def header():
    right = {
        0: [("near ", TEXT), ("AI Red", RED), ("  ·  SandBox", TEXT)],
        1: [("Cybersecurity Program", PEWTER)],
        3: [("session ", PEWTER), (SESSION, TEXT), ("  ·  net=none", PEWTER)]
           + ([("  ·  keys stay on the host", PEWTER)] if LW >= 76 else []),
    }
    lines = []
    for j in range(6):
        cells = []
        for i in range(12):
            t, b = MARK[2 * j][i], MARK[2 * j + 1][i]
            tc = RED if t == "R" else LIGHT if t == "#" else None
            bc = RED if b == "R" else LIGHT if b == "#" else None
            if tc and bc:
                cells.append(fg(tc) + bg(bc) + "▀")
            elif tc:
                cells.append(fg(tc) + DEFBG + "▀")
            elif bc:
                cells.append(fg(bc) + DEFBG + "▄")
            else:
                cells.append(DEFBG + " ")
        lines.append(DEFBG + "  " + "".join(cells) + DEFBG + "   " + emit(right.get(j, []), used=17))
    return lines


DUNE = "▁▁▂▃▄▅▄▃▂▁▁▁▂▂▃▃▂▁▁▁▁▂▃▄▅▆▅▄▃▂▁▁▁▂▃▃▂▂▁▁▁▂▃▄▃▂▁▁▁▁▂▂▃▄▅▄▃▂▁▁▁▂▂▃▄▅▄▃▂▁▁▂▃▄▃▂"


def heading(word):
    return emit([("  ░▒▓█ ", S1), (word, TEXT), (" █▓▒░", S1)])


def rule(word):
    inner = f" ✦ {word} ✦ "
    left = max(2, (LW - 4 - len(inner)) // 2)
    return emit([("  " + "═" * left, PEWTER), (inner, TEXT), ("═" * max(2, LW - 4 - left - len(inner)), PEWTER)])


def status_line(label, detail, status, live=None):
    pre = f"  > {label:<11} "
    body = detail if live is None else live
    lead = (LW - 12) - len(pre) - len(body)
    segs = [(pre, TEXT), (body, TEXT if live is None else PEWTER)]
    segs.append((" " + "." * max(1, lead - 1) + " " if live is None else " " * max(1, lead + 1), PEWTER))
    segs += [("[ ", PEWTER), ("OK" if status == "ok" else status, S1 if status == "ok" else PEWTER), (" ]", PEWTER)]
    return emit(segs)


def sweep(f, width=8, band="▒█▒"):
    span = width - len(band)
    pos = (f // 2) % (span * 2)
    p = pos if pos <= span else span * 2 - pos
    return "▕" + " " * p + band + " " * (span - p) + "▏"


def run_step(label, detail, seconds):
    for f in range(int(seconds * 14)):
        write("\r" + status_line(label, detail, "··" if (f // 6) % 2 else "  ", live=sweep(f)))
        time.sleep(1 / 14)
    write("\r" + status_line(label, detail, "ok") + "\n")


def run_decode_step(label):
    for f in range(14 * 3):
        n = max(0, (f - 6) // 2)
        name = "".join(ch if i < n else KANA[(i * 7 + f * 13) % len(KANA)] for i, ch in enumerate(MACHINE))
        write("\r" + status_line(label, "", "··" if (f // 6) % 2 else "  ", live=f"{name} {sweep(f)}"))
        time.sleep(1 / 14)
    write("\r" + status_line(label, f"{MACHINE} · net=none", "ok") + "\n")


def type_out(s, delay=0.06):
    for ch in s:
        write(ch)
        time.sleep(delay)


def main():
    global LW
    cols, rows = shutil.get_terminal_size((80, 24))
    while cols < 50 or rows < 16:
        write(f"\r\x1b[2Kwiden to 50x16 (now {cols}x{rows}) ")
        time.sleep(0.3)
        cols, rows = shutil.get_terminal_size((80, 24))
    LW = min(cols, 80)
    splash = Splash(cols, rows)
    write("\r\x1b[2K" + fg(PEWTER) + "SandBox CLI demo · mock data · press Enter to play" + "\x1b[0m ")
    input()
    write("\x1b[?25l")
    try:
        write("\x1b[2J\x1b[H" + fg(PEWTER) + "~/research " + "\x1b[0m" + "$ ")
        type_out("rts launch")
        time.sleep(0.4)
        # the prompt is on row 1; the splash fills the rows below it, placed absolutely
        top = 2
        k = 0
        while k <= 210:
            start = time.time()
            write(splash.frame(k, top))
            k += 2
            time.sleep(max(0.0, 1 / 14 - (time.time() - start)))
        write(f"\x1b[{top + splash.H};1H\x1b[?25h" + emit([("press Enter to continue to the launch log", PEWTER)]))
        input()
        write("\x1b[?25l\n")
        for line in header():
            write(line + "\n")
        write(emit([("  " + DUNE[:LW - 4], PEWTER)]) + "\n\n")
        write(heading("LAUNCH") + "\n")
        run_step("preflight", "mvm supervisor · opencode 2.1.4", 0.9)
        run_step("sign-in", "NEAR AI Cloud (keychain)", 0.8)
        run_step("inference", "ironwire → 127.0.0.1:43210", 0.7)
        run_decode_step("microVM")
        run_step("copy in", "12 files → /in", 0.7)
        run_step("handshake", "plugin nonce verified", 0.6)
        write("\n" + rule("HANDING THE TERMINAL TO OPENCODE") + "\n")
        write(emit([("  opencode runs here; the launcher stays quiet until it exits", PEWTER)]) + "\n")
        time.sleep(2.2)
        write("\n" + heading("TEARDOWN") + "\n")
        run_step("opencode", "stopped", 0.5)
        run_step("export", "4 files · 12,288 bytes → out/", 0.8)
        run_step("microVM", f"{MACHINE} removed", 0.7)
        write(emit([("  results  ", PEWTER), (f"sessions/{SESSION}/out", TEXT)]) + "\n")
        write(emit([("  " + DUNE[:LW - 4], PEWTER)]) + "\n")
    finally:
        write("\x1b[0m\x1b[?25h\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        write("\x1b[0m\x1b[?25h\n")
