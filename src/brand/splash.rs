//! The launch splash: a sandstorm clears to the NEAR AI Red cube, the
//! wordmark and the "Cybersecurity Program" tagline. A port of the `Splash`
//! class in scripts/splash/sandbox_demo.py (without its GIF loop), drawn
//! inline under the prompt rather than at absolute positions.
//!
//! Terminals of at least 80x24 get the full splash; from 52x16 up to that,
//! the compact layout (cube left, lockup beside it); smaller ones none.

use std::collections::HashMap;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use super::{CREASE, DEFBG, Depth, FRONT, INK, PEWTER, PILE, RED, RESET, Rgb, S0, S1, S2, SIDE, TOP, WHITE};

const MARK: [&str; 12] = [
    "....RRRR....", "...RRRRR....", "..RRRR####..", "..RR..#####.", "##RR.....###", "##RR.....###",
    "###.....####", "###.....####", ".#####..##..", "..########..", "....#####...", "....####....",
];
const WM: [&str; 9] = [
    "110111100001111100000111110011011110000022000022000222222000000000000022",
    "111111110011111110001111111011111110000222200022000222222200000000000022",
    "111000110011000011011100011011100000000222200022000220002200222200022222",
    "110000110110000011000000011011100000002200220022000220002202222220222222",
    "110000110110111111001111011011100000002200220022000222222202200220220022",
    "110000110110000000011000011011100000002222220022000222222002222220220022",
    "110000110111000011011000111011100000022222222022000220022002200000220022",
    "110000110011111110011111111011100000022000022022000220002202222220222222",
    "110000110001111100001111001011000000022000022022000220002200222200022222",
];
/// Grains by density: only ASCII, the middle dot and stipple blocks, which
/// every terminal draws.
const GRAINS: [char; 9] = [' ', '.', '·', ':', ':', '░', '░', '▒', '▒'];
/// The last animation step: the storm has settled around the lockup.
pub const LAST_STEP: usize = 210;
/// Wall-clock length of the animation; slow terminals drop frames instead.
pub const DURATION: Duration = Duration::from_millis(1500);
const FRAME: Duration = Duration::from_micros(1_000_000 / 14);

pub(crate) fn mark() -> &'static [&'static str; 12] {
    &MARK
}

fn clamp(v: f64, a: f64, b: f64) -> f64 {
    if v < a { a } else if v > b { b } else { v }
}

fn ease(t: f64) -> f64 {
    t * t * (3.0 - 2.0 * t)
}

fn sst(a: f64, b: f64, x: f64) -> f64 {
    ease(clamp((x - a) / (b - a), 0.0, 1.0))
}

fn mix(a: Rgb, b: Rgb, t: f64) -> Rgb {
    Rgb(a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t, a.2 + (b.2 - a.2) * t)
}

fn sand(b: f64) -> Rgb {
    if b < 0.5 { mix(S0, S1, b * 2.0) } else { mix(S1, S2, (b - 0.5) * 2.0) }
}

/// Nearest of four fixed sand shades, to keep the terminal's glyph cache small.
fn sand_q(b: f64) -> Rgb {
    sand(clamp((b * 3.0).round_ties_even(), 0.0, 3.0) / 3.0)
}

/// The prototype's integer hash, with Python's 32-bit masking of negative inputs.
fn hash2(i: i64, j: i64) -> f64 {
    let h = (i.wrapping_mul(374_761_393).wrapping_add(j.wrapping_mul(668_265_263)) as u64) & 0xFFFF_FFFF;
    let h = ((h ^ (h >> 13)).wrapping_mul(1_274_126_177)) & 0xFFFF_FFFF;
    (h ^ (h >> 16)) as f64 / 4_294_967_296.0
}

fn vn(x: f64, y: f64) -> f64 {
    let (xi, yi) = (x.floor(), y.floor());
    let (xf, yf) = (x - xi, y - yi);
    let (u, v) = (xf * xf * (3.0 - 2.0 * xf), yf * yf * (3.0 - 2.0 * yf));
    let (xi, yi) = (xi as i64, yi as i64);
    let (a, b) = (hash2(xi, yi), hash2(xi + 1, yi));
    let (c, d) = (hash2(xi, yi + 1), hash2(xi + 1, yi + 1));
    a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v
}

fn fbm(x: f64, y: f64, octaves: usize) -> f64 {
    let (mut s, mut a, mut f) = (0.0, 0.5, 1.0);
    for _ in 0..octaves {
        s += a * vn(x * f, y * f);
        f *= 2.03;
        a *= 0.5;
    }
    s
}

fn g1(x: f64, c: f64, w: f64, h: f64) -> f64 {
    let q = (x - c) / w;
    h * (-q * q).exp()
}

/// One placed character of text: the glyph and its colour (None: the terminal's own).
type Glyph = (char, Option<Rgb>);

/// The splash scene for one terminal size.
pub struct Splash {
    pub full: bool,
    pub width: usize,
    pub height: usize,
    fx: i64,
    fy: i64,
    s: i64,
    d: i64,
    f: f64,
    pw: usize,
    ph: usize,
    base: Vec<Option<Rgb>>,
    text: HashMap<(usize, usize), Glyph>,
    center: (f64, f64),
    /// (row0, row1, col0, col1): cells kept clear of light sand.
    boxes: Vec<(usize, usize, usize, usize)>,
}

impl Splash {
    /// The scene for a terminal of `cols` x `rows`, or None when it is too small.
    pub fn new(cols: usize, rows: usize) -> Option<Self> {
        let full = cols >= 80 && rows >= 24;
        if !full && (cols < 52 || rows < 16) {
            return None;
        }
        let (width, height, fx) = if full { (80, 23, 32) } else { (cols.min(60), 14, 7) };
        let mut sp = Splash {
            full,
            width,
            height,
            fx,
            fy: 6,
            s: 20,
            d: 4,
            f: width as f64 / 80.0,
            pw: width,
            ph: 2 * height,
            base: vec![None; width * 2 * height],
            text: HashMap::new(),
            center: (0.0, 0.0),
            boxes: Vec::new(),
        };
        sp.cube();
        if full {
            for (y, row) in WM.iter().enumerate() {
                for (x, ch) in row.chars().enumerate() {
                    if ch != '0' {
                        sp.put(4 + x as i64, 28 + y as i64, if ch == '1' { WHITE } else { RED });
                    }
                }
            }
            sp.place(20, &[("Cybersecurity Program", None)], None);
            sp.place(22, &[("S A N D B O X", Some(PEWTER))], None);
            sp.center = (40.0, 22.0);
            sp.boxes = vec![(0, 13, 25, 55), (14, 18, 3, 76), (20, 20, 28, 52), (22, 22, 30, 50)];
        } else {
            let c = (fx + sp.s + 3) as usize;
            sp.place(5, &[("near ", None), ("AI Red", Some(RED))], Some(c));
            sp.place(7, &[("Cybersecurity Program", None)], Some(c));
            sp.place(9, &[("S A N D B O X", Some(PEWTER))], Some(c));
            sp.center = ((fx + 10) as f64, 14.0);
            sp.boxes = vec![(0, 13, 1, (fx + sp.s + 2) as usize), (4, 10, c - 1, width - 1)];
        }
        Some(sp)
    }

    fn put(&mut self, x: i64, y: i64, c: Rgb) {
        if (0..self.pw as i64).contains(&x) && (0..self.ph as i64).contains(&y) {
            self.base[y as usize * self.pw + x as usize] = Some(c);
        }
    }

    fn cube(&mut self) {
        let (fx, fy, s, d) = (self.fx, self.fy, self.s, self.d);
        for y in fy..fy + s {
            for x in fx..fx + s {
                self.put(x, y, FRONT);
            }
        }
        for y in fy - d..fy {
            let o = fy - y;
            for x in fx - o..fx + s - o {
                self.put(x, y, TOP);
            }
        }
        for x in fx - d..fx {
            let o = fx - x;
            for y in fy - o..fy + s - o {
                self.put(x, y, SIDE);
            }
        }
        for x in fx - 1..fx + s - 1 {
            self.put(x, fy - 1, CREASE);
        }
        for y in fy - 1..fy + s - 1 {
            self.put(fx - 1, y, CREASE);
        }
        for o in 1..=d {
            self.put(fx - o, fy - o, CREASE);
        }
        for (j, row) in MARK.iter().enumerate() {
            for (i, ch) in row.chars().enumerate() {
                if ch != '.' {
                    self.put(fx + 4 + i as i64, fy + 4 + j as i64, if ch == 'R' { RED } else { INK });
                }
            }
        }
    }

    fn place(&mut self, r: usize, segments: &[(&str, Option<Rgb>)], col: Option<usize>) {
        let len: usize = segments.iter().map(|(t, _)| t.chars().count()).sum();
        let mut c = col.unwrap_or((self.width - len) / 2);
        for (t, colour) in segments {
            for ch in t.chars() {
                if ch != ' ' {
                    self.text.insert((r, c), (ch, *colour));
                }
                c += 1;
            }
        }
    }

    fn quiet(&self, r: usize, c: usize) -> bool {
        self.boxes.iter().any(|&(r0, r1, c0, c1)| (r0..=r1).contains(&r) && (c0..=c1).contains(&c))
    }

    /// Storm density, the clearing around the lockup, and the drift at the cube's base.
    fn raw(&self, x: f64, y: f64, t: f64) -> f64 {
        let (xx, yy) = (x * 0.05 + t * 0.9, y * 0.1);
        let qx = fbm(xx * 0.6 + 3.1 + t * 0.12, yy * 0.6 - 1.7, 2);
        let qy = fbm(xx * 0.6 - 2.3, yy * 0.6 + 4.2 + t * 0.1, 2);
        let n = fbm(xx + 2.2 * qx, yy + qy, 3);
        let gust = 0.18 * (x * 0.09 + t * 3.1 + y * 0.04 + 2.0 * qx).sin();
        clamp((n - 0.17) * 2.4 + gust, 0.0, 1.0) * (0.85 + 0.3 * y / self.ph as f64)
    }

    fn env(&self, k: f64, x: f64, y: f64, d: f64) -> f64 {
        let (cx, cy) = self.center;
        let dist = (x - cx).hypot((y - cy) * 1.3);
        let m_end = sst(30.0 * self.f, 60.0 * self.f, dist);
        let settled = |clr: f64| {
            let m = 1.0 - (1.0 - m_end) * clr;
            d * (0.1 + 0.9 * m) * (1.0 - 0.58 * clr)
        };
        if k < 48.0 {
            d
        } else if k < 144.0 {
            settled(sst(0.0, 0.6, ease((k - 48.0) / 96.0) * 1.6 - dist / (49.0 * self.f) * 0.9))
        } else {
            settled(1.0)
        }
    }

    fn piles(&self, a: f64) -> Vec<f64> {
        let (fx, s, d) = (self.fx as f64, self.s as f64, self.d as f64);
        (0..2 * self.width)
            .map(|xx| {
                let x = (xx as f64 + 0.5) / 2.0;
                let mut h = g1(x, fx - 2.0, 3.5, 3.4) + g1(x, fx + s + 1.5, 4.5, 5.0);
                h += 1.3 * sst(fx - d - 4.0, fx - d + 2.0, x) * (1.0 - sst(fx + s + 4.0, fx + s + 13.0, x));
                h += 0.7 * (vn(x * 0.55, 3.3) - 0.5);
                (h * a).max(0.0)
            })
            .collect()
    }

    /// The rows of the frame at animation step `k` (0..=LAST_STEP), each
    /// starting with `\r`, drawing exactly `width` cells and ending in a reset.
    pub fn frame(&self, k: usize, depth: Depth) -> Vec<String> {
        let kf = k as f64;
        let t = kf / 24.0;
        let a = if kf < 48.0 { 0.45 + 0.15 * kf / 48.0 } else { 0.6 + 0.4 * ease(((kf - 48.0) / 96.0).min(1.0)) };
        let hc = self.piles(a);
        let base_y = (self.fy + self.s) as f64;
        let (lc, lr) = (self.width / 2 + 1, self.height / 2 + 1);
        let lat: Vec<Vec<f64>> = (0..lr)
            .map(|j| {
                (0..lc)
                    .map(|i| {
                        let (x, y) = (2.0 * i as f64 + 0.5, 4.0 * j as f64 + 1.0);
                        self.env(kf, x, y, self.raw(x, y, t))
                    })
                    .collect()
            })
            .collect();
        let dens = |fx: f64, fy: f64| {
            let (fx, fy) = (clamp(fx, 0.0, lc as f64 - 1.001), clamp(fy, 0.0, lr as f64 - 1.001));
            let (i, j) = (fx as usize, fy as usize);
            let (tx, ty) = (fx - i as f64, fy - j as f64);
            lat[j][i] * (1.0 - tx) * (1.0 - ty)
                + lat[j][i + 1] * tx * (1.0 - ty)
                + lat[j + 1][i] * (1.0 - tx) * ty
                + lat[j + 1][i + 1] * tx * ty
        };
        let mut rows = Vec::with_capacity(self.height);
        for r in 0..self.height {
            let mut line = String::from("\r");
            let mut cur: Option<String> = None;
            for c in 0..self.width {
                let d = dens(c as f64 / 2.0, r as f64 / 2.0);
                let top = self.base[2 * r * self.pw + c];
                let bot = self.base[(2 * r + 1) * self.pw + c];
                let tx = self.text.get(&(r, c));
                let quiet = self.quiet(r, c);
                let solid = tx.is_some() || top.is_some() || bot.is_some() || quiet;
                let (mut ns, mut npile) = (0usize, 0usize);
                for dy in 0..4 {
                    for dx in 0..2 {
                        let (xx, yy) = ((2 * c + dx) as i64, (4 * r + dy) as i64);
                        let dd = dens((xx as f64 + 0.5) / 4.0 - 0.25, (yy as f64 + 0.5) / 8.0 - 0.125);
                        let shift = (t * (30.0 + 34.0 * hash2(yy, 77))) as i64;
                        if hash2(xx + shift, yy) < dd * 1.05 - 0.04 {
                            ns += 1;
                        }
                        let h = hc[xx as usize];
                        if h > 0.2 {
                            let (y, top_y) = ((yy as f64 + 0.5) / 2.0, base_y - h);
                            if top_y <= y
                                && y < base_y + 1.2
                                && hash2(xx * 3 + 11, yy * 7 + 5) < 0.5 + 0.45 * clamp((y - top_y) / 2.5, 0.0, 1.0)
                            {
                                npile += 1;
                            }
                        }
                    }
                }
                // Over the cube and wordmark, sand is one stipple colour on the
                // art's own colour: two glyphs per art colour, not every shade.
                let under = match (top, bot) {
                    (Some(a), Some(b)) => Some(mix(a, b, 0.5)),
                    (Some(a), None) | (None, Some(a)) => Some(a),
                    (None, None) => None,
                };
                let (style, ch) = if ns > 0 && (d > 0.42 || (d > 0.08 && !solid)) {
                    let dl = dens((c as f64 - 1.0) / 2.0, (r as f64 - 1.0) / 2.0);
                    let b = clamp(0.22 + 0.62 * d + 0.9 * (d - dl), 0.0, 1.0);
                    match under {
                        Some(u) if d < 0.6 => {
                            (depth.fg(Some(S1)) + &depth.bg(u), if ns + npile < 5 { '░' } else { '▒' })
                        }
                        _ => (depth.fg(Some(sand_q(b))) + DEFBG, GRAINS[(ns + npile).min(8)]),
                    }
                } else if npile > 0 {
                    match under {
                        Some(u) => (depth.fg(Some(PILE)) + &depth.bg(u), if npile < 5 { '░' } else { '▒' }),
                        None => (depth.fg(Some(PILE)) + DEFBG, GRAINS[npile]),
                    }
                } else if let Some(&(g, colour)) = tx {
                    (depth.fg(colour) + DEFBG, g)
                } else if let (Some(tc), Some(bc)) = (top, bot) {
                    (depth.fg(Some(tc)) + &depth.bg(bc), '▀')
                } else if let Some(tc) = top {
                    (depth.fg(Some(tc)) + DEFBG, '▀')
                } else if let Some(bc) = bot {
                    (depth.fg(Some(bc)) + DEFBG, '▄')
                } else if ns > 0 && !quiet {
                    (depth.fg(Some(sand_q(0.3 + d * 2.0))) + DEFBG, GRAINS[ns])
                } else {
                    (DEFBG.to_string(), ' ')
                };
                if cur.as_deref() != Some(style.as_str()) {
                    line.push_str(&style);
                    cur = Some(style);
                }
                line.push(ch);
            }
            line.push_str(RESET);
            rows.push(line);
        }
        rows
    }
}

/// Why the splash ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    Finished,
    Skipped,
    Interrupted,
}

/// What the splash loop waits on between frames.
pub trait Keys {
    /// Wait up to `timeout` for input. Some(true): Ctrl-C; Some(false): another key.
    fn wait(&mut self, timeout: Duration) -> Option<bool>;
}

/// The animation steps drawn for elapsed time `e`, ending exactly at LAST_STEP.
fn step_at(e: Duration) -> usize {
    ((e.as_secs_f64() / DURATION.as_secs_f64()).min(1.0) * LAST_STEP as f64).round() as usize
}

/// Play the splash: frames are chosen by wall-clock time, so a slow terminal
/// drops frames instead of stretching the splash; a key skips to the final
/// frame. The cursor is hidden while drawing and shown again on every exit.
pub fn play(out: &mut dyn Write, keys: &mut dyn Keys, sp: &Splash, depth: Depth) -> io::Result<Ended> {
    let start = Instant::now();
    let mut drawn = false;
    let mut draw = |out: &mut dyn Write, k: usize| -> io::Result<()> {
        let mut s = String::new();
        if drawn {
            // Back to the first row of the previous frame.
            s.push_str(&format!("\x1b[{}F", sp.height - 1));
        } else {
            s.push_str("\x1b[?25l");
        }
        s.push_str(&sp.frame(k, depth).join("\n"));
        drawn = true;
        out.write_all(s.as_bytes())?;
        out.flush()
    };
    let result = (|| {
        let mut k = 0;
        loop {
            draw(out, k)?;
            if k == LAST_STEP {
                return Ok(Ended::Finished);
            }
            let next = Instant::now() + FRAME;
            match keys.wait(next.saturating_duration_since(Instant::now())) {
                Some(true) => return Ok(Ended::Interrupted),
                Some(false) => {
                    draw(out, LAST_STEP)?;
                    return Ok(Ended::Skipped);
                }
                None => {}
            }
            let e = start.elapsed();
            k = if e >= DURATION { LAST_STEP } else { step_at(e).max(k + 1).min(LAST_STEP) };
        }
    })();
    // Leave the final frame on screen, the cursor on the line below it.
    let _ = out.write_all(format!("{RESET}\x1b[?25h\r\n").as_bytes());
    let _ = out.flush();
    result
}

/// Stdin in non-canonical, no-echo mode for the length of the splash. ISIG is
/// off too, so Ctrl-C arrives as a byte rather than a signal: the splash ends
/// cleanly without changing SIGINT handling for the steps after it.
pub struct StdinKeys {
    original: Option<libc::termios>,
}

impl StdinKeys {
    pub fn new() -> Self {
        // SAFETY: termios is plain data filled by tcgetattr before use.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        let original = (unsafe { libc::tcgetattr(0, &mut t) } == 0).then_some(t);
        if let Some(mut raw) = original {
            raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
            raw.c_cc[libc::VMIN] = 0;
            raw.c_cc[libc::VTIME] = 0;
            // SAFETY: a termios copied from tcgetattr for the same fd.
            unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw) };
        }
        StdinKeys { original }
    }
}

impl Default for StdinKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl Keys for StdinKeys {
    fn wait(&mut self, timeout: Duration) -> Option<bool> {
        let mut fds = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: one pollfd we own.
        let ready = unsafe { libc::poll(&mut fds, 1, ms) };
        if ready <= 0 || fds.revents & libc::POLLIN == 0 {
            return None;
        }
        // Drain the keypress so it reaches neither sign-in nor opencode.
        let mut buf = [0u8; 64];
        // SAFETY: reads into a buffer we own; VMIN=0 makes it non-blocking.
        let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return None;
        }
        Some(buf[..n as usize].contains(&0x03))
    }
}

impl Drop for StdinKeys {
    fn drop(&mut self) {
        if let Some(t) = self.original {
            // SAFETY: restores the attributes read in new().
            unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
        }
    }
}

/// Show the splash on stdout when `wanted`; Err only when it was interrupted.
pub fn show(wanted: bool, depth: Depth) -> Result<(), String> {
    if !wanted {
        return Ok(());
    }
    let Some(sp) = super::window_size(1).and_then(|(c, r)| Splash::new(c, r)) else {
        return Ok(());
    };
    let mut keys = StdinKeys::new();
    let ended = play(&mut io::stdout().lock(), &mut keys, &sp, depth);
    drop(keys);
    match ended {
        Ok(Ended::Interrupted) => Err("interrupted (Ctrl-C) during the splash; nothing was started".into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::strip_escapes;
    use super::*;

    fn text_rows(rows: &[String]) -> Vec<String> {
        rows.iter().map(|r| strip_escapes(r).trim_start_matches('\r').to_string()).collect()
    }

    #[test]
    fn hash_and_noise_match_the_prototype() {
        // Values from scripts/splash/sandbox_demo.py.
        assert_eq!(hash2(0, 0), 0.0);
        assert!((hash2(3, 5) - 0.09490608680061996).abs() < 1e-12, "{}", hash2(3, 5));
        assert!((hash2(-2, 7) - 0.4271658475045115).abs() < 1e-12, "{}", hash2(-2, 7));
        assert!((fbm(1.3, -0.7, 3) - 0.4434597246656345).abs() < 1e-12, "{}", fbm(1.3, -0.7, 3));
    }

    #[test]
    fn the_full_splash_at_80x24_has_the_cube_wordmark_and_tagline() {
        let sp = Splash::new(80, 24).unwrap();
        assert!(sp.full);
        let rows = sp.frame(LAST_STEP, Depth::TrueColor);
        assert_eq!(rows.len(), 23);
        let text = text_rows(&rows);
        for t in &text {
            assert_eq!(t.chars().count(), 80, "{t:?}");
        }
        // Cube: cell rows 1..=10, around columns 28..52, drawn in half blocks
        // (rows 11 and 12 are its base, under the settled sand pile).
        for t in &text[1..=10] {
            let cube: String = t.chars().skip(28).take(25).collect();
            assert!(cube.contains('▀') || cube.contains('▄'), "{t:?}");
        }
        // The red mark sits on the cube's front face.
        let front = Depth::TrueColor.bg(FRONT);
        assert!(rows[6].contains(&Depth::TrueColor.fg(Some(RED))) && rows[6].contains(&front));
        // Wordmark: cell rows 14..=18, white "near" and red "AI Red".
        for r in 14..=18 {
            assert!(text[r].contains('▀') || text[r].contains('▄'), "{:?}", text[r]);
            assert!(rows[r].contains(&Depth::TrueColor.fg(Some(WHITE))) || rows[r].contains(&Depth::TrueColor.bg(WHITE)));
        }
        assert!(text[20].contains("Cybersecurity Program"), "{:?}", text[20]);
        assert!(text[22].contains("S A N D B O X"), "{:?}", text[22]);
        for row in &rows {
            assert!(row.ends_with(RESET), "{row:?}");
            assert!(!row.contains('\n'));
        }
    }

    #[test]
    fn the_storm_covers_the_scene_before_it_clears() {
        let sp = Splash::new(80, 24).unwrap();
        let grains = |rows: Vec<String>| text_rows(&rows).concat().chars().filter(|c| "░▒.·:".contains(*c)).count();
        assert!(grains(sp.frame(0, Depth::TrueColor)) > 3 * grains(sp.frame(LAST_STEP, Depth::TrueColor)));
    }

    #[test]
    fn a_narrow_terminal_gets_the_compact_layout_and_a_tiny_one_none() {
        let sp = Splash::new(60, 20).unwrap();
        assert!(!sp.full);
        let rows = sp.frame(LAST_STEP, Depth::Ansi256);
        assert_eq!(rows.len(), 14);
        let text = text_rows(&rows);
        for t in &text {
            assert_eq!(t.chars().count(), 60, "{t:?}");
        }
        for t in &text[1..=10] {
            let cube: String = t.chars().take(28).collect();
            assert!(cube.contains('▀') || cube.contains('▄'), "{t:?}");
        }
        assert!(text[5].contains("near AI Red"), "{:?}", text[5]);
        assert!(text[7].contains("Cybersecurity Program"));
        assert!(text[9].contains("S A N D B O X"));
        assert!(rows.iter().all(|r| !r.contains(";2;")), "256-colour only");
        assert!(Splash::new(79, 24).is_some_and(|s| !s.full && s.width == 60));
        assert!(Splash::new(54, 16).is_some_and(|s| s.width == 54));
        assert!(Splash::new(51, 24).is_none() && Splash::new(80, 15).is_none());
    }

    struct Scripted(Vec<Option<bool>>, usize);

    impl Keys for Scripted {
        fn wait(&mut self, timeout: Duration) -> Option<bool> {
            self.1 += 1;
            let k = if self.0.is_empty() { None } else { self.0.remove(0) };
            if k.is_none() {
                std::thread::sleep(timeout);
            }
            k
        }
    }

    fn frames(out: &str) -> usize {
        1 + out.matches("\x1b[13F").count()
    }

    #[test]
    fn the_splash_runs_about_a_second_and_a_half_and_restores_the_terminal() {
        let sp = Splash::new(60, 20).unwrap();
        let mut out = Vec::new();
        let start = Instant::now();
        let ended = play(&mut out, &mut Scripted(vec![], 0), &sp, Depth::TrueColor).unwrap();
        let took = start.elapsed();
        assert_eq!(ended, Ended::Finished);
        assert!(took >= DURATION && took < DURATION + Duration::from_millis(900), "{took:?}");
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("\x1b[?25l"));
        assert!(out.ends_with("\x1b[0m\x1b[?25h\r\n"), "{:?}", &out[out.len() - 20..]);
        assert!((2..=30).contains(&frames(&out)), "{}", frames(&out));
        // The last frame drawn is the settled scene.
        let last = sp.frame(LAST_STEP, Depth::TrueColor).join("\n");
        assert!(out.contains(&last));
        // Nothing follows the final reset but the cursor and the newline.
        let after = &out[out.rfind(RESET).unwrap()..];
        assert_eq!(after, "\x1b[0m\x1b[?25h\r\n");
    }

    #[test]
    fn a_keypress_skips_to_the_final_frame() {
        let sp = Splash::new(80, 24).unwrap();
        let mut out = Vec::new();
        let start = Instant::now();
        let ended = play(&mut out, &mut Scripted(vec![None, Some(false)], 0), &sp, Depth::TrueColor).unwrap();
        assert_eq!(ended, Ended::Skipped);
        assert!(start.elapsed() < Duration::from_millis(600));
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.matches("\x1b[22F").count(), 2, "two frames, then the final one");
        assert!(out.contains(&sp.frame(LAST_STEP, Depth::TrueColor).join("\n")));
        assert!(out.ends_with("\x1b[0m\x1b[?25h\r\n"));
    }

    #[test]
    fn ctrl_c_ends_the_splash_and_still_restores_the_cursor() {
        let sp = Splash::new(80, 24).unwrap();
        let mut out = Vec::new();
        let ended = play(&mut out, &mut Scripted(vec![Some(true)], 0), &sp, Depth::TrueColor).unwrap();
        assert_eq!(ended, Ended::Interrupted);
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("\x1b[22F"), "no frame after the interrupt");
        assert!(out.ends_with("\x1b[0m\x1b[?25h\r\n"));
    }

    #[test]
    fn not_wanted_draws_nothing() {
        assert_eq!(show(false, Depth::TrueColor), Ok(()));
    }

    #[test]
    #[ignore = "prints the splash for the report"]
    fn print_the_splash() {
        for (c, r) in [(80, 24), (60, 20)] {
            let sp = Splash::new(c, r).unwrap();
            println!("--- {c}x{r} step {LAST_STEP} (text)");
            for row in text_rows(&sp.frame(LAST_STEP, Depth::TrueColor)) {
                println!("{}", row.trim_end());
            }
            println!("--- {c}x{r} step 0 (text)");
            for row in text_rows(&sp.frame(0, Depth::TrueColor)) {
                println!("{}", row.trim_end());
            }
        }
    }
}
