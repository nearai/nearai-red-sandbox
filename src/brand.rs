//! The NEAR AI Red SandBox look in the launcher's own terminal output: the
//! splash (`brand::splash`), the styled launch progress (`brand::progress`)
//! and the opencode theme file (`brand::theme`).
//!
//! Ported from scripts/splash/sandbox_demo.py and keeping its properties:
//! cells use the terminal's own background (SGR 49) and body text its own
//! foreground (SGR 39), so light and dark terminals both work; the palette
//! stays small, and sand over art is drawn as a background tint, because
//! xterm.js-based terminals cache one glyph per character and colour pair
//! and some stop drawing once that cache overflows.

pub mod progress;
pub mod splash;
pub mod theme;

use std::io::IsTerminal;

/// An sRGB colour; mixes keep fractions, emitted values truncate like the prototype.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rgb(pub f64, pub f64, pub f64);

const fn hex(v: u32) -> Rgb {
    Rgb(((v >> 16) & 0xff) as f64, ((v >> 8) & 0xff) as f64, (v & 0xff) as f64)
}

pub const TOP: Rgb = hex(0xE9E7E1);
pub const FRONT: Rgb = hex(0xB7B7BB);
pub const SIDE: Rgb = hex(0x76767D);
pub const CREASE: Rgb = hex(0x2B2B30);
pub const INK: Rgb = hex(0x272727);
pub const RED: Rgb = hex(0xEB1924);
pub const WHITE: Rgb = hex(0xFAFAF7);
pub const PEWTER: Rgb = hex(0x808088);
pub const LIGHT: Rgb = hex(0xD9D9DC);
pub const S0: Rgb = hex(0x3B362D);
pub const S1: Rgb = hex(0xA1977F);
pub const S2: Rgb = hex(0xEEE5D1);
pub const PILE: Rgb = hex(0xD6CAB0);
/// VOID (#070708) is the prototype's backdrop; the launcher never paints it,
/// because cells keep the terminal's own background.
pub const VOID: Rgb = hex(0x070708);

/// The terminal's own background.
pub const DEFBG: &str = "\x1b[49m";
pub const RESET: &str = "\x1b[0m";

/// How many colours the terminal takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    TrueColor,
    Ansi256,
}

impl Depth {
    /// COLORTERM=truecolor or 24bit means 24-bit colour; otherwise the 256-colour palette.
    pub fn from_env(env: &[(String, String)]) -> Self {
        match get(env, "COLORTERM") {
            Some(v) if v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit") => Depth::TrueColor,
            _ => Depth::Ansi256,
        }
    }

    /// A foreground; None is the terminal's own (SGR 39).
    pub fn fg(self, c: Option<Rgb>) -> String {
        match c {
            None => "\x1b[39m".into(),
            Some(c) => self.sgr(38, c),
        }
    }

    pub fn bg(self, c: Rgb) -> String {
        self.sgr(48, c)
    }

    fn sgr(self, kind: u8, c: Rgb) -> String {
        let (r, g, b) = (c.0 as u8, c.1 as u8, c.2 as u8);
        match self {
            Depth::TrueColor => format!("\x1b[{kind};2;{r};{g};{b}m"),
            Depth::Ansi256 => format!("\x1b[{kind};5;{}m", nearest_256(r, g, b)),
        }
    }
}

/// The nearest xterm 256-colour index: the 6x6x6 cube or the 24-step grey ramp.
pub fn nearest_256(r: u8, g: u8, b: u8) -> u8 {
    const STEPS: [i32; 6] = [0, 95, 135, 175, 215, 255];
    let level = |v: u8| -> usize {
        // Ties go to the brighter level.
        (0..6).rev().min_by_key(|&i| (STEPS[i] - v as i32).abs()).unwrap()
    };
    let (ri, gi, bi) = (level(r), level(g), level(b));
    let dist = |(x, y, z): (i32, i32, i32)| {
        (x - r as i32).pow(2) + (y - g as i32).pow(2) + (z - b as i32).pow(2)
    };
    let cube = (STEPS[ri], STEPS[gi], STEPS[bi]);
    let mean = (r as i32 + g as i32 + b as i32) / 3;
    let gi_ramp = ((mean - 8).max(0) / 10).min(23);
    let grey = 8 + 10 * gi_ramp;
    if dist((grey, grey, grey)) < dist(cube) {
        232 + gi_ramp as u8
    } else {
        16 + 36 * ri as u8 + 6 * gi as u8 + bi as u8
    }
}

fn get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Colour is allowed: NO_COLOR is unset or empty (no-color.org) and TERM is not `dumb`.
pub fn colour_allowed(env: &[(String, String)]) -> bool {
    get(env, "NO_COLOR").is_none_or(str::is_empty) && get(env, "TERM") != Some("dumb")
}

/// The splash is drawn only for an interactive terminal on stdin and stdout,
/// with colour allowed and without `--no-splash`.
pub fn splash_wanted(stdin_tty: bool, stdout_tty: bool, env: &[(String, String)], no_splash: bool) -> bool {
    stdin_tty && stdout_tty && !no_splash && colour_allowed(env)
}

pub fn stdin_stdout_are_ttys() -> (bool, bool) {
    (std::io::stdin().is_terminal(), std::io::stdout().is_terminal())
}

/// The window size of a terminal file descriptor, as (cols, rows).
pub fn window_size(fd: i32) -> Option<(usize, usize)> {
    let mut size = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCGWINSZ writes one winsize into the struct we own.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut size) } < 0 || size.ws_col == 0 || size.ws_row == 0 {
        return None;
    }
    Some((size.ws_col as usize, size.ws_row as usize))
}

/// Output with every CSI and OSC escape removed (tests and plain captures).
pub fn strip_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn truecolor_needs_colorterm_and_otherwise_maps_to_the_256_palette() {
        assert_eq!(Depth::from_env(&env(&[("COLORTERM", "truecolor")])), Depth::TrueColor);
        assert_eq!(Depth::from_env(&env(&[("COLORTERM", "24bit")])), Depth::TrueColor);
        assert_eq!(Depth::from_env(&env(&[("COLORTERM", "yes")])), Depth::Ansi256);
        assert_eq!(Depth::from_env(&env(&[])), Depth::Ansi256);
        assert_eq!(Depth::TrueColor.fg(Some(RED)), "\x1b[38;2;235;25;36m");
        assert_eq!(Depth::Ansi256.fg(Some(RED)), "\x1b[38;5;196m");
        assert_eq!(Depth::Ansi256.bg(WHITE), "\x1b[48;5;231m");
        assert_eq!(Depth::TrueColor.fg(None), "\x1b[39m");
        assert_eq!(nearest_256(0, 0, 0), 16);
        assert_eq!(nearest_256(128, 128, 136), 244);
    }

    #[test]
    fn the_splash_needs_two_ttys_colour_and_no_opt_out() {
        let plain = env(&[("TERM", "xterm-256color")]);
        assert!(splash_wanted(true, true, &plain, false));
        assert!(!splash_wanted(false, true, &plain, false));
        assert!(!splash_wanted(true, false, &plain, false));
        assert!(!splash_wanted(true, true, &plain, true), "--no-splash");
        assert!(!splash_wanted(true, true, &env(&[("NO_COLOR", "1")]), false));
        assert!(splash_wanted(true, true, &env(&[("NO_COLOR", "")]), false), "an empty NO_COLOR is unset");
        assert!(!splash_wanted(true, true, &env(&[("TERM", "dumb")]), false));
    }

    #[test]
    fn strip_escapes_removes_csi_and_osc() {
        assert_eq!(strip_escapes("\x1b[38;2;1;2;3ma\x1b[0m\x1b]2;title\x07b\x1b]0;t\x1b\\c"), "abc");
    }
}
