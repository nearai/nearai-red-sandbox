//! `rts launch` progress on stderr: the prototype's header, headings, rules
//! and status lines with a sweeping band (and a decode line for steps that
//! verify), or plain `[rts] ...` lines carrying the same information when
//! stderr is not a terminal, NO_COLOR is set or TERM is dumb.
//!
//! The session log (launcher.log) is written by the session's Logger and
//! stays plain text; this module only draws the terminal side. Errors are
//! never drawn here: a failed step ends in a FAIL line and the caller prints
//! the full reason on the next line.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::{DEFBG, Depth, LIGHT, PEWTER, RED, RESET, Rgb, S1};

const KANA: [char; 16] = ['ｱ', 'ｶ', 'ｻ', 'ﾀ', 'ﾅ', 'ﾊ', 'ﾏ', 'ﾔ', 'ﾗ', 'ﾜ', 'ｦ', 'ﾝ', 'ｷ', 'ｼ', 'ﾁ', 'ﾆ'];
const DUNE: &str = "▁▁▂▃▄▅▄▃▂▁▁▁▂▂▃▃▂▁▁▁▁▂▃▄▅▆▅▄▃▂▁▁▁▂▃▃▂▂▁▁▁▂▃▄▃▂▁▁▁▁▂▂▃▄▅▄▃▂▁▁▁▂▂▃▄▅▄▃▂▁▁▂▃▄▃▂";
const TICK: Duration = Duration::from_micros(1_000_000 / 14);
/// Styled output needs room for a status line.
const MIN_WIDTH: usize = 60;

/// The body text colour: the terminal's own foreground.
const TEXT: Option<Rgb> = None;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Plain,
    Styled { depth: Depth, width: usize },
}

impl Mode {
    /// Styled only on a terminal of at least 60 columns with colour allowed.
    pub fn detect(stderr_tty: bool, cols: Option<usize>, env: &[(String, String)]) -> Self {
        match cols {
            Some(c) if stderr_tty && c >= MIN_WIDTH && super::colour_allowed(env) => {
                Mode::Styled { depth: Depth::from_env(env), width: c.min(80) }
            }
            _ => Mode::Plain,
        }
    }

    /// For stderr of this process.
    pub fn for_stderr(env: &[(String, String)]) -> Self {
        use std::io::IsTerminal;
        Mode::detect(std::io::stderr().is_terminal(), super::window_size(2).map(|(cols, _)| cols), env)
    }
}

/// What a running step shows until it ends.
#[derive(Clone, Debug)]
pub enum Live {
    /// A pending marker only: for steps that print their own lines (sign-in).
    Still,
    /// The sweeping band.
    Sweep,
    /// `text` decoding from kana, then the band.
    Decode(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Fail,
    Pending(usize),
}

fn chars(s: &str) -> usize {
    s.chars().count()
}

fn truncate(s: &str, max: usize) -> String {
    if chars(s) <= max {
        return s.into();
    }
    s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
}

/// Renders styled lines for one width and colour depth.
#[derive(Clone, Copy)]
pub struct Painter {
    pub depth: Depth,
    pub width: usize,
}

impl Painter {
    /// One line on the terminal's own background, padded to the width.
    fn emit(&self, segments: &[(&str, Option<Rgb>)], used: usize) -> String {
        let n = used + segments.iter().map(|(t, _)| chars(t)).sum::<usize>();
        let mut s = String::from(DEFBG);
        for (t, c) in segments {
            s.push_str(&self.depth.fg(*c));
            s.push_str(t);
        }
        s.push_str(DEFBG);
        s.push_str(&" ".repeat(self.width.saturating_sub(n)));
        s.push_str(RESET);
        s
    }

    /// The small cube beside the product name, the session and its results.
    pub fn header(&self, session_id: &str, results: &Path) -> Vec<String> {
        let results = truncate(&results.display().to_string(), self.width.saturating_sub(17 + 9));
        let right: [Vec<(&str, Option<Rgb>)>; 6] = [
            vec![("near ", TEXT), ("AI Red", Some(RED)), ("  ·  SandBox", TEXT)],
            vec![("Cybersecurity Program", Some(PEWTER))],
            vec![],
            vec![("session ", Some(PEWTER)), (session_id, TEXT), ("  ·  net=none", Some(PEWTER))],
            vec![("results  ", Some(PEWTER)), (results.as_str(), TEXT)],
            vec![],
        ];
        let mark = super::splash::mark();
        let pick = |ch: u8| match ch {
            b'R' => Some(RED),
            b'#' => Some(LIGHT),
            _ => None,
        };
        (0..6)
            .map(|j| {
                let mut cells = String::new();
                for i in 0..12 {
                    let (t, b) = (pick(mark[2 * j].as_bytes()[i]), pick(mark[2 * j + 1].as_bytes()[i]));
                    cells.push_str(&match (t, b) {
                        (Some(t), Some(b)) => self.depth.fg(Some(t)) + &self.depth.bg(b) + "▀",
                        (Some(t), None) => self.depth.fg(Some(t)) + DEFBG + "▀",
                        (None, Some(b)) => self.depth.fg(Some(b)) + DEFBG + "▄",
                        (None, None) => format!("{DEFBG} "),
                    });
                }
                format!("{DEFBG}  {cells}{DEFBG}   {}", self.emit(&right[j], 17))
            })
            .collect()
    }

    pub fn dune(&self) -> String {
        let d: String = DUNE.chars().take(self.width.saturating_sub(4)).collect();
        self.emit(&[("  ", None), (d.as_str(), Some(PEWTER))], 0)
    }

    pub fn heading(&self, word: &str) -> String {
        self.emit(&[("  ░▒▓█ ", Some(S1)), (word, TEXT), (" █▓▒░", Some(S1))], 0)
    }

    pub fn rule(&self, word: &str) -> String {
        let inner = format!(" ✦ {word} ✦ ");
        let span = self.width.saturating_sub(4);
        let left = (span.saturating_sub(chars(&inner)) / 2).max(2);
        let right = span.saturating_sub(left + chars(&inner)).max(2);
        self.emit(
            &[(&format!("  {}", "═".repeat(left)), Some(PEWTER)), (&inner, TEXT), (&"═".repeat(right), Some(PEWTER))],
            0,
        )
    }

    /// A session log or rts line: the text in the terminal's own colour, so a
    /// refusal reported through the log reads as plainly as it did before.
    pub fn note(&self, text: &str) -> String {
        self.emit(&[("  · ", Some(PEWTER)), (text, TEXT)], 0)
    }

    pub fn muted(&self, text: &str) -> String {
        self.emit(&[("  · ", Some(PEWTER)), (text, Some(PEWTER))], 0)
    }

    fn status_line(&self, label: &str, detail: &str, status: Status, live: Option<&str>) -> String {
        let pre = format!("  > {label:<11} ");
        let room = (self.width - 12).saturating_sub(chars(&pre) + 2);
        let body = truncate(live.unwrap_or(detail), room);
        let lead = (self.width - 12) as isize - chars(&pre) as isize - chars(&body) as isize;
        let fill = if live.is_none() {
            format!(" {} ", ".".repeat((lead - 1).max(1) as usize))
        } else {
            " ".repeat((lead + 1).max(1) as usize)
        };
        let (word, colour) = match status {
            Status::Ok => ("OK", S1),
            Status::Fail => ("FAIL", RED),
            Status::Pending(f) => (if (f / 6) % 2 == 1 { "··" } else { "  " }, PEWTER),
        };
        self.emit(
            &[
                (&pre, TEXT),
                (&body, if live.is_none() { TEXT } else { Some(PEWTER) }),
                (&fill, Some(PEWTER)),
                ("[ ", Some(PEWTER)),
                (word, Some(colour)),
                (" ]", Some(PEWTER)),
            ],
            0,
        )
    }

    fn live_line(&self, label: &str, live: &Live, frame: usize) -> String {
        let text = match live {
            Live::Still => String::new(),
            Live::Sweep => sweep(frame),
            Live::Decode(name) => format!("{} {}", decode(name, frame), sweep(frame)),
        };
        self.status_line(label, "", Status::Pending(frame), Some(&text))
    }
}

/// The band sweeping back and forth in an 8-cell track.
fn sweep(f: usize) -> String {
    const WIDTH: usize = 8;
    let band = "▒█▒";
    let span = WIDTH - chars(band);
    let pos = (f / 2) % (span * 2);
    let p = if pos <= span { pos } else { span * 2 - pos };
    format!("▕{}{band}{}▏", " ".repeat(p), " ".repeat(span - p))
}

/// `name` revealed left to right from cycling kana; fully revealed from frame 6 + 2 * len.
fn decode(name: &str, f: usize) -> String {
    let n = f.saturating_sub(6) / 2;
    name.chars()
        .enumerate()
        .map(|(i, ch)| if i < n { ch } else { KANA[(i * 7 + f * 13) % KANA.len()] })
        .collect()
}

struct State {
    mode: Mode,
    out: Box<dyn Write + Send>,
    /// The running step's label and what it shows.
    live: Option<(String, Live)>,
    frame: usize,
    /// opencode owns the terminal: write plain lines only, as before.
    handed_off: bool,
}

impl State {
    fn painter(&self) -> Option<Painter> {
        match self.mode {
            Mode::Styled { depth, width } if !self.handed_off => Some(Painter { depth, width }),
            _ => None,
        }
    }

    fn write(&mut self, s: &str) {
        let _ = self.out.write_all(s.as_bytes());
        let _ = self.out.flush();
    }

    fn line(&mut self, s: &str) {
        self.write(&format!("{s}\n"));
    }

    fn draw_live(&mut self) {
        if let (Some(p), Some((label, live))) = (self.painter(), self.live.clone()) {
            let line = p.live_line(&label, &live, self.frame);
            self.write(&format!("\r{line}"));
        }
    }

    /// Clear the running step's line before another line is written.
    fn clear_live(&mut self) {
        if self.live.is_some() && self.painter().is_some() {
            self.write("\r\x1b[2K");
        }
    }
}

/// The launch progress. Cloning shares one output.
#[derive(Clone)]
pub struct Progress(Arc<Mutex<State>>, bool);

impl Progress {
    /// `animate`: redraw running steps from a ticker thread (off in tests).
    pub fn new(mode: Mode, out: Box<dyn Write + Send>, animate: bool) -> Self {
        Progress(Arc::new(Mutex::new(State { mode, out, live: None, frame: 0, handed_off: false })), animate)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn header(&self, session_id: &str, results: &Path) {
        let mut s = self.state();
        match s.painter() {
            Some(p) => {
                for line in p.header(session_id, results) {
                    s.line(&line);
                }
                s.line(&p.dune());
                s.line("");
            }
            None => s.line(&format!(
                "[rts] NEAR AI Red SandBox · session {session_id} · net=none · results {}",
                results.display()
            )),
        }
    }

    /// A section heading; plain output has none (the lines carry their own context).
    pub fn heading(&self, word: &str) {
        let mut s = self.state();
        if let Some(p) = s.painter() {
            s.clear_live();
            s.line(&p.heading(word));
            s.draw_live();
        }
    }

    /// Start a step; it ends with `ok`, or as FAIL when dropped.
    pub fn step(&self, label: &str, live: Live) -> Step {
        let mut s = self.state();
        s.live = Some((label.to_string(), live));
        s.frame = 0;
        s.draw_live();
        let animate = self.1 && s.painter().is_some() && !matches!(s.live, Some((_, Live::Still)));
        drop(s);
        let ticker = animate.then(|| {
            let stop = Arc::new(AtomicBool::new(false));
            let (state, flag) = (self.0.clone(), stop.clone());
            let handle = thread::spawn(move || {
                while !flag.load(Ordering::SeqCst) {
                    thread::sleep(TICK);
                    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                    if flag.load(Ordering::SeqCst) {
                        break;
                    }
                    s.frame += 1;
                    s.draw_live();
                }
            });
            (stop, handle)
        });
        Step { progress: Some(self.clone()), label: label.to_string(), ticker }
    }

    /// Advance a running step's animation by one frame (the ticker's job).
    pub fn tick(&self) {
        let mut s = self.state();
        s.frame += 1;
        s.draw_live();
    }

    fn finish(&self, label: &str, detail: &str, ok: bool) {
        let mut s = self.state();
        s.clear_live();
        s.live = None;
        match s.painter() {
            Some(p) => {
                let (detail, status) = if ok { (detail, Status::Ok) } else { ("failed; the reason follows", Status::Fail) };
                let line = p.status_line(label, detail, status, None);
                s.line(&line);
            }
            None if s.handed_off => {}
            None => s.line(&format!("[rts] {label}: {}", if ok { detail } else { "failed" })),
        }
    }

    /// A line from the session log or another part of rts: `plain` exactly
    /// as rts printed it before, `message` in the styled layout.
    pub fn note(&self, plain: &str, message: &str) {
        let mut s = self.state();
        match s.painter() {
            Some(p) => {
                s.clear_live();
                s.line(&p.note(message));
                s.draw_live();
            }
            None => s.line(plain),
        }
    }

    /// opencode takes the terminal: a closing rule, then plain lines only.
    pub fn hand_off(&self) {
        let mut s = self.state();
        s.clear_live();
        s.live = None;
        match s.painter() {
            Some(p) => {
                s.line("");
                s.line(&p.rule("HANDING THE TERMINAL TO OPENCODE"));
                s.line(&p.muted("opencode runs here; the launcher stays quiet until it exits"));
            }
            None => s.line("[rts] handing the terminal to opencode"),
        }
        s.handed_off = true;
    }

    /// Teardown starts: the terminal is the launcher's again.
    pub fn teardown(&self) {
        let mut s = self.state();
        s.handed_off = false;
        s.clear_live();
        s.live = None;
        if let Some(p) = s.painter() {
            s.line("");
            s.line(&p.heading("TEARDOWN"));
        }
    }
}

/// A running step.
pub struct Step {
    progress: Option<Progress>,
    label: String,
    ticker: Option<(Arc<AtomicBool>, JoinHandle<()>)>,
}

impl Step {
    /// A step that draws nothing (no launch progress installed).
    pub fn inert() -> Self {
        Step { progress: None, label: String::new(), ticker: None }
    }

    fn stop(&mut self) {
        if let Some((stop, handle)) = self.ticker.take() {
            stop.store(true, Ordering::SeqCst);
            let _ = handle.join();
        }
    }

    pub fn ok(mut self, detail: &str) {
        self.stop();
        if let Some(p) = self.progress.take() {
            p.finish(&self.label, detail, true);
        }
    }
}

impl Drop for Step {
    fn drop(&mut self) {
        self.stop();
        if let Some(p) = self.progress.take() {
            p.finish(&self.label, "", false);
        }
    }
}

// --- the process's launch progress ---

static CURRENT: Mutex<Option<Progress>> = Mutex::new(None);

/// Make `p` the launch progress for this process (`rts launch` only).
pub fn install(p: Progress) {
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = Some(p);
}

pub fn current() -> Option<Progress> {
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// A step of the installed progress, or an inert one.
pub fn step(label: &str, live: Live) -> Step {
    current().map_or_else(Step::inert, |p| p.step(label, live))
}

/// One session log line on the terminal: `[rts <id>] <m>` unless styled.
pub fn log_line(id: &str, m: &str) {
    let plain = format!("[rts {id}] {m}");
    match current() {
        Some(p) => p.note(&plain, m),
        None => eprintln!("{plain}"),
    }
}

/// A line rts prints for the operator outside the session log; a leading
/// `[rts] ` is left out of the styled layout.
pub fn message(m: &str) {
    match current() {
        Some(p) => p.note(m, m.strip_prefix("[rts] ").unwrap_or(m)),
        None => eprintln!("{m}"),
    }
}

pub fn hand_off() {
    if let Some(p) = current() {
        p.hand_off();
    }
}

pub fn teardown() {
    if let Some(p) = current() {
        p.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::super::strip_escapes;
    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    /// The same launch, as the real one drives it.
    fn launch(p: &Progress) {
        p.header("3f9a1c2b7e04", Path::new("/s/3f9a1c2b7e04/out"));
        p.heading("LAUNCH");
        p.step("preflight", Live::Sweep).ok("mvm supervisor · opencode 2.2.2");
        let s = p.step("sign-in", Live::Still);
        p.note("Opening your browser to sign in to NEAR AI Cloud…", "Opening your browser to sign in to NEAR AI Cloud…");
        s.ok("NEAR AI Cloud");
        let s = p.step("attestation", Live::Decode("deepseek-ai/DeepSeek-V4.1".into()));
        for _ in 0..70 {
            p.tick();
        }
        s.ok("1 model verified · 2 TLS keys pinned");
        p.note("[rts 3f9a1c2b7e04] created rts-3f9a1c2b7e04", "created rts-3f9a1c2b7e04");
        drop(p.step("microVM", Live::Decode("rts-3f9a1c2b7e04".into())));
        p.hand_off();
        p.note("[rts 3f9a1c2b7e04] plugin ready; session running", "plugin ready; session running");
        p.teardown();
        p.note("[rts 3f9a1c2b7e04] teardown: removed rts-3f9a1c2b7e04", "teardown: removed rts-3f9a1c2b7e04");
    }

    #[test]
    fn plain_output_has_no_escapes_and_the_same_information() {
        let buf = Buf::default();
        launch(&Progress::new(Mode::Plain, Box::new(buf.clone()), false));
        let out = buf.text();
        assert!(!out.contains('\x1b') && !out.contains('\r'), "{out:?}");
        assert_eq!(
            out.lines().collect::<Vec<_>>(),
            [
                "[rts] NEAR AI Red SandBox · session 3f9a1c2b7e04 · net=none · results /s/3f9a1c2b7e04/out",
                "[rts] preflight: mvm supervisor · opencode 2.2.2",
                "Opening your browser to sign in to NEAR AI Cloud…",
                "[rts] sign-in: NEAR AI Cloud",
                "[rts] attestation: 1 model verified · 2 TLS keys pinned",
                "[rts 3f9a1c2b7e04] created rts-3f9a1c2b7e04",
                "[rts] microVM: failed",
                "[rts] handing the terminal to opencode",
                "[rts 3f9a1c2b7e04] plugin ready; session running",
                "[rts 3f9a1c2b7e04] teardown: removed rts-3f9a1c2b7e04",
            ]
        );
    }

    fn styled(width: usize) -> (String, Vec<String>) {
        let buf = Buf::default();
        launch(&Progress::new(Mode::Styled { depth: Depth::TrueColor, width }, Box::new(buf.clone()), false));
        let out = buf.text();
        // What the terminal ends up showing: each \r-overwritten line's last state.
        let shown = strip_escapes(&out).split('\n').map(|l| l.rsplit('\r').next().unwrap().trim_end().to_string()).collect();
        (out, shown)
    }

    #[test]
    fn styled_output_has_headings_rules_and_status_lines() {
        let (out, shown) = styled(80);
        let find = |needle: &str| shown.iter().find(|l| l.contains(needle)).cloned().unwrap_or_else(|| panic!("{needle:?} in {shown:#?}"));
        assert!(find("near AI Red  ·  SandBox").starts_with("  ") && find("near AI Red").contains('▀'));
        assert!(find("session 3f9a1c2b7e04  ·  net=none").contains("session"));
        assert!(find("results  /s/3f9a1c2b7e04/out").contains("results"));
        assert_eq!(find("LAUNCH"), "  ░▒▓█ LAUNCH █▓▒░");
        assert_eq!(find("TEARDOWN"), "  ░▒▓█ TEARDOWN █▓▒░");
        let ok = find("> preflight");
        assert!(ok.starts_with("  > preflight   mvm supervisor · opencode 2.2.2 ...") && ok.ends_with("[ OK ]"), "{ok}");
        // As in the prototype: the dot leader ends one column past width - 12.
        assert_eq!(ok.chars().count(), 80 - 12 + 1 + 6);
        assert!(find("> attestation").contains("1 model verified · 2 TLS keys pinned"));
        let fail = find("> microVM");
        assert!(fail.contains("failed; the reason follows") && fail.ends_with("[ FAIL ]"), "{fail}");
        assert!(find("Opening your browser").starts_with("  · Opening your browser"));
        let rule = find("HANDING THE TERMINAL TO OPENCODE");
        assert!(rule.starts_with("  ══") && rule.ends_with("══") && rule.contains('✦'), "{rule}");
        // After the hand-off, opencode owns the screen: the plain line as before.
        assert!(shown.contains(&"[rts 3f9a1c2b7e04] plugin ready; session running".to_string()));
        assert!(find("teardown: removed").starts_with("  · teardown"));
        // Log lines, which carry session refusals, are not muted.
        assert!(out.contains("\x1b[39mteardown: removed"), "log text in the default colour");
        // The decode line showed kana while verifying, and the model name once decoded.
        assert!(KANA.iter().any(|k| out.contains(*k)));
        assert!(strip_escapes(&out).contains("deepseek-ai/DeepSeek-V4.1 ▕"));
        // Every styled line ends with a reset; nothing styled is left open.
        for line in out.split('\n').filter(|l| l.contains('\x1b')) {
            assert!(line.ends_with(RESET) || line.ends_with("\x1b[2K"), "{line:?}");
        }
        assert!(out.ends_with(&format!("{RESET}\n")));
    }

    #[test]
    fn a_narrow_terminal_keeps_status_lines_within_the_width() {
        let (_, shown) = styled(60);
        // Status lines fit; notes wrap rather than lose text (they can carry errors).
        for l in shown.iter().filter(|l| l.starts_with("  >")) {
            assert!(l.chars().count() <= 60, "{l:?}");
        }
        assert!(shown.iter().any(|l| l.starts_with("  > attestation") && l.contains('…') && l.ends_with("[ OK ]")), "{shown:#?}");
    }

    #[test]
    fn mode_detection_needs_a_wide_enough_terminal_and_colour() {
        let env = |p: &[(&str, &str)]| p.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>();
        let e = env(&[("TERM", "xterm-256color"), ("COLORTERM", "truecolor")]);
        assert_eq!(Mode::detect(true, Some(120), &e), Mode::Styled { depth: Depth::TrueColor, width: 80 });
        assert_eq!(Mode::detect(true, Some(70), &env(&[])), Mode::Styled { depth: Depth::Ansi256, width: 70 });
        assert_eq!(Mode::detect(false, Some(120), &e), Mode::Plain);
        assert_eq!(Mode::detect(true, Some(59), &e), Mode::Plain);
        assert_eq!(Mode::detect(true, None, &e), Mode::Plain);
        assert_eq!(Mode::detect(true, Some(120), &env(&[("NO_COLOR", "1")])), Mode::Plain);
        assert_eq!(Mode::detect(true, Some(120), &env(&[("TERM", "dumb")])), Mode::Plain);
    }

    #[test]
    fn the_ticker_animates_and_stops_with_the_step() {
        let buf = Buf::default();
        let p = Progress::new(Mode::Styled { depth: Depth::TrueColor, width: 80 }, Box::new(buf.clone()), true);
        let s = p.step("attestation", Live::Decode("abc".into()));
        thread::sleep(Duration::from_millis(400));
        s.ok("done");
        let n = buf.text().matches('\r').count();
        assert!(n >= 3, "{n}");
        thread::sleep(Duration::from_millis(200));
        assert_eq!(buf.text().matches('\r').count(), n, "no redraw after the step ended");
    }

    #[test]
    fn without_installed_progress_steps_are_inert() {
        Step::inert().ok("x");
        drop(Step::inert());
    }

    #[test]
    #[ignore = "prints a styled launch block for the report"]
    fn print_a_styled_launch() {
        let (_, shown) = styled(80);
        for l in shown {
            println!("{l}");
        }
    }
}
