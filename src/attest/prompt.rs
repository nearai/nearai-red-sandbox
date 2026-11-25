//! Asking the user, at launch, whether to trust a NEAR AI build that nothing
//! else trusts, and attesting again in full after a yes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::trusted::{self, TrustedComposes, TrustedEntry};
use super::{AttestOptions, AttestationFailure, Attested, ComposePolicy, NotTrusted, Role};
use crate::inference::NearEnvironment;

/// Prompts per launch, so a gateway flapping between builds cannot loop.
pub const MAX_PROMPTS: usize = 3;

/// The prompt is shown only in production, under `--compose-policy pinned`,
/// with stdin and stderr both terminals, and with a verified feed document
/// in force for this launch: without one a revoked build cannot be ruled
/// out. Stored trust is honoured either way; only asking needs the feed.
pub fn eligible(
    near: NearEnvironment,
    options: &AttestOptions,
    stdin_tty: bool,
    stderr_tty: bool,
    feed_in_force: bool,
) -> bool {
    near == NearEnvironment::Production
        && options.compose_policy == ComposePolicy::Pinned
        && stdin_tty
        && stderr_tty
        && feed_in_force
}

/// `y` or `yes`, any case, surrounding whitespace ignored.
pub fn accepted(answer: &str) -> bool {
    let a = answer.trim().to_ascii_lowercase();
    a == "y" || a == "yes"
}

/// Where the build's hold issue can be found: its title carries `sha[:12]`.
pub fn compare_url(hash: &[u8; 32]) -> String {
    format!(
        "https://github.com/nearai/nearai-red-sandbox/issues?q={}",
        &hex::encode(hash)[..12]
    )
}

/// Printable ASCII only (no ESC, other controls or non-ASCII), at most `max`
/// chars.
pub(crate) fn printable(raw: &str, max: usize) -> String {
    raw.chars()
        .filter(|c| matches!(c, ' '..='~'))
        .take(max)
        .collect()
}

/// `app_name` as it may reach the terminal. No quote binds it and it also
/// comes back from the store file, so it is filtered and capped here.
pub(crate) fn display_app_name(raw: Option<&str>) -> String {
    let shown = raw.map(|r| printable(r, 64)).unwrap_or_default();
    if shown.is_empty() {
        "unknown".into()
    } else {
        shown
    }
}

/// Text from the store file (its load warning, which can quote the file's
/// bytes) as it may reach the terminal: printable ASCII, at most 300 chars.
pub fn display_store_text(raw: &str) -> String {
    printable(raw, 300)
}

/// The store-load warning's terminal line.
pub fn store_warning_line(warning: &str) -> String {
    format!("[rts] {}", display_store_text(warning))
}

fn short(hash: &[u8; 32]) -> String {
    hex::encode(&hash[..4])
}

pub fn prompt_text(nt: &NotTrusted) -> String {
    let first = match nt.role {
        Role::Gateway => "NEAR AI moved its production gateway to a new build.".to_string(),
        Role::Model => format!("NEAR AI moved {} to a new build.", printable(&nt.model, 64)),
    };
    // Only checks that have run when the prompt appears: the GPU verdict
    // runs in the full re-attestation after a yes.
    let checked = "TDX quote, TCB status, this launch's nonce, compose hash";
    format!(
        "{first}\n\
         \n  Build    {build}\
         \n  Hash     {hash}\
         \n  Checked  {checked}\
         \n  Compare  {compare}\n\
         \nTrust this build on this device? Red Sandbox will use it without asking\
         \nagain until you run `rts trust forget {short}`. [y/N]",
        build = display_app_name(nt.app_name.as_deref()),
        hash = hex::encode(nt.hash),
        compare = compare_url(&nt.hash),
        short = short(&nt.hash),
    )
}

/// The line a launch prints for each build it relies on because the user
/// trusts it. `trusted_at` comes from the store file and the model ID from
/// the session config (checked only for being non-empty), so both are
/// filtered too.
pub fn trusted_line(model: &str, role: Role, hash: &[u8; 32], trusted_at: &str) -> String {
    let what = match role {
        Role::Gateway => "gateway".to_string(),
        Role::Model => printable(model, 64),
    };
    format!(
        "[rts] NEAR AI {what} build {}: you trusted it on {}",
        short(hash),
        printable(trusted_at, 10)
    )
}

/// A [`trusted_line`] for each user-trusted entry `attested` accepted, dated
/// from `store`. An entry the store no longer holds is skipped.
pub fn trusted_lines(
    attested: &Attested,
    store: &TrustedComposes,
    near: NearEnvironment,
) -> Vec<String> {
    attested
        .user_trusted()
        .into_iter()
        .filter_map(|(model, role, hash)| {
            let entry = store.find(near, role, &hash)?;
            Some(trusted_line(&model, role, &hash, &entry.trusted_at))
        })
        .collect()
}

/// The user-trusted builds (model, role, hash) whose lines were printed last
/// this session, so re-attestation prints them again only when they change.
#[derive(Debug, Default)]
pub struct TrustedPrinted(BTreeSet<(String, Role, [u8; 32])>);

impl TrustedPrinted {
    /// Seeded from the launch attestation, whose lines the launch printed.
    pub fn from_attested(attested: &Attested) -> Self {
        Self(attested.user_trusted().into_iter().collect())
    }

    /// [`trusted_lines`] when `attested`'s user-trusted set differs from the
    /// one printed last; otherwise none.
    pub fn changed_lines(
        &mut self,
        attested: &Attested,
        store: &TrustedComposes,
        near: NearEnvironment,
    ) -> Vec<String> {
        let now: BTreeSet<_> = attested.user_trusted().into_iter().collect();
        if now == self.0 {
            return vec![];
        }
        self.0 = now;
        trusted_lines(attested, store, near)
    }
}

/// Shows a prompt and reads one answer; `None` on EOF or an error.
pub trait Ask {
    fn ask(&mut self, text: &str) -> Option<String>;
}

/// Asks on stderr and reads stdin, with the launch progress paused.
pub struct TerminalAsk;

impl Ask for TerminalAsk {
    fn ask(&mut self, text: &str) -> Option<String> {
        use std::io::{BufRead, Write};
        // Writes straight to stderr: the progress lock is held while paused,
        // so nothing here may go through `brand::progress`.
        let read = || {
            discard_type_ahead();
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\n{text} ");
            let _ = err.flush();
            drop(err);
            let mut line = String::new();
            match std::io::stdin().lock().read_line(&mut line) {
                Ok(0) | Err(_) => None,
                Ok(_) => Some(line),
            }
        };
        match crate::brand::progress::current() {
            Some(p) => p.paused(read),
            None => read(),
        }
    }
}

/// Discards terminal input typed before the prompt appears, so a line typed
/// earlier in the launch cannot answer it. Errors are ignored: this runs
/// only with stdin a terminal, and if it fails the prompt still reads the
/// next line as before.
fn discard_type_ahead() {
    #[cfg(unix)]
    // SAFETY: tcflush on fd 0 only drops queued input; it touches no memory.
    unsafe {
        libc::tcflush(0, libc::TCIFLUSH);
    }
    #[cfg(windows)]
    // SAFETY: as `brand::splash`'s console reset: flushes the console input
    // buffer of the process's own stdin handle.
    unsafe {
        use windows_sys::Win32::System::Console::{
            FlushConsoleInputBuffer, GetStdHandle, STD_INPUT_HANDLE,
        };
        FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));
    }
}

/// One `[rts]` line of the launch, through the launch progress.
fn say(line: &str) {
    #[cfg(test)]
    SAID.with(|s| s.borrow_mut().push(line.to_string()));
    crate::brand::progress::message(line);
}

#[cfg(test)]
thread_local! {
    /// Every line [`say`] printed on this thread, for tests.
    static SAID: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The lines [`say`] printed on this thread since the last call.
#[cfg(test)]
pub(crate) fn said_take() -> Vec<String> {
    SAID.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// Attests, and on a compose nothing trusts asks the user (when
/// [`eligible`], at most [`MAX_PROMPTS`] times, and only with a `home` to
/// save to). A yes saves the build and attests again from scratch: the
/// refusal came before the GPU verdict and before later entries were
/// checked, so only the new attestation's result is returned.
/// `feed_in_force` is whether this launch has a verified feed document.
#[allow(clippy::too_many_arguments)]
pub fn attest_with_consent(
    near: NearEnvironment,
    options: &AttestOptions,
    ttys: (bool, bool),
    feed_in_force: bool,
    home: Option<&Path>,
    now: u64,
    ask: &mut dyn Ask,
    mut attest: impl FnMut(&BTreeMap<[u8; 32], Role>) -> Result<Attested, AttestationFailure>,
) -> Result<Attested, AttestationFailure> {
    let (mut store, warning) = trusted::load(home);
    if let Some(w) = warning {
        say(&store_warning_line(&w));
    }
    let mut prompts = 0;
    loop {
        match attest(&store.for_environment(near)) {
            Ok(attested) => {
                for line in trusted_lines(&attested, &store, near) {
                    say(&line);
                }
                return Ok(attested);
            }
            Err(AttestationFailure::ComposeNotTrusted(nt)) => {
                let Some(home) = home else {
                    return Err(AttestationFailure::ComposeNotTrusted(nt));
                };
                if !eligible(near, options, ttys.0, ttys.1, feed_in_force) || prompts >= MAX_PROMPTS
                {
                    return Err(AttestationFailure::ComposeNotTrusted(nt));
                }
                prompts += 1;
                if !ask.ask(&prompt_text(&nt)).is_some_and(|a| accepted(&a)) {
                    return Err(AttestationFailure::ComposeNotTrusted(nt));
                }
                let entry = TrustedEntry {
                    environment: near,
                    role: nt.role,
                    sha256: nt.hash,
                    app_name: nt.app_name.clone(),
                    trusted_at: trusted::today_utc(now),
                };
                if let Err(e) = trusted::add(home, entry) {
                    let message = format!("{}; {e}", nt.message);
                    return Err(AttestationFailure::ComposeNotTrusted(NotTrusted {
                        message,
                        ..nt
                    }));
                }
                // The store's warning, if any, was printed once above.
                store = trusted::load(Some(home)).0;
            }
            Err(other) => return Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const GW_HASH: &str = "f4a9b4803216afe5fe6a59df20790d6c12cfaf64055e121ba9375756398fb2b5";

    const EXPECTED_GATEWAY: &str = "NEAR AI moved its production gateway to a new build.

  Build    dstack-0.5.15
  Hash     f4a9b4803216afe5fe6a59df20790d6c12cfaf64055e121ba9375756398fb2b5
  Checked  TDX quote, TCB status, this launch's nonce, compose hash
  Compare  https://github.com/nearai/nearai-red-sandbox/issues?q=f4a9b4803216

Trust this build on this device? Red Sandbox will use it without asking
again until you run `rts trust forget f4a9b480`. [y/N]";

    fn hash(h: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(h, &mut out).unwrap();
        out
    }

    fn gw() -> NotTrusted {
        NotTrusted {
            model: "deepseek-ai/DeepSeek-V4.1".into(),
            role: Role::Gateway,
            hash: hash(GW_HASH),
            app_name: Some("dstack-0.5.15".into()),
            message: "model deepseek-ai/DeepSeek-V4.1: gateway: compose not pinned".into(),
        }
    }

    fn model_nt(byte: u8) -> NotTrusted {
        NotTrusted {
            model: "zai-org/GLM-5".into(),
            role: Role::Model,
            hash: [byte; 32],
            app_name: Some("vllm-glm".into()),
            message: format!(
                "model zai-org/GLM-5: model_attestations[0]: compose {byte} not pinned"
            ),
        }
    }

    #[derive(Default)]
    struct ScriptedAsk {
        shown: Vec<String>,
        answers: VecDeque<Option<String>>,
    }

    impl ScriptedAsk {
        fn answering(answers: &[Option<&str>]) -> Self {
            ScriptedAsk {
                shown: vec![],
                answers: answers.iter().map(|a| a.map(String::from)).collect(),
            }
        }
    }

    impl Ask for ScriptedAsk {
        fn ask(&mut self, text: &str) -> Option<String> {
            self.shown.push(text.to_string());
            self.answers.pop_front().expect("an answer was queued")
        }
    }

    type Outcome = Result<Attested, AttestationFailure>;
    type Results = VecDeque<Outcome>;
    type TrustedMap = BTreeMap<[u8; 32], Role>;

    /// Runs `attest_with_consent` with scripted results; returns its result,
    /// the trusted maps `attest` received, and the store afterwards.
    fn run(
        ttys: (bool, bool),
        with_home: bool,
        ask: &mut ScriptedAsk,
        results: Vec<Outcome>,
    ) -> (Outcome, Vec<TrustedMap>, trusted::TrustedComposes) {
        run_feed(ttys, true, with_home, ask, results)
    }

    /// [`run`], with or without a verified feed document in force.
    fn run_feed(
        ttys: (bool, bool),
        feed_in_force: bool,
        with_home: bool,
        ask: &mut ScriptedAsk,
        results: Vec<Outcome>,
    ) -> (Outcome, Vec<TrustedMap>, trusted::TrustedComposes) {
        let d = tempfile::tempdir().unwrap();
        let home = with_home.then(|| d.path());
        let mut results: Results = results.into();
        let mut maps = vec![];
        let out = attest_with_consent(
            NearEnvironment::Production,
            &AttestOptions::default(),
            ttys,
            feed_in_force,
            home,
            NOW,
            ask,
            |trusted| {
                maps.push(trusted.clone());
                results.pop_front().expect("an attest result was queued")
            },
        );
        let (store, _) = trusted::load(Some(d.path()));
        (out, maps, store)
    }

    /// 2026-11-25T12:00:00Z.
    const NOW: u64 = 1_795_608_000;

    fn ok_with(byte: u8) -> Attested {
        Attested {
            fingerprints: [[byte; 32]].into(),
            ..Attested::default()
        }
    }

    fn not_trusted(nt: NotTrusted) -> Result<Attested, AttestationFailure> {
        Err(AttestationFailure::ComposeNotTrusted(nt))
    }

    #[test]
    fn the_gateway_prompt_matches_the_approved_wording() {
        assert_eq!(prompt_text(&gw()), EXPECTED_GATEWAY);
    }

    #[test]
    fn the_model_prompt_names_the_model() {
        let text = prompt_text(&model_nt(7));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "NEAR AI moved zai-org/GLM-5 to a new build.");
        assert_eq!(lines[2], "  Build    vllm-glm");
        // Only checks that have run when the prompt appears: the GPU verdict
        // runs in the full re-attestation after a yes.
        assert_eq!(
            lines[4],
            "  Checked  TDX quote, TCB status, this launch's nonce, compose hash"
        );
        assert!(!text.contains("GPU"), "{text}");
        assert!(
            text.ends_with("`rts trust forget 07070707`. [y/N]"),
            "{text}"
        );
    }

    #[test]
    fn the_prompt_never_mentions_review() {
        for nt in [gw(), model_nt(1)] {
            assert!(!prompt_text(&nt).to_lowercase().contains("review"));
        }
        for role in [Role::Gateway, Role::Model] {
            let line = trusted_line("m", role, &[1; 32], "2026-11-25");
            assert!(!line.to_lowercase().contains("review"), "{line}");
        }
    }

    #[test]
    fn the_trusted_lines_match_the_approved_wording() {
        assert_eq!(
            trusted_line("m", Role::Gateway, &hash(GW_HASH), "2026-11-25"),
            "[rts] NEAR AI gateway build f4a9b480: you trusted it on 2026-11-25"
        );
        assert_eq!(
            trusted_line("zai-org/GLM-5", Role::Model, &[0xab; 32], "2026-11-25"),
            "[rts] NEAR AI zai-org/GLM-5 build abababab: you trusted it on 2026-11-25"
        );
    }

    #[test]
    fn a_hostile_trusted_at_is_filtered_and_capped() {
        let line = trusted_line("m", Role::Gateway, &[1; 32], "\x1b[2J2026-11-25\r\nextra");
        assert!(!line.contains('\x1b') && !line.contains('\r') && !line.contains('\n'));
        assert!(line.ends_with("you trusted it on [2J2026-11"), "{line}");
    }

    #[test]
    fn a_hostile_app_name_cannot_rewrite_the_prompt() {
        let long = "A".repeat(200);
        let mut nt = gw();
        nt.app_name = Some(format!("\x1b[2Jevil\rname\nInjected  line{long}"));
        let text = prompt_text(&nt);
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(!text.contains('\r'), "{text:?}");
        assert_eq!(text.lines().count(), EXPECTED_GATEWAY.lines().count());
        let build = text
            .lines()
            .find_map(|l| l.strip_prefix("  Build    "))
            .unwrap();
        assert!(build.chars().count() <= 64, "{build}");
        assert!(build.starts_with("[2Jevilname"), "{build}");

        assert_eq!(display_app_name(Some("")), "unknown");
        assert_eq!(display_app_name(Some("\x1b\r\n\u{00e9}")), "unknown");
        assert_eq!(display_app_name(None), "unknown");
        assert_eq!(display_app_name(Some(&"b".repeat(200))), "b".repeat(64));
        nt.app_name = None;
        assert!(prompt_text(&nt).contains("\n  Build    unknown\n"));
    }

    #[test]
    fn a_hostile_model_name_cannot_rewrite_the_prompt_or_the_trusted_line() {
        let long = "M".repeat(200);
        let mut nt = model_nt(7);
        nt.model = format!("\x1b[2Jevil\rmodel\n{long}");
        let text = prompt_text(&nt);
        assert!(!text.contains('\x1b') && !text.contains('\r'), "{text:?}");
        assert_eq!(text.lines().count(), EXPECTED_GATEWAY.lines().count());
        let first = text.lines().next().unwrap();
        let shown = first
            .strip_prefix("NEAR AI moved ")
            .and_then(|f| f.strip_suffix(" to a new build."))
            .unwrap();
        assert!(shown.starts_with("[2Jevilmodel"), "{shown}");
        assert_eq!(shown.chars().count(), 64, "{shown}");

        let line = trusted_line(&nt.model, Role::Model, &[1; 32], "2026-11-25");
        assert!(!line.contains('\x1b') && !line.contains('\r') && !line.contains('\n'));
        assert!(
            line.starts_with(&format!("[rts] NEAR AI {shown} build ")),
            "{line}"
        );
    }

    #[test]
    fn the_compare_url_uses_the_first_12_hex_characters() {
        assert_eq!(
            compare_url(&hash(GW_HASH)),
            "https://github.com/nearai/nearai-red-sandbox/issues?q=f4a9b4803216"
        );
    }

    #[test]
    fn accepted_takes_only_y_or_yes() {
        for a in ["y", "Y", " yes\n", "YES", "y\r\n"] {
            assert!(accepted(a), "{a:?}");
        }
        for a in ["", "n", "yes please", "1", "ye", "\n"] {
            assert!(!accepted(a), "{a:?}");
        }
    }

    #[test]
    fn not_eligible_without_both_ttys_or_outside_production_pinned() {
        let pinned = AttestOptions::default();
        let mr = AttestOptions {
            compose_policy: ComposePolicy::MrConfigOnly,
            ..AttestOptions::default()
        };
        assert!(eligible(
            NearEnvironment::Production,
            &pinned,
            true,
            true,
            true
        ));
        assert!(!eligible(
            NearEnvironment::Production,
            &pinned,
            false,
            true,
            true
        ));
        assert!(!eligible(
            NearEnvironment::Production,
            &pinned,
            true,
            false,
            true
        ));
        assert!(!eligible(
            NearEnvironment::Staging,
            &pinned,
            true,
            true,
            true
        ));
        assert!(!eligible(
            NearEnvironment::Production,
            &mr,
            true,
            true,
            true
        ));
    }

    /// Without a verified feed document a revoked build cannot be told
    /// apart, so the user is never asked.
    #[test]
    fn not_eligible_without_a_feed_document() {
        let pinned = AttestOptions::default();
        assert!(!eligible(
            NearEnvironment::Production,
            &pinned,
            true,
            true,
            false
        ));
    }

    #[test]
    fn nothing_is_asked_without_a_feed_document() {
        let mut ask = ScriptedAsk::default();
        let (out, maps, store) =
            run_feed((true, true), false, true, &mut ask, vec![not_trusted(gw())]);
        match out {
            Err(AttestationFailure::ComposeNotTrusted(nt)) => assert_eq!(nt, gw()),
            other => panic!("expected the refusal as is, got {other:?}"),
        }
        assert!(ask.shown.is_empty());
        assert_eq!(maps.len(), 1);
        assert!(store.entries.is_empty());
    }

    /// The launch's own warning about a hostile store reaches the terminal
    /// filtered, through [`store_warning_line`].
    #[test]
    fn the_launch_prints_a_hostile_store_warning_without_escapes() {
        let d = tempfile::tempdir().unwrap();
        let path = crate::install::trusted_composes_path(d.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, r#"{"version":1,"entries":[],"\u001b[2J":1}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        said_take();
        let out = attest_with_consent(
            NearEnvironment::Production,
            &AttestOptions::default(),
            (true, true),
            true,
            Some(d.path()),
            NOW,
            &mut ScriptedAsk::default(),
            |_| Ok(Attested::default()),
        );
        assert!(out.is_ok());
        let said = said_take();
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(said[0].starts_with("[rts] ignoring "), "{said:?}");
        assert!(said[0].contains("unknown field `[2J`"), "{said:?}");
        assert!(!said[0].contains('\x1b'), "{said:?}");
    }

    #[test]
    fn yes_saves_the_hash_and_attests_again_with_it() {
        let mut ask = ScriptedAsk::answering(&[Some("y\n")]);
        let (out, maps, store) = run(
            (true, true),
            true,
            &mut ask,
            vec![not_trusted(gw()), Ok(ok_with(2))],
        );
        assert_eq!(out.unwrap(), ok_with(2), "the second attest call's result");
        assert_eq!(maps.len(), 2);
        assert!(maps[0].is_empty());
        assert_eq!(maps[1], BTreeMap::from([(hash(GW_HASH), Role::Gateway)]));
        assert_eq!(ask.shown, vec![EXPECTED_GATEWAY.to_string()]);
        assert_eq!(store.entries.len(), 1);
        let e = &store.entries[0];
        assert_eq!(e.environment, NearEnvironment::Production);
        assert_eq!(e.role, Role::Gateway);
        assert_eq!(e.sha256, hash(GW_HASH));
        assert_eq!(e.app_name.as_deref(), Some("dstack-0.5.15"));
        assert_eq!(e.trusted_at, "2026-11-25");
    }

    #[test]
    fn after_yes_an_error_from_the_full_attestation_is_returned_as_is() {
        let mut ask = ScriptedAsk::answering(&[Some("yes")]);
        let (out, maps, store) = run(
            (true, true),
            true,
            &mut ask,
            vec![
                not_trusted(gw()),
                Err(AttestationFailure::Other(
                    "model m: NRAS refused the GPU".into(),
                )),
            ],
        );
        match out {
            Err(AttestationFailure::Other(m)) => assert_eq!(m, "model m: NRAS refused the GPU"),
            other => panic!("expected the retry's error, got {other:?}"),
        }
        assert_eq!(maps.len(), 2);
        assert_eq!(store.entries.len(), 1, "the yes is kept");
    }

    #[test]
    fn a_hostile_app_name_is_stored_raw() {
        let mut nt = gw();
        nt.app_name = Some("\x1b[2Jx".into());
        let mut ask = ScriptedAsk::answering(&[Some("y")]);
        let (_, _, store) = run(
            (true, true),
            true,
            &mut ask,
            vec![not_trusted(nt), Ok(ok_with(1))],
        );
        assert_eq!(store.entries[0].app_name.as_deref(), Some("\x1b[2Jx"));
    }

    #[test]
    fn no_refuses_and_saves_nothing() {
        let mut ask = ScriptedAsk::answering(&[Some("n\n")]);
        let (out, maps, store) = run((true, true), true, &mut ask, vec![not_trusted(gw())]);
        match out {
            Err(AttestationFailure::ComposeNotTrusted(nt)) => assert_eq!(nt, gw()),
            other => panic!("expected ComposeNotTrusted, got {other:?}"),
        }
        assert!(store.entries.is_empty());
        assert_eq!(maps.len(), 1);
        assert_eq!(ask.shown.len(), 1);
    }

    #[test]
    fn eof_refuses() {
        let mut ask = ScriptedAsk::answering(&[None]);
        let (out, maps, store) = run((true, true), true, &mut ask, vec![not_trusted(gw())]);
        assert!(matches!(out, Err(AttestationFailure::ComposeNotTrusted(_))));
        assert!(store.entries.is_empty());
        assert_eq!(maps.len(), 1);
    }

    #[test]
    fn a_retry_meeting_another_build_prompts_for_that_one() {
        let mut ask = ScriptedAsk::answering(&[Some("y"), Some("y")]);
        let (out, maps, store) = run(
            (true, true),
            true,
            &mut ask,
            vec![
                not_trusted(model_nt(1)),
                not_trusted(model_nt(2)),
                Ok(ok_with(9)),
            ],
        );
        assert_eq!(out.unwrap(), ok_with(9));
        assert_eq!(
            ask.shown,
            vec![prompt_text(&model_nt(1)), prompt_text(&model_nt(2))]
        );
        assert_eq!(maps.len(), 3);
        assert_eq!(
            maps[2],
            BTreeMap::from([([1; 32], Role::Model), ([2; 32], Role::Model)])
        );
        assert_eq!(store.entries.len(), 2);
    }

    #[test]
    fn the_fourth_untrusted_build_refuses() {
        let mut ask = ScriptedAsk::answering(&[Some("y"), Some("y"), Some("y")]);
        let results = (1..=4).map(|b| not_trusted(model_nt(b))).collect();
        let (out, maps, _) = run((true, true), true, &mut ask, results);
        assert_eq!(ask.shown.len(), MAX_PROMPTS);
        assert_eq!(maps.len(), 4);
        match out {
            Err(AttestationFailure::ComposeNotTrusted(nt)) => assert_eq!(nt, model_nt(4)),
            other => panic!("expected the 4th refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_revoked_build_never_prompts() {
        let mut ask = ScriptedAsk::default();
        let revoked =
            "model m: gateway: compose hash abc is revoked by the attestation policy feed";
        let (out, maps, _) = run(
            (true, true),
            true,
            &mut ask,
            vec![Err(AttestationFailure::Other(revoked.into()))],
        );
        match out {
            Err(AttestationFailure::Other(m)) => assert_eq!(m, revoked),
            other => panic!("expected the revocation, got {other:?}"),
        }
        assert!(ask.shown.is_empty());
        assert_eq!(maps.len(), 1);
    }

    #[test]
    fn nothing_is_asked_without_a_terminal() {
        for ttys in [(false, true), (true, false)] {
            let mut ask = ScriptedAsk::default();
            let (out, _, store) = run(ttys, true, &mut ask, vec![not_trusted(gw())]);
            assert!(matches!(out, Err(AttestationFailure::ComposeNotTrusted(_))));
            assert!(ask.shown.is_empty());
            assert!(store.entries.is_empty());
        }
    }

    #[test]
    fn nothing_is_asked_without_a_home() {
        let mut ask = ScriptedAsk::default();
        let (out, _, _) = run((true, true), false, &mut ask, vec![not_trusted(gw())]);
        assert!(matches!(out, Err(AttestationFailure::ComposeNotTrusted(_))));
        assert!(ask.shown.is_empty());
    }

    #[test]
    fn a_failed_save_refuses_with_the_reason() {
        let d = tempfile::tempdir().unwrap();
        // A file where the home directory should be: the save cannot write.
        let home = d.path().join("not-a-dir");
        std::fs::write(&home, b"x").unwrap();
        let mut ask = ScriptedAsk::answering(&[Some("y")]);
        let mut calls = 0;
        let out = attest_with_consent(
            NearEnvironment::Production,
            &AttestOptions::default(),
            (true, true),
            true,
            Some(&home),
            NOW,
            &mut ask,
            |_| {
                calls += 1;
                not_trusted(gw())
            },
        );
        assert_eq!(calls, 1);
        match out {
            Err(AttestationFailure::ComposeNotTrusted(nt)) => {
                assert!(nt.message.starts_with(&gw().message), "{}", nt.message);
                assert!(nt.message.len() > gw().message.len(), "{}", nt.message);
                assert_eq!(nt.hash, gw().hash);
            }
            other => panic!("expected ComposeNotTrusted, got {other:?}"),
        }
    }

    #[test]
    fn a_hostile_store_key_cannot_reach_the_terminal_in_the_warning() {
        let d = tempfile::tempdir().unwrap();
        let path = crate::install::trusted_composes_path(d.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, r#"{"version":1,"entries":[],"\u001b[2J":1}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let (_, warning) = trusted::load(Some(d.path()));
        let raw = warning.expect("an unknown key is a warning");
        assert!(
            raw.contains('\x1b'),
            "the probe still reaches serde's text: {raw:?}"
        );
        let line = store_warning_line(&raw);
        assert!(line.starts_with("[rts] ignoring "), "{line}");
        assert!(!line.contains('\x1b'), "{line:?}");
        assert!(line.contains("unknown field `[2J`"), "{line}");
        assert!(line.bytes().all(|b| (0x20..=0x7e).contains(&b)), "{line:?}");
    }

    #[test]
    fn store_text_is_printable_and_capped_at_300() {
        assert_eq!(display_store_text("a\x1b\r\nb\u{00e9}c"), "abc");
        assert_eq!(display_store_text(&"x".repeat(400)), "x".repeat(300));
    }

    fn trusted_fixture(hashes: &[&str]) -> (Attested, trusted::TrustedComposes) {
        let entries: Vec<_> = hashes
            .iter()
            .map(|h| serde_json::json!({"role": "gateway", "compose_hash": h, "compose_acceptance": "user-trusted"}))
            .collect();
        let store = trusted::TrustedComposes {
            entries: hashes
                .iter()
                .map(|h| trusted::TrustedEntry {
                    environment: NearEnvironment::Production,
                    role: Role::Gateway,
                    sha256: hash(h),
                    app_name: None,
                    trusted_at: "2026-11-20".into(),
                })
                .collect(),
        };
        let attested = Attested {
            evidence: vec![serde_json::json!({"model": "m", "entries": entries})],
            ..Attested::default()
        };
        (attested, store)
    }

    #[test]
    fn re_attestation_prints_the_trusted_lines_only_when_the_set_changes() {
        let other = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let near = NearEnvironment::Production;
        let (one, store_one) = trusted_fixture(&[GW_HASH]);
        let (two, store_two) = trusted_fixture(&[GW_HASH, other]);
        let mut printed = TrustedPrinted::default();
        let first = printed.changed_lines(&one, &store_one, near);
        assert_eq!(
            first,
            vec!["[rts] NEAR AI gateway build f4a9b480: you trusted it on 2026-11-20".to_string()]
        );
        assert!(
            printed.changed_lines(&one, &store_one, near).is_empty(),
            "same set twice prints once"
        );
        assert_eq!(
            printed.changed_lines(&two, &store_two, near).len(),
            2,
            "a changed set prints again"
        );
        assert!(printed.changed_lines(&two, &store_two, near).is_empty());
        // Seeded from the launch's attestation: the launch already printed it.
        let mut seeded = TrustedPrinted::from_attested(&one);
        assert!(seeded.changed_lines(&one, &store_one, near).is_empty());
        // Going back to none is a change, but prints nothing.
        assert!(
            seeded
                .changed_lines(&Attested::default(), &store_one, near)
                .is_empty()
        );
        assert_eq!(seeded.changed_lines(&one, &store_one, near).len(), 1);
    }

    #[test]
    fn trusted_lines_name_each_user_trusted_entry_with_its_date() {
        let store = trusted::TrustedComposes {
            entries: vec![trusted::TrustedEntry {
                environment: NearEnvironment::Production,
                role: Role::Gateway,
                sha256: hash(GW_HASH),
                app_name: None,
                trusted_at: "2026-11-20".into(),
            }],
        };
        let attested = Attested {
            evidence: vec![serde_json::json!({
                "model": "m",
                "entries": [
                    {"role": "gateway", "compose_hash": GW_HASH, "compose_acceptance": "user-trusted"},
                    {"role": "model", "index": 0, "compose_hash": GW_HASH, "compose_acceptance": "pinned"},
                ],
            })],
            ..Attested::default()
        };
        assert_eq!(
            trusted_lines(&attested, &store, NearEnvironment::Production),
            vec!["[rts] NEAR AI gateway build f4a9b480: you trusted it on 2026-11-20".to_string()]
        );
        assert!(trusted_lines(&attested, &store, NearEnvironment::Staging).is_empty());
    }
}
