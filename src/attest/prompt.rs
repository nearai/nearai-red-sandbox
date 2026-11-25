//! Asking the user, at launch, whether to trust a NEAR AI build that nothing
//! else trusts, and attesting again in full after a yes.

use std::collections::BTreeMap;
use std::path::Path;

use super::trusted::{self, TrustedComposes, TrustedEntry};
use super::{AttestOptions, AttestationFailure, Attested, ComposePolicy, NotTrusted, Role};
use crate::inference::NearEnvironment;

/// Prompts per launch, so a gateway flapping between builds cannot loop.
pub const MAX_PROMPTS: usize = 3;

/// The prompt is shown only in production, under `--compose-policy pinned`,
/// with stdin and stderr both terminals.
pub fn eligible(
    near: NearEnvironment,
    options: &AttestOptions,
    stdin_tty: bool,
    stderr_tty: bool,
) -> bool {
    near == NearEnvironment::Production
        && options.compose_policy == ComposePolicy::Pinned
        && stdin_tty
        && stderr_tty
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
fn printable(raw: &str, max: usize) -> String {
    raw.chars()
        .filter(|c| matches!(c, ' '..='~'))
        .take(max)
        .collect()
}

/// `app_name` as it may reach the terminal. No quote binds it and it also
/// comes back from the store file, so it is filtered and capped here.
fn display_app_name(raw: Option<&str>) -> String {
    let shown = raw.map(|r| printable(r, 64)).unwrap_or_default();
    if shown.is_empty() {
        "unknown".into()
    } else {
        shown
    }
}

fn short(hash: &[u8; 32]) -> String {
    hex::encode(&hash[..4])
}

pub fn prompt_text(nt: &NotTrusted) -> String {
    let (first, checked) = match nt.role {
        Role::Gateway => (
            "NEAR AI moved its production gateway to a new build.".to_string(),
            "TDX quote, TCB status, this launch's nonce, compose hash",
        ),
        Role::Model => (
            format!("NEAR AI moved {} to a new build.", nt.model),
            "TDX quote, TCB status, this launch's nonce, compose hash, GPU",
        ),
    };
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
/// trusts it. `trusted_at` comes from the store file, so it is filtered too.
pub fn trusted_line(model: &str, role: Role, hash: &[u8; 32], trusted_at: &str) -> String {
    let what = match role {
        Role::Gateway => "gateway".to_string(),
        Role::Model => model.to_string(),
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

/// Attests, and on a compose nothing trusts asks the user (when
/// [`eligible`], at most [`MAX_PROMPTS`] times, and only with a `home` to
/// save to). A yes saves the build and attests again from scratch: the
/// refusal came before the GPU verdict and before later entries were
/// checked, so only the new attestation's result is returned.
pub fn attest_with_consent(
    near: NearEnvironment,
    options: &AttestOptions,
    ttys: (bool, bool),
    home: Option<&Path>,
    now: u64,
    ask: &mut dyn Ask,
    mut attest: impl FnMut(&BTreeMap<[u8; 32], Role>) -> Result<Attested, AttestationFailure>,
) -> Result<Attested, AttestationFailure> {
    let (mut store, warning) = trusted::load(home);
    if let Some(w) = warning {
        crate::brand::progress::message(&format!("[rts] {w}"));
    }
    let mut prompts = 0;
    loop {
        match attest(&store.for_environment(near)) {
            Ok(attested) => {
                for line in trusted_lines(&attested, &store, near) {
                    crate::brand::progress::message(&line);
                }
                return Ok(attested);
            }
            Err(AttestationFailure::ComposeNotTrusted(nt)) => {
                let Some(home) = home else {
                    return Err(AttestationFailure::ComposeNotTrusted(nt));
                };
                if !eligible(near, options, ttys.0, ttys.1) || prompts >= MAX_PROMPTS {
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
        let d = tempfile::tempdir().unwrap();
        let home = with_home.then(|| d.path());
        let mut results: Results = results.into();
        let mut maps = vec![];
        let out = attest_with_consent(
            NearEnvironment::Production,
            &AttestOptions::default(),
            ttys,
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
    fn the_model_prompt_names_the_model_and_adds_gpu() {
        let text = prompt_text(&model_nt(7));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "NEAR AI moved zai-org/GLM-5 to a new build.");
        assert_eq!(lines[2], "  Build    vllm-glm");
        assert_eq!(
            lines[4],
            "  Checked  TDX quote, TCB status, this launch's nonce, compose hash, GPU"
        );
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
        assert!(eligible(NearEnvironment::Production, &pinned, true, true));
        assert!(!eligible(NearEnvironment::Production, &pinned, false, true));
        assert!(!eligible(NearEnvironment::Production, &pinned, true, false));
        assert!(!eligible(NearEnvironment::Staging, &pinned, true, true));
        assert!(!eligible(NearEnvironment::Production, &mr, true, true));
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
