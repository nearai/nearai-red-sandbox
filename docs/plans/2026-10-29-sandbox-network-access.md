# Controlled network access from the sandbox: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A session gets guest egress only to an allowlist its operator declares before launch (`network.allow` in the session config, `rts launch --allow-host`, the `packages` preset). No allowlist still means no network, and every launch proves it. Every allowed and denied flow lands in `sessions/<id>/network.jsonl`.

**Architecture:** A new `src/network.rs` parses, expands, validates and resolves the entries on the host, and refuses an `mvmctl` environment that would route egress outside `rts`'s control. Only a resolved `network::Plan` can produce `--allow-host` values (a newtype with a private field). `MvmSandbox::create` (`src/mvm.rs:304-324`) passes them to `machine create`, and for a non-empty plan replaces `machine start` with a supervised background `mvmctl machine run --name rts-<id> --ttl 30d` (the workaround for tinylabscom/mvm#4860), started through a new `Runner::attach` seam and owned by `MvmSandbox`, so `remove()` runs rm, then SIGTERM, on every path. After boot, `session_body` (`src/session.rs:616-707`) probes each entry from the guest with busybox `nc` through mvm's proxy on `127.0.0.1:1080`, or probes that `1.1.1.1:443` is unreachable when there is no allowlist. It treats the attach process exiting as `network-lost`. Teardown confirms that no endpoint or supervisor process remains and copies this VM's signed entries from mvm's audit log.

**Tech Stack:** Rust 2024 (`rts`, `cargo test`), std only for networking (`ToSocketAddrs`, `IpAddr`), `serde`/`serde_json` (already direct), mvm v0.22.0 `mvmctl` on HVF, busybox `nc` in the guest. The opencode plugin is unchanged: it passes `bridge` through as is (`plugin/index.ts:35-37,65-80`).

**Spec:** `docs/specs/2026-10-29-sandbox-network-access-design.md` (approved 2026-10-29), all sections. Its research records are `docs/research/2026-10-29-mvm-v0.22.0-egress.md`, `docs/research/2026-10-29-mvm-egress-spike-hvf.md` and `docs/research/2026-10-29-mvm-attached-run-spike.md`. Read the spec first; this plan does not restate its rationale.

## Global Constraints

- **Start after `release-installers` merges.** That branch changes `src/config.rs`, `src/session.rs` and `src/main.rs`, and adds `src/install.rs` and `src/setup.rs`. Before Task 1, rebase `sandbox-network` onto the `nearai/main` that contains it, then re-check every `file:line` cited below against the rebased code. Lines may move, but the cited items must still exist. If one no longer exists, stop and report.
- Every cargo command uses `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0`. Below, `T` stands for `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo test`.
- Baseline. Measured 2026-10-29 on this branch after merging `nearai/main` `54436c2`, before `release-installers`: `T --lib` reports `test result: FAILED. 246 passed; 5 failed; 1 ignored`. The five failures are pre-existing and out of scope: `copy::tests::a_long_name_is_refused`, `copy::tests::a_symlink_to_a_host_path_is_refused`, `copy::tests::a_hardlink_is_refused`, `copy::tests::copy_out_is_byte_exact_across_slices` and `copy::tests::an_oversized_file_is_refused`. After the rebase, re-run `T --lib` and paste the summary line. The pass count will change, but the failures must be exactly these five; if they are not, stop and report. After every task, `T --lib` shows these five failures and no others, with more passes than before. Never report "tests pass" from a filtered run. `bun test tests/unit` must still pass in full.
- **No new crates.** Nothing in `Cargo.toml` changes. If a task seems to need a crate (`toml`, `ipnet`, `nix`, `libc`), stop and ask.
- **Fail closed.** Every check returns `Err` and the caller refuses or ends the session. Nothing logs and continues, except two reports at teardown: a failed audit copy and a lingering process. Both are logged loudly, and neither stops the export of `/out` or the VM removal. No failure falls back to wider access.
- **Never** pass `--net`, `--peer`, `--gpu`, `--grants-file` or `--policy` to `mvmctl`. `--allow-host` appears only on `machine create`, once per entry of a resolved `Plan`.
- **The attach log.** `sessions/<id>/mvm-attach.log` is mode 0600. It holds the attach process's stdout and stderr, which echo every exec's argv including base64 file chunks. Its contents never reach the operator's terminal, `launcher.log` or an error string. Errors name the file instead.
- Values copied from the spec and from mvm v0.22.0:
  - preset `packages`, all on port 443: `dl-cdn.alpinelinux.org`, `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`, `index.crates.io`, `static.crates.io`, `crates.io`;
  - the default port is 443. Ports 0, 22 and anything above 65535 are refused;
  - at most 64 entries after expansion (counted after deduplication);
  - refused ranges: loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), metadata (`169.254.169.254`, `fd00:ec2::254`), unspecified (`0.0.0.0/8`, `::`), multicast (`224.0.0.0/4`, `ff00::/8`) and `100.64.0.0/10`. An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is judged by its IPv4 address;
  - the deny-all probe target is `1.1.1.1:443`;
  - each entry is probed once with a 10-second timeout;
  - the guest proxy is `127.0.0.1:1080`. The proxy environment set for tool execs is `HTTPS_PROXY=http://127.0.0.1:1080`, `HTTP_PROXY=http://127.0.0.1:1080`, `ALL_PROXY=socks5h://127.0.0.1:1080` and `NO_PROXY=localhost,127.0.0.1,::1`, plus the same four in lower case (mvm's `guest_netd.rs:102-123`, per the research notes);
  - the attach command is `machine run --name <name> --ttl <limits.sessionHours>h` (Task 9a; the plan first fixed it at `30d`): no `--image`, no argv, no `-d`. `30d` is mvm's `MAX_TTL`, which is inclusive (`ttl.rs:16,72` at v0.22.0, which accepts the suffixes s/m/h/d);
  - the audit source is `<mvm root>/audit/local.jsonl` plus `local.seg-*.jsonl`. Kept events are those with prefix `host.flow.`, `dns.`, `icmp.` or `host.route.` and an exact `entry.labels.vm_name`;
  - the startup lines (logged through `Logger::log`, `src/session.rs:472-478`, so on the terminal they carry its usual `[rts <id>] ` prefix) are `network: N hosts allowed (<entries as written>); TCP only; every connection is logged` (`1 host` when N is 1) and `network: none`.
- The mvm root is `MVM_HOME`, or else `HOME/.mvm`, with an empty value treated as unset, exactly as in `supervisor_pid_file` (`src/session.rs:382-387`). Task 3 extracts that logic as `session::mvm_root`.
- Containment tests (`tests/contain/`) run real mvm, one at a time (`--test-threads=1`, which also covers the spec's one-start-at-a-time rule). Every test owns its machines through `harness::Machine`, whose `Drop` calls `remove()`, and `remove()` also stops the attach process. A test that fails mid-way still cleans up. After the suite, `mvmctl machine ps` lists no `rts-` machine and `ps -ax | grep -E 'mvm-(network-endpoint|hvf-supervisor)'` shows none started by the suite.
- Commit style: short imperative subject, no `feat:` prefixes, no emojis, ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push.

## Review Focus

1. **Entries that look harmless but reach the host.** `localhost`, `127.0.0.1:8463`, `[::ffff:127.0.0.1]:443`, `[::1]:443`, `169.254.169.254:80`, `[fd00:ec2::254]:80`, `100.64.0.1:443`, a bare unbracketed IPv6 address, ports `22`/`0`/`65536`, and a name that resolves only to loopback. Each is refused before any `machine` command. Tests in Task 1 (syntax and ranges) and Task 2 (`localhost` through the resolver).
2. **The proxy variables mvm actually reads.** mvm takes `https_proxy`/`HTTPS_PROXY`, `http_proxy`/`HTTP_PROXY` and `all_proxy`/`ALL_PROXY` from its own environment (`network_endpoint_spawn.rs:871-875` at v0.22.0). `SpawnRunner` does not clear the environment (`src/mvm.rs:84-88`), so any of the six set in the operator's shell would carry allowed traffic out through that proxy. Every launch refuses, including a launch with no allowlist. Test in Task 3.
3. **`--allow-host` is repeatable.** `parse_args` refuses a repeated flag through `seen` (`src/main.rs:43,66-68`). `--allow-host` must be exempt from that check. `--no-network` empties the config's entries, and combining it with `--allow-host` is refused. Test in Task 4.
4. **The deny-all probe cannot pass by accident.** If `nc` is missing or the probe output is anything other than the exact marker, the session is refused. A guest without `nc` must never read as "unreachable". Test in Task 7.
5. **A dead attach process is a dead session.** If `mvmctl machine run` exits at any point, whether before boot (retried once), during the plugin handshake or mid-session, the session ends with `network-lost`. `/out` is exported, the VM is removed, and the attach process gets SIGTERM after rm. Tests in Task 5 (sandbox level), Task 9 (before opencode starts, and during the handshake) and Task 10 (mid-session, through the real launcher).

---

### Task 1: Parse, expand and validate allowlist entries

**Files:**
- Create: `src/network.rs`
- Modify: `src/lib.rs` (`pub mod network;`)
- Test: `src/network.rs` unit tests

**Interfaces:**
- Consumes: nothing. This is pure code.
- Produces:
  - `pub const PRESET_PACKAGES: &[&str]` (the seven hosts), `pub const MAX_ENTRIES: usize = 64;`, `pub const DEFAULT_PORT: u16 = 443;`
  - `#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)] pub enum Host { Name(String), Ip(std::net::IpAddr) }`
  - `#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)] pub struct Entry { pub host: Host, pub port: u16 }`
  - `impl Entry { pub fn display(&self) -> String }` gives `name:port`, `a.b.c.d:port` or `[v6]:port`
  - `pub fn expand(written: &[String]) -> Result<Vec<Entry>, String>`
  - `pub fn refused_range(ip: std::net::IpAddr) -> Option<&'static str>` returns the range name (`"loopback"`, `"link-local"`, `"cloud metadata"`, `"unspecified"`, `"multicast"`, `"100.64.0.0/10"`)

Decisions:
- An entry is the preset name (`packages`), a host name with an optional port, or an IP address with a port. IPv4 is written `a.b.c.d:port` and IPv6 `[addr]:port`. An IP literal with no port is refused, because the spec's syntax gives IPs a port. A bare unbracketed IPv6 address is refused.
- Host names are lowercased and must be 1-253 characters made of labels of 1-63 `[a-z0-9-]` characters, not starting or ending with `-`. Entries with wildcards, underscores, a trailing dot, a URL scheme or a path are refused. A preset name takes precedence over a host of the same name.
- Ports are parsed as `u32`, then 0, 22 and anything above 65535 are refused.
- Deduplicate on `Entry`, keeping first-seen order. Then refuse more than `MAX_ENTRIES`.
- Every error names the entry as written and the reason, e.g. `network entry "127.0.0.1:8463": loopback addresses are always refused`.

- [ ] **Step 1: Write the failing tests.**

```rust
#[test]
fn presets_expand_and_duplicates_collapse_in_order() {
    let e = expand(&s(&["packages", "pypi.org", "api.example-target.com", "PyPI.org:443"])).unwrap();
    let shown: Vec<String> = e.iter().map(Entry::display).collect();
    let mut want: Vec<String> = PRESET_PACKAGES.iter().map(|h| format!("{h}:443")).collect();
    want.push("api.example-target.com:443".into());
    assert_eq!(shown, want);
}

#[test]
fn hosts_ips_and_ports_parse() {
    let e = expand(&s(&["a.example:8443", "198.51.100.7:8443", "[2001:db8::7]:443", "192.168.1.20:8080"])).unwrap();
    assert_eq!(e[0], Entry { host: Host::Name("a.example".into()), port: 8443 });
    assert_eq!(e[2].display(), "[2001:db8::7]:443");
    assert_eq!(e[3].host, Host::Ip("192.168.1.20".parse().unwrap()));
}

#[test]
fn each_refusal_names_the_entry_and_the_reason() {
    for (entry, why) in [
        ("a.example:22", "port 22"), ("a.example:0", "port"), ("a.example:65536", "port"),
        ("127.0.0.1:8463", "loopback"), ("[::1]:443", "loopback"), ("[::ffff:127.0.0.1]:443", "loopback"),
        ("169.254.169.254:80", "metadata"), ("[fd00:ec2::254]:80", "metadata"), ("169.254.1.1:80", "link-local"),
        ("[fe80::1]:443", "link-local"), ("0.0.0.0:443", "unspecified"), ("[::]:443", "unspecified"),
        ("224.0.0.1:443", "multicast"), ("[ff02::1]:443", "multicast"), ("100.64.0.1:443", "100.64.0.0/10"),
        ("198.51.100.7", "port"), ("2001:db8::7", "bracket"), ("*.example.com", "host name"),
        ("https://a.example", "host name"), ("a.example.", "host name"), ("under_score.example", "host name"), ("", "empty"),
    ] {
        let e = expand(&s(&[entry])).unwrap_err();
        assert!(e.contains(&format!("{entry:?}")) && e.to_lowercase().contains(why), "{entry}: {e}");
    }
}

#[test]
fn more_than_64_entries_after_expansion_is_refused() {
    let at_cap: Vec<String> = (0..57).map(|i| format!("h{i}.example")).chain(["packages".into()]).collect();
    assert_eq!(expand(&at_cap).unwrap().len(), 64);
    let over: Vec<String> = at_cap.iter().cloned().chain(["one-more.example".into()]).collect();
    assert!(expand(&over).unwrap_err().contains("64"));
}
```

(`s` is a test helper, `fn s(v: &[&str]) -> Vec<String>`.)

- [ ] **Step 2: Run, expect FAIL.** `T --lib network::tests` fails to compile (`unresolved import` / `cannot find function expand`).
- [ ] **Step 3: Implement** `src/network.rs` as decided above, with `pub mod network;` in `src/lib.rs`. `refused_range` converts an IPv4-mapped IPv6 address with `to_ipv4_mapped()` before it checks.
- [ ] **Step 4: Run, expect PASS.** `T --lib` shows the baseline's five failures only, with 4 more passes.
- [ ] **Step 5: Commit.** `git add src/network.rs src/lib.rs && git commit -m "Parse and validate sandbox network allowlist entries"`

---

### Task 2: Resolve on the host, the plan, and the startup line

**Files:**
- Modify: `src/network.rs`
- Test: `src/network.rs` unit tests

**Interfaces:**
- Consumes: `expand`, `refused_range` (Task 1).
- Produces:
  - `pub trait Resolver: Send + Sync { fn resolve(&self, name: &str) -> std::io::Result<Vec<std::net::IpAddr>>; }`
  - `pub struct SystemResolver;`, which implements `Resolver` with `(name, 443).to_socket_addrs()`, deduplicated
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct AllowHost(String);` with a private field, and `impl AllowHost { pub fn as_str(&self) -> &str }`
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct Plan { written: Vec<String>, entries: Vec<Entry>, resolved: std::collections::BTreeMap<String, Vec<std::net::IpAddr>> }` with private fields
  - `pub fn plan(written: &[String], resolver: &dyn Resolver) -> Result<Plan, String>`
  - `impl Plan { pub fn is_empty(&self) -> bool; pub fn entries(&self) -> &[Entry]; pub fn allow_hosts(&self) -> Vec<AllowHost>; pub fn startup_line(&self) -> String; pub fn record(&self, probes: &[Probe]) -> serde_json::Value }`
  - `#[derive(Debug, Clone, PartialEq, Eq)] pub struct Probe { pub target: String, pub result: String }`. It is defined here so that `record` compiles; Task 7 produces values of it.

Decisions:
- `plan` calls `expand`, then resolves every `Host::Name` once. A resolver error, or an empty answer, refuses with `network entry "<as written>": <name> does not resolve on this host (<error>)`. A name whose addresses all fall in `refused_range` refuses, naming the first range. Mixed answers are kept, because mvm refuses the restricted ones itself.
- `AllowHost` strings: a name gives `name:port`, IPv4 gives `a.b.c.d:port`, and IPv6 gives `addr:port` **without brackets**. mvm v0.22.0's `HostPort::from_str` splits at the last `:` and keeps the host verbatim (`crates/mvm-contract/src/policy/network_policy.rs:68-83`), so a bracketed host would fail to pin and silently turn the whole gate into deny-all (`egress_gate.rs:310-332`).
- `startup_line()`: `network: none` for an empty plan. Otherwise `network: {n} host{s} allowed ({written joined by ", "}); TCP only; every connection is logged`, where `n` counts the expanded entries.
- `record(probes)` is `{"allow": [written], "expanded": [display()], "resolved": {name: [ip strings]}, "probes": [{"target", "result"}]}`.

- [ ] **Step 1: Write the failing tests.** Use a `struct FakeResolver(HashMap<&'static str, io::Result<Vec<IpAddr>>>)`. The test helper clones the results, building errors by `kind`.

```rust
#[test]
fn a_name_that_does_not_resolve_refuses_the_session() {
    let e = plan(&s(&["nowhere.example"]), &fake(&[("nowhere.example", Err(io::ErrorKind::NotFound))])).unwrap_err();
    assert!(e.contains("\"nowhere.example\"") && e.contains("does not resolve"), "{e}");
    let e = plan(&s(&["empty.example"]), &fake(&[("empty.example", Ok(vec![]))])).unwrap_err();
    assert!(e.contains("does not resolve"), "{e}");
}

#[test]
fn a_name_resolving_only_to_refused_ranges_is_refused() {
    for (name, ip, why) in [("localhost", "127.0.0.1", "loopback"), ("meta.example", "169.254.169.254", "metadata"), ("cgnat.example", "100.64.3.4", "100.64.0.0/10")] {
        let e = plan(&s(&[name]), &fake(&[(name, Ok(vec![ip.parse().unwrap()]))])).unwrap_err();
        assert!(e.contains(why), "{name}: {e}");
    }
    let mixed = plan(&s(&["mixed.example"]), &fake(&[("mixed.example", Ok(vec!["127.0.0.1".parse().unwrap(), "198.51.100.9".parse().unwrap()]))])).unwrap();
    assert_eq!(mixed.entries().len(), 1);
}

#[test]
fn allow_hosts_render_for_mvm_and_ipv6_is_unbracketed() {
    let p = plan(&s(&["a.example", "198.51.100.7:8443", "[2001:db8::7]:443"]), &fake(&[("a.example", Ok(vec!["198.51.100.1".parse().unwrap()]))])).unwrap();
    let v: Vec<String> = p.allow_hosts().iter().map(|a| a.as_str().to_string()).collect();
    assert_eq!(v, ["a.example:443", "198.51.100.7:8443", "2001:db8::7:443"]);
}

#[test]
fn the_startup_line_for_none_one_and_many() {
    let r = fake(&[("api.example-target.com", Ok(vec!["198.51.100.2".parse().unwrap()]))]);
    assert_eq!(plan(&[], &r).unwrap().startup_line(), "network: none");
    assert_eq!(plan(&s(&["198.51.100.7:8443"]), &r).unwrap().startup_line(), "network: 1 host allowed (198.51.100.7:8443); TCP only; every connection is logged");
    // `packages` names resolve through the fake too: give each of the seven an address.
    let many = plan(&s(&["packages", "api.example-target.com", "198.51.100.7:8443", "192.168.1.20:8080"]), &with_packages(r)).unwrap();
    assert_eq!(many.startup_line(), "network: 10 hosts allowed (packages, api.example-target.com, 198.51.100.7:8443, 192.168.1.20:8080); TCP only; every connection is logged");
}

#[test]
fn the_record_carries_written_expanded_resolved_and_probes() {
    let p = plan(&s(&["a.example"]), &fake(&[("a.example", Ok(vec!["198.51.100.1".parse().unwrap()]))])).unwrap();
    let r = p.record(&[Probe { target: "a.example:443".into(), result: "connected".into() }]);
    assert_eq!(r, serde_json::json!({"allow": ["a.example"], "expanded": ["a.example:443"], "resolved": {"a.example": ["198.51.100.1"]}, "probes": [{"target": "a.example:443", "result": "connected"}]}));
}
```

- [ ] **Step 2: Run, expect FAIL.** `T --lib network::tests` fails to compile (`cannot find function plan`).
- [ ] **Step 3: Implement** as decided.
- [ ] **Step 4: Run, expect PASS.** `T --lib` shows the five baseline failures only.
- [ ] **Step 5: Commit.** `git add src/network.rs && git commit -m "Resolve allowlisted hosts on the host before launch"`

---

### Task 3: Refuse mvm host settings that grant egress outside rts

**Files:**
- Modify: `src/network.rs`, `src/session.rs` (extract `mvm_root` from `supervisor_pid_file`, `src/session.rs:382-387`)
- Test: `src/network.rs`, `src/session.rs` unit tests

**Interfaces:**
- Consumes: the operator environment `Deps.env` (`src/session.rs:433`).
- Produces:
  - `pub fn mvm_root(env: &[(String, String)]) -> Result<std::path::PathBuf, String>` in `src/session.rs`. `supervisor_pid_file` now calls it and its message stays the same.
  - `pub const PROXY_VARS: [&str; 6] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"];`
  - `pub fn check_mvm_host(env: &[(String, String)], mvm_root: &std::path::Path) -> Result<(), String>`

Decisions:
- Refuse when any of `PROXY_VARS` is present in `env`, even if empty, naming the variable and saying that mvm would route allowed guest traffic through it. This widens the spec, which names `HTTPS_PROXY` and `HTTP_PROXY`, to the six names mvm reads.
- Host config: in v0.22.0, `MvmConfig::default_grants()` hard-codes `egress: None` (`crates/mvm-core/src/user_config.rs:187-200`), so today's host config cannot grant egress. As a guard against a future mvm that can, read `<mvm root>/config/config.toml` when it exists. Refuse if any non-comment line mentions `egress` (case-insensitive), or if the file exists but cannot be read. A missing file passes, because mvm then writes its defaults. This is a line scan, since no `toml` crate is allowed.
- Every launch runs this, with or without an allowlist (Task 9).

- [ ] **Step 1: Write the failing tests.**

```rust
#[test]
fn any_proxy_variable_mvm_reads_refuses_every_launch() {
    let root = crate::testutil::tempdir("mvmroot");
    for var in PROXY_VARS {
        let e = check_mvm_host(&[(var.into(), String::new())], &root).unwrap_err();
        assert!(e.contains(var), "{e}");
    }
    assert!(check_mvm_host(&[("NO_PROXY".into(), "x".into()), ("HOME".into(), "/h".into())], &root).is_ok());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_host_config_mentioning_egress_or_unreadable_refuses() {
    let root = crate::testutil::tempdir("mvmroot");
    std::fs::create_dir_all(root.join("config")).unwrap();
    let cfg = root.join("config/config.toml");
    std::fs::write(&cfg, "dev_vm_cpus = 8\ndefault_cpus = 2\ntrusted_plan_signers = []\n# egress in a comment is fine\n[tenant]\nname = \"\"\n").unwrap();
    assert!(check_mvm_host(&[], &root).is_ok());
    std::fs::write(&cfg, "[default_grants.egress]\nallow = []\n").unwrap();
    assert!(check_mvm_host(&[], &root).unwrap_err().contains("config.toml"));
    std::fs::remove_file(&cfg).unwrap();
    std::fs::create_dir(&cfg).unwrap(); // exists, unreadable as a file
    assert!(check_mvm_host(&[], &root).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
```

In `src/session.rs`, add `mvm_root_prefers_mvm_home_and_ignores_empty_values`: `MVM_HOME=""` with `HOME=/h` gives `/h/.mvm`, `MVM_HOME=/m` gives `/m`, and neither set is an error.

- [ ] **Step 2: Run, expect FAIL.** It fails to compile (`check_mvm_host`, `mvm_root` not found).
- [ ] **Step 3: Implement.** Keep `rss_monitor_uses_the_vm_pid_file_and_refuses_lost_or_over_limit_samples` (`src/session.rs:1136`) green unchanged.
- [ ] **Step 4: Run, expect PASS.** `T --lib` shows the five baseline failures only.
- [ ] **Step 5: Commit.** `git add src/network.rs src/session.rs && git commit -m "Refuse proxy and host-config egress outside rts control"`

---

### Task 4: Config `network.allow`, `--allow-host` and `--no-network`

**Files:**
- Modify: `src/config.rs` (`Raw`, `src/config.rs:106-119`; `OperatorConfig`, `:68-81`; `parse_config`, `:233-322`)
- Modify: `src/main.rs` (`Action::Launch`, `:19-23`; `parse_args`, `:26-124`; `USAGE`, `:143`; `check_launch`, `:187-202`; `launch`, `:251-340`; the dispatch at `:357-361`)
- Test: `src/config.rs`, `src/main.rs` unit tests

**Interfaces:**
- Consumes: `network::expand` (Task 1).
- Produces:
  - `OperatorConfig.network: Vec<String>`, the entries as written, after flags are merged
  - `#[derive(Deserialize, Default)] #[serde(deny_unknown_fields)] struct RawNetwork { allow: Option<Vec<String>> }`, as `#[serde(default)] network: RawNetwork` on `Raw`
  - `#[derive(Debug, Default, Clone, PartialEq, Eq)] struct NetworkFlags { allow: Vec<String>, none: bool }` in `src/main.rs`, as `Action::Launch { network: NetworkFlags, .. }`
  - `fn apply_network(cfg: &mut config::OperatorConfig, flags: &NetworkFlags)`
  - `check_launch` additionally runs `rts::network::expand(&cfg.network)` before credentials, so a bad entry from either source fails before sign-in

Decisions:
- `parse_config` validates `network.allow` with `network::expand` and prefixes errors with `config: network.allow: `. An unknown key under `network` is refused by `deny_unknown_fields`.
- `--allow-host VALUE` is launch-only and repeatable: it is not inserted into `seen`. Its value goes through the existing non-empty, not-starting-with-`-` filter (`src/main.rs:77-81`). `--no-network` is a launch-only boolean, and a repeat of it is a duplicate as before. If both flags appear, `parse_args` returns `Err("--no-network cannot be combined with --allow-host")`.
- `apply_network`: `none` clears `cfg.network`. Otherwise the flag entries are appended after the config's entries. `launch` calls it before `check_launch`.
- `USAGE` gains `[--allow-host ENTRY]... [--no-network]` and three one-line examples, worded as in Task 11.

- [ ] **Step 1: Write the failing tests.**

```rust
// src/config.rs
#[test]
fn network_allow_is_read_validated_and_defaults_to_none() {
    assert!(parse("{}").unwrap().network.is_empty());
    let c = parse(r#"{ "network": { "allow": ["packages", "192.168.1.20:8080"] } }"#).unwrap();
    assert_eq!(c.network, ["packages", "192.168.1.20:8080"]);
    assert!(parse(r#"{ "network": { "allow": ["127.0.0.1:8463"] } }"#).unwrap_err().starts_with("config: network.allow: "));
    assert!(parse(r#"{ "network": { "allow": [], "peer": [] } }"#).is_err());
}

// src/main.rs
#[test]
fn allow_host_repeats_and_no_network_conflicts() {
    let Action::Launch { network, .. } = parse_args(&["launch", "--allow-host", "packages", "--allow-host", "a.example:8443"]).unwrap() else { panic!() };
    assert_eq!(network, NetworkFlags { allow: vec!["packages".into(), "a.example:8443".into()], none: false });
    let Action::Launch { network, .. } = parse_args(&["launch", "--no-network"]).unwrap() else { panic!() };
    assert!(network.none);
    assert!(parse_args(&["launch", "--no-network", "--allow-host", "a.example"]).unwrap_err().contains("--no-network"));
    assert!(parse_args(&["launch", "--allow-host"]).unwrap_err().contains("needs a value"));
    assert!(parse_args(&["login", "--allow-host", "a.example"]).is_err());
    assert!(parse_args(&["launch", "--no-network", "--no-network"]).unwrap_err().contains("Duplicate"));
}

#[test]
fn flags_merge_with_the_config_and_bad_entries_stop_before_credentials() {
    let mut cfg = real_models();
    cfg.network = vec!["packages".into()];
    apply_network(&mut cfg, &NetworkFlags { allow: vec!["a.example".into()], none: false });
    assert_eq!(cfg.network, ["packages", "a.example"]);
    apply_network(&mut cfg, &NetworkFlags { allow: vec![], none: true });
    assert!(cfg.network.is_empty());
    cfg.network = vec!["a.example:22".into()];
    assert!(check_launch(&cfg, &[], &rts::attest::AttestOptions::default()).unwrap_err().contains("port 22"));
}
```

Extend `malformed_arguments_fail_before_config_or_credentials_are_touched` (`src/main.rs:764`) with `["launch", "--allow-host", "--no-network"]` (a value that starts with `-`).

- [ ] **Step 2: Run, expect FAIL.** It fails to compile (no field `network`, no `NetworkFlags`).
- [ ] **Step 3: Implement** as decided. Update every `Action::Launch { .. }` pattern in `src/main.rs` tests that names all fields.
- [ ] **Step 4: Run, expect PASS.** `T --lib` shows the five baseline failures only, and `T --bin rts` passes.
- [ ] **Step 5: Commit.** `git add src/config.rs src/main.rs && git commit -m "Read the network allowlist from config and launch flags"`

---

### Task 5: `machine create --allow-host` and the supervised attached start

**Files:**
- Modify: `src/sandbox.rs` (`CreateSpec`, `:77-82`)
- Modify: `src/mvm.rs` (`Runner`, `:34-42`; `SpawnRunner`, `:77-89`; `MvmSandbox`, `:193-254`; `create`, `:304-324`; `remove`, `:335-348`; `FORBIDDEN` and the create test, `:390-409`)
- Modify: the `CreateSpec` literals at `src/session.rs:636` and `tests/contain/harness.rs:117`, and the four in `src/mvm.rs` tests (`egress: None`)
- Test: `src/mvm.rs` unit tests

**Interfaces:**
- Consumes: `network::AllowHost` (Task 2).
- Produces:
  - `pub struct Egress<'a> { pub allow_hosts: &'a [crate::network::AllowHost], pub attach_log: &'a std::path::Path }` in `src/sandbox.rs`, and `pub egress: Option<Egress<'a>>` on `CreateSpec`
  - `pub const ATTACH_TTL: &str = "30d";` in `src/mvm.rs`
  - `pub trait Attached: Send { fn pid(&self) -> u32; fn exited(&mut self) -> Option<String>; fn terminate(&mut self, grace: Duration); }`
  - on `Runner`: `fn attach(&self, argv: &[String], log: &Path) -> io::Result<Box<dyn Attached>>`, with a default that returns `Err(io::ErrorKind::Unsupported)` so that the existing fakes (`src/mvm.rs:367`, `src/session.rs:846`, `src/main.rs:608`, `tests/contain/harness.rs`) still compile. The `Arc<R>` impl (`src/mvm.rs:38-42`) forwards it.
  - `impl Runner for SpawnRunner`: `attach` opens `log` with `create(true).append(true).mode(0o600)`, then `set_permissions(0o600)` in case the file already existed. It runs mvmctl with the same environment as `run` (`extra_env` plus `GIT_CONFIG_GLOBAL`), stdin `/dev/null`, stdout and stderr to the log file, and `process_group(0)`, so the operator's Ctrl-C never reaches it. `terminate` sends SIGTERM to the process group, waits up to `grace`, then sends SIGKILL to the group and reaps.
  - on `MvmSandbox`: `pub fn attach_pid(&self) -> Option<u32>`; and `pub fn network_lost(&self) -> Option<String>`, which returns `Some("network-lost: mvmctl machine run exited (<status>)")` once a held attach process has exited

Decisions:
- `create` with `egress: Some(e)` refuses an empty `allow_hosts`. It runs `machine create <name> --image <img> --profile dev --cpus <c> --memory <m>M`, then `--allow-host <as_str>` for each entry, and nothing else. It then calls `attach(["machine", "run", "--name", name, "--ttl", ATTACH_TTL], e.attach_log)`. It waits until `machine ps` shows a line whose first field is the name and which contains `running`, polling every 500 ms for up to `CONTROL_TIMEOUT`. If the attach process exits before that, it starts again exactly once, appending to the same log. A second exit, or the timeout, returns `Err("machine run exited before boot (see <log path>)")`. The error never includes log contents. Once booted, the handle is kept in `attach: Mutex<Option<Box<dyn Attached>>>`. With `egress: None`, `create` is unchanged and runs `machine start`.
- `remove` keeps its order and adds a step: mark unavailable, `machine rm --force --yes`, **then** `terminate(Duration::from_secs(5))` on the held attach (`rm` does not stop it), then the `machine ps` check. Confirming that the endpoint and supervisor processes are gone needs the `Host` seam and the pids, so Task 9 does it in `Live::teardown`.
- `FORBIDDEN` becomes `["--net", "--peer", "--gpu", "--grants-file", "--policy"]`. The no-network test also asserts that no `--allow-host` appears.

- [ ] **Step 1: Write the failing tests.** Add a `FakeAttached { pid: u32, exits: Arc<AtomicUsize>, terminated: Arc<AtomicBool> }`, with `exited()` reading a shared flag, and give the test `Fake` an `attach` that records the argv and log path and returns one. To get `AllowHost` values, call `network::plan` with a fake resolver from a `#[cfg(test)] pub(crate)` helper in `network.rs`, `fn test_allow_hosts(entries: &[&str]) -> Vec<AllowHost>`, which skips resolution for IP literals.

```rust
#[test]
fn create_with_egress_passes_each_allow_host_and_attaches_instead_of_start() {
    let hosts = crate::network::test_allow_hosts(&["198.51.100.7:443", "198.51.100.8:8443"]);
    let (f, calls, attached) = fake_with_attach(|a| if a[1] == "ps" { out(0, &format!("NAME STATUS\n{NAME} running\n"), "") } else { out(0, "", "") });
    let sb = MvmSandbox::new(NAME, f).unwrap();
    let log = Path::new("/s/mvm-attach.log");
    sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2, egress: Some(Egress { allow_hosts: &hosts, attach_log: log }) }).unwrap();
    assert_eq!(argvs(&calls)[0], sv(&["machine", "create", NAME, "--image", IMAGE, "--profile", "dev", "--cpus", "2", "--memory", "2048M", "--allow-host", "198.51.100.7:443", "--allow-host", "198.51.100.8:8443"]));
    assert!(!argvs(&calls).iter().any(|a| a.get(1).map(String::as_str) == Some("start")));
    assert_eq!(attached.lock().unwrap().clone(), vec![(sv(&["machine", "run", "--name", NAME, "--ttl", "30d"]), log.to_path_buf())]);
    for a in argvs(&calls).iter().chain(attached.lock().unwrap().iter().map(|(a, _)| a)) {
        for flag in FORBIDDEN { assert!(!a.contains(&flag.to_string()), "{a:?}"); }
    }
}

#[test]
fn an_attach_that_exits_before_boot_is_retried_once_then_refused() { /* ps never shows running; each FakeAttached exits at once: two attach calls, then Err containing "before boot" and the log path, and not the log text */ }

#[test]
fn a_dead_attach_is_network_lost_and_remove_terminates_it_after_rm() {
    // Boot normally; flip the FakeAttached's exited flag.
    // sb.network_lost() is Some, starts with "network-lost:".
    // sb.remove(): the recorded order is machine rm, then terminate, then machine ps.
}

#[test]
fn spawn_runner_attach_writes_both_streams_to_a_0600_log_in_its_own_group() {
    let d = crate::testutil::tempdir("attach");
    let log = d.join("mvm-attach.log");
    let r = SpawnRunner { mvmctl: "/bin/sh".into(), empty_git_config: "/dev/null".into(), extra_env: HashMap::new() };
    let mut a = r.attach(&sv(&["-c", "echo out; echo err >&2; sleep 30"]), &log).unwrap();
    // poll up to 2 s for both lines in the log; `ps -o pgid= -p <pid>` equals the pid
    assert_eq!(std::fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
    a.terminate(Duration::from_secs(2));
    assert!(a.exited().is_some());
    std::fs::remove_dir_all(d).unwrap();
}
```

Keep `create_issues_exact_lines_and_no_network_flag` (`src/mvm.rs:393`) with `egress: None`, and add the assertion that it contains no `--allow-host`.

- [ ] **Step 2: Run, expect FAIL.** `T --lib mvm::tests` fails to compile (no field `egress`, no `attach`).
- [ ] **Step 3: Implement** as decided. `ps_status`-style parsing sits beside `ps_names` (`src/mvm.rs:133-135`).
- [ ] **Step 4: Run, expect PASS.** `T --lib` shows the five baseline failures only, and `T --test contain --no-run` compiles.
- [ ] **Step 5: Commit.** `git add src/sandbox.rs src/mvm.rs src/network.rs src/session.rs tests/contain/harness.rs && git commit -m "Start network machines under a supervised attached run"`

---

### Task 6: Proxy environment for tool calls in network sessions

**Files:**
- Modify: `src/network.rs` (`proxy_env`)
- Modify: `src/bridge.rs` (`BridgeOptions`, `:33-46`; `call`, `:89-104`)
- Modify: `src/tools.rs` (`ToolLimits`, `:16-24`; `shell`, `:115-131`; `lim()`, `:310-311`)
- Modify: `src/session.rs` (`plugin_options`, `:595-614`)
- Test: `src/tools.rs`, `src/bridge.rs`, `src/session.rs` unit tests

**Interfaces:**
- Produces:
  - `pub fn proxy_env() -> Vec<String>`, the eight `KEY=value` strings from Global Constraints, upper case first
  - `BridgeOptions.proxy: bool` (`#[serde(default)]`), emitted by `plugin_options` as `"proxy": true` only when `!cfg.network.is_empty()`. Otherwise the key is absent, so today's bridge JSON is unchanged.
  - `ToolLimits.proxy: bool`

Decisions:
- `machine exec` gets none of mvm's proxy environment (spec blocker 3). When `proxy` is set, `shell` runs `env <proxy_env()...> sh -c <command>` instead of `sh -c <command>`. The wrapper (`src/protocol.rs:44-57`) is unchanged, so argv positions such as the nonce at `a[8]` stay where they are. Only `shell` changes, because the file tools make no network calls.

- [ ] **Step 1: Write the failing tests.** In `src/tools.rs`, `shell_in_a_network_session_runs_under_the_proxy_env`: with `Recorder` and `ToolLimits { proxy: true, ..lim() }`, the recorded argv is `["env", "HTTPS_PROXY=http://127.0.0.1:1080", …, "no_proxy=localhost,127.0.0.1,::1", "sh", "-c", "pip download six"]`. With `proxy: false` it stays `["sh", "-c", …]`. In `src/bridge.rs`, `proxy_defaults_to_false_and_parses_when_set`. In `src/session.rs`, extend `plugin_options_carry_the_exact_model_allowlist` (`:718`) to check that `o["bridge"].get("proxy")` is `None` there and `Some(true)` with `cfg.network = vec!["a.example".into()]`.
- [ ] **Step 2: Run, expect FAIL.** It fails to compile (no field `proxy`).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** `T --lib` shows the five baseline failures only, and `bun test tests/unit` passes.
- [ ] **Step 5: Commit.** `git add src/network.rs src/bridge.rs src/tools.rs src/session.rs && git commit -m "Give sandboxed shell calls the guest proxy in network sessions"`

---

### Task 7: Post-boot probes

**Files:**
- Modify: `src/network.rs`
- Test: `src/network.rs` unit tests (with `crate::testutil::Recorder`, `src/testutil.rs:32-55`, and `run_wrapped_locally` for the script text)

**Interfaces:**
- Consumes: `crate::sandbox::Exec`, `Plan` (Task 2).
- Produces:
  - `pub const DENY_ALL_TARGET: &str = "1.1.1.1:443";`
  - `pub fn probe_argv(target: &str) -> Vec<String>`
  - `pub fn deny_all_argv() -> Vec<String>`
  - `pub fn run_probes(sb: &dyn Exec, plan: &Plan) -> Result<Vec<Probe>, String>`

Decisions:
- The guest has busybox `nc` (BusyBox v1.37.0, `/usr/bin/nc -> /bin/busybox`, checked 2026-10-29 in the guest's base image `alpine@sha256:e311ae74…ffb42`, the `FROM` in `guest/Dockerfile`). Its `-w SEC` covers connects and final net reads, so a closed stdin still lets the response arrive.
- `probe_argv(target)` is `sh -c <fixed script> sh <target>`. The script:
  - prints `RTS_PROBE no-nc` and exits 0 when `command -v nc` fails;
  - otherwise sends `CONNECT $1 HTTP/1.1\r\nHost: $1\r\n\r\n` with `printf` into `nc -w 10 127.0.0.1 1080` and takes the first line;
  - prints `RTS_PROBE connected` when that line matches `HTTP/1.? 200*`, and otherwise `RTS_PROBE refused <line, at most 200 chars>`.
- `deny_all_argv()` follows the same pattern for `1.1.1.1:443`. It tries both a direct `nc -w 5 1.1.1.1 443 </dev/null` and the CONNECT through the proxy, and prints `RTS_PROBE unreachable` only when neither connects. Otherwise it prints `RTS_PROBE reachable-direct` or `RTS_PROBE reachable-proxy`. With no nc, it prints `RTS_PROBE no-nc`.
- `run_probes` runs one exec per probe with `ExecOptions::new(15_000, 4096)`, in entry order, and stops at the first failure. For a non-empty plan, a probe passes only if the last stdout line is exactly `RTS_PROBE connected`. For an empty plan, it passes only if the line is exactly `RTS_PROBE unreachable`. An exec error, a non-zero exit, `no-nc` or any other output gives `Err("network probe <target> failed: <result>")`. `Ok` returns every `Probe` with `result` set to the marker word.
- The target passed for a name is `name:port` and for an IP is the entry's `display()`. HTTP CONNECT takes bracketed IPv6.

- [ ] **Step 1: Write the failing tests.**

```rust
#[test]
fn the_deny_all_probe_fails_closed_without_nc_or_on_odd_output() {
    for (stdout, ok) in [("RTS_PROBE unreachable\n", true), ("RTS_PROBE no-nc\n", false), ("", false), ("RTS_PROBE reachable-direct\n", false), ("RTS_PROBE unreachable\nRTS_PROBE connected\n", false), ("rts_probe unreachable\n", false)] {
        let rec = Recorder::new(move |_, _| ok(stdout.as_bytes()));
        let r = run_probes(&rec, &empty_plan());
        assert_eq!(r.is_ok(), ok, "{stdout:?}: {r:?}");
    }
}

#[test]
fn each_allowed_entry_is_probed_in_order_and_the_first_failure_names_it() {
    // Plan for ["198.51.100.7:443", "198.51.100.8:8443"]. The second answers "RTS_PROBE refused HTTP/1.1 403 Forbidden".
    // Err contains "198.51.100.8:8443" and "refused". Two execs ran, each with timeout_ms 15_000, and argv[3] equals the target.
}

#[test]
fn the_probe_script_reports_no_nc_when_nc_is_missing() {
    // run_wrapped_locally (src/testutil.rs:11-17) on ["env", "PATH=/nonexistent", "/bin/sh", "-c", <probe_argv's script>, "sh", "a.example:443"]:
    // `command -v nc` fails, so stdout is exactly "RTS_PROBE no-nc\n". The same holds for deny_all_argv's script.
}
```

- [ ] **Step 2: Run, expect FAIL.** It fails to compile (`run_probes` not found).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** `T --lib` shows the five baseline failures only.
- [ ] **Step 5: Commit.** `git add src/network.rs && git commit -m "Probe allowed hosts and deny-all from the guest after boot"`

---

### Task 8: Copy this VM's audit entries into `network.jsonl`

**Files:**
- Modify: `src/network.rs`
- Test: `src/network.rs` unit tests (fixture lines built in the test)

**Interfaces:**
- Produces: `pub fn extract_audit(audit_dir: &std::path::Path, vm_name: &str, out: &std::path::Path) -> Result<usize, String>`, which returns the number of lines written

Decisions:
- Sources are every `local.seg-*.jsonl` in `audit_dir`, sorted by name, then `local.jsonl`. The machine name is unique per session (`rts-<12 hex>`), so no time window is needed, and mvm's segment naming and rotation timing do not matter.
- Read line by line (`BufRead`). Keep a line only when it parses as JSON with `entry.labels.vm_name == vm_name`, an exact string match, and `entry.event` starts with one of the four prefixes. Write kept lines byte for byte plus `\n`, to `out`, created 0600 with `truncate(true)`. Never open mvm's files for writing.
- A missing `audit_dir` or `local.jsonl` is an `Err` (`mvm audit log not found at …`). Unparseable lines are skipped.

- [ ] **Step 1: Write the failing test.**

```rust
#[test]
fn audit_entries_are_filtered_by_vm_name_and_event_across_a_rotated_segment() {
    let d = crate::testutil::tempdir("audit");
    let line = |vm: &str, ev: &str| format!(r#"{{"entry":{{"event":"{ev}","labels":{{"vm_name":"{vm}","target":"x:443"}}}},"canonical":"Y2Fu","prev_hash":"cA","signature":"c2ln"}}"#);
    let me = "rts-0123456789ab";
    std::fs::write(d.join("local.seg-0001.jsonl"), [line(me, "host.flow.allowed"), line("rts-ffffffffffff", "host.flow.denied"), "not json".into()].join("\n") + "\n").unwrap();
    std::fs::write(d.join("local.jsonl"), [line(me, "dns.resolved"), line(me, "plan.signed"), line(&format!("{me}x"), "host.flow.denied"), line(me, "host.route.decided"), line(me, "icmp.refused")].join("\n") + "\n").unwrap();
    let out = d.join("network.jsonl");
    assert_eq!(extract_audit(&d, me, &out).unwrap(), 4);
    let text = std::fs::read_to_string(&out).unwrap();
    assert_eq!(text.lines().collect::<Vec<_>>(), [line(me, "host.flow.allowed"), line(me, "dns.resolved"), line(me, "host.route.decided"), line(me, "icmp.refused")]);
    assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(extract_audit(&d.join("missing"), me, &out).is_err());
    std::fs::remove_dir_all(d).unwrap();
}
```

- [ ] **Step 2: Run, expect FAIL.** It fails to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** `T --lib` shows the five baseline failures only.
- [ ] **Step 5: Commit.** `git add src/network.rs && git commit -m "Copy the session VM's signed egress audit into network.jsonl"`

---

### Task 9: Wire networking into the session

**Files:**
- Modify: `src/session.rs`: `SessionPaths`/`session_paths` (`:125-173`), `Deps`/`Deps::real` (`:429-454`), `Live`/`teardown` (`:481-528`), `run_session` (`:532-580`) and `session_body` (`:616-707`)
- Modify: the `Deps { .. }` literals in `src/session.rs` tests (`:1039`, `:1203`, `:1213`, `:1247`, `:1271`), and the `Live { .. }` literal at `:1176`
- Test: `src/session.rs` unit tests

**Interfaces:**
- Consumes: Tasks 2, 3, 5, 6, 7 and 8.
- Produces:
  - `SessionPaths.attach_log` (`sessions/<id>/mvm-attach.log`), `SessionPaths.session_record` (`sessions/<id>/session.json`) and `SessionPaths.network_audit` (`sessions/<id>/network.jsonl`)
  - `Deps.resolver: Arc<dyn network::Resolver>`. `Deps::real` uses `SystemResolver`.
  - `pub fn network_children(host: &dyn Host, attach_pid: u32) -> Result<Vec<u32>, String>` runs `pgrep -P <pid>` and keeps the children whose `ps -o comm=` basename is `mvm-network-endpoint` or `mvm-hvf-supervisor`. It returns `Err` unless one `mvm-network-endpoint` is among them. The spike observed both as children of the attach mvmctl.
  - `Live` gains `host: &'a dyn Host`, `network_pids: Vec<u32>` and `audit_dir: Option<PathBuf>`

Decisions:
- `sessions/<id>/session.json` does not exist today: only `attestation.json`, `inference.jsonl`, `tools.jsonl` and `launcher.log` are written (`src/attest/record.rs:15`, `src/main.rs:319`, `src/session.rs:169-170`). This task creates it with `write_private` (`src/session.rs:118-121`, 0600) as `{"network": plan.record(&probes)}`. It is written once before create, with `probes: []`, and rewritten after the probes.
- Order in `session_body`, between `preflight` (`:619-627`) and `sweep_orphans` (`:628`):
  1. `network::check_mvm_host(&deps.env, &mvm_root(&deps.env)?)`, on every session;
  2. `let plan = network::plan(&cfg.network, deps.resolver.as_ref())?`;
  3. write `session.json`.
  Then `create` with `egress: (!plan.is_empty()).then(|| Egress { allow_hosts: &hosts, attach_log: &p.attach_log })`. After `machine_created`, on a network session only, `live.network_pids = network_children(...)?`. Then `network::run_probes(live.sb, &plan)?` runs for every session; a no-network session runs the deny-all probe. Then `session.json` is rewritten, and `live.log.log(&plan.startup_line())` runs. Only after that come `initialize_guest_storage` and `copy_in` (`:640-644`). `live.audit_dir` is set to `<mvm root>/audit` before create.
- Supervision: `live.sb.network_lost()` is checked:
  - next to every `interrupted(..).or_else(|| stopped(..))` after create (`:645`);
  - in the `wait_for_ready` closure (`:677-688`), so a lost attach ends the handshake with that reason;
  - in the main loop (`:693-706`), every iteration.
  Each check returns `Err(reason)`, and `run_session` already tears down: export `/out`, then remove. The process exit code is 1.
- `Live::teardown` after `self.sb.remove()` (`:523-526`):
  1. for each pid in `network_pids` whose `ps -o comm=` basename is still `mvm-network-endpoint` or `mvm-hvf-supervisor`, log `teardown: NETWORK PROCESS REMAINED: pid <n> (<comm>); killed`, send SIGKILL and continue;
  2. if `audit_dir` is set, run `extract_audit(audit_dir, &paths.machine, &paths.network_audit)`. On success, log `teardown: copied <n> network audit entries to <path>`; on failure, `teardown: NETWORK AUDIT FAILED: <e>`.
  Neither step can stop the export or the removal, because both run after them.

- [ ] **Step 1: Write the failing tests.** Extend the session test `Fake` (`src/session.rs:828-851`) with an `attach` that returns a shared `FakeAttached` (as in Task 5), and give it scripted replies: `machine ps` gives `rts-0123456789ab running`, `pgrep -P 4242` gives `4243\n4244\n`, `ps -o comm= -p 4243` gives `mvm-network-endpoint`, 4244 gives `mvm-hvf-supervisor`, the probe execs answer `RTS_PROBE connected` or `RTS_PROBE unreachable` with a valid trailer, `ps -o rss=` gives `1000`, and `MVM_HOME` is a temp dir holding `vms/rts-0123456789ab/hvf.pid` and `audit/local.jsonl`. `NoResolve` is a resolver that panics, for no-network tests. Add these tests:
  - `a_session_with_a_proxy_variable_is_refused_before_any_machine_command`: `env` has `https_proxy=http://p:3128`. The exit code is 1, no call starts with `machine`, and `launcher.log` names `https_proxy`.
  - `an_unresolvable_entry_refuses_before_any_machine_command`: `cfg.network = ["nowhere.example"]`.
  - `a_no_network_session_runs_the_deny_all_probe_and_records_it`: `opencode` is `/nonexistent-opencode`, so the session stops after the probes. `session.json` equals `{"network": {"allow": [], "expanded": [], "resolved": {}, "probes": [{"target": "1.1.1.1:443", "result": "unreachable"}]}}`, `launcher.log` has `network: none`, the calls include `machine start` and no `machine run`, and `network.jsonl` exists.
  - `a_network_session_creates_with_allow_hosts_probes_and_logs_the_startup_line`: `cfg.network = ["198.51.100.7:8443"]`. The create argv ends `--allow-host 198.51.100.7:8443`, the attach argv is `machine run --name rts-0123456789ab --ttl 30d`, `session.json` has `probes: [{"target": "198.51.100.7:8443", "result": "connected"}]`, the log has `network: 1 host allowed (198.51.100.7:8443); TCP only; every connection is logged`, and teardown ran `machine rm` before `terminate`.
  - `a_lost_attach_before_opencode_ends_the_session_with_network_lost_and_still_exports_and_removes`: flip the `FakeAttached` to exited right after the probe exec. The `:645`-site check fires before `Terminal::spawn`. The exit code is 1, `launcher.log` contains `network-lost` and `teardown: removed`, and copy-out's exec ran after the flip.
  - `a_lost_attach_during_the_handshake_ends_the_session_with_network_lost`: `opencode` is a temp executable script, `#!/bin/sh\ntouch <dir>/started; exec sleep 30`, with `<dir>` baked in. `FakeAttached::exited()` reports an exit once `<dir>/started` exists. `Terminal` opens its own pty (`src/terminal.rs:25-34`) and needs no tty on the test's stdin. The session ends with `network-lost` well before `handshakeMs`, the opencode stand-in is stopped, and `machine rm` ran. The main-loop path needs a real plugin handshake, so Task 10 covers it.
  - `a_failed_probe_refuses_and_tears_down`: the probe answers `RTS_PROBE refused HTTP/1.1 403 Forbidden`. The exit code is 1, the log names the entry, and `machine rm` ran.
  - `teardown_kills_a_lingering_endpoint_and_reports_audit_failure_without_blocking_removal`: build `Live` directly, with `network_pids = [4243]`, `ps -o comm=` still `mvm-network-endpoint`, and `audit_dir` missing. The log has both `NETWORK PROCESS REMAINED` and `NETWORK AUDIT FAILED`, and `machine rm` ran.
- [ ] **Step 2: Run, expect FAIL.** `T --lib session::tests` fails to compile (no field `resolver`), then on the assertions.
- [ ] **Step 3: Implement** as decided. Keep every existing session test green. Existing tests that get past `create` now run the deny-all probe, so their fakes must answer that `machine exec` with stdout `RTS_PROBE unreachable` (`a_session_refuses_before_opencode_when_supervisor_cannot_be_monitored`, `:1240`). Existing tests that refuse earlier need only the new `resolver` field (`NoResolve`).
- [ ] **Step 4: Run, expect PASS.** `T --lib` shows the five baseline failures only, and `T --bin rts` passes.
- [ ] **Step 5: Commit.** `git add src/session.rs && git commit -m "Validate, probe, supervise and audit sandbox network per session"`

---

### Task 9a: Session time limit and the attach TTL (added 2026-10-29, approved by Zaki)

Supersedes the fixed `ATTACH_TTL = "30d"` in Task 5 and the Global Constraints: the attach `--ttl` follows a real session limit.

**Files:**
- Modify: `src/config.rs` (`Limits` `:46`, `RawLimits`, `parse_config` `:292-317`), `src/mvm.rs` (the attach argv from Task 5), `src/session.rs` (the run loop in `session_body`), `opencode/session.example.json`, `opencode/README.md`
- Test: `src/config.rs`, `src/mvm.rs`, `src/session.rs` unit tests

**Interfaces:**
- Produces: `Limits.session_hours: u32` from config `limits.sessionHours`, default `24`, refused unless `1..=720` (720 h is mvm's 30-day `MAX_TTL`); `pub fn attach_ttl(hours: u32) -> String` returning `"<hours>h"`; the session loop ends the session with stop reason `session-limit` when the wall-clock time since boot reaches the limit (export `/out`, remove the VM), for every session, with or without network.

- [ ] **Step 1: Failing tests.** `limits.sessionHours` absent gives 24; `0`, `721` and a non-integer are refused with `config: limits.sessionHours must be an integer from 1 to 720`; `attach_ttl(24) == "24h"`; the attach argv for a 24 h config is `machine run --name <name> --ttl 24h`; a session whose limit has passed (injected clock) stops with `session-limit` and runs teardown in the usual order; a session within its limit is not stopped.
- [ ] **Step 2: Run, expect FAIL** (`RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo test --lib`).
- [ ] **Step 3: Implement**; replace `ATTACH_TTL` and every test that asserted `--ttl 30d`.
- [ ] **Step 4: Run, expect PASS**, and the full gate.
- [ ] **Step 5: Commit** "Limit session wall-clock time and derive the attach TTL from it".

### Task 9b: Post-boot check of the IPs mvm pinned (added 2026-10-29, approved by Zaki)

`rts` resolves and validates every name before boot (Task 2), but mvm resolves the names again when its endpoint starts and pins those answers. A different answer at that moment (DNS changed, or a hostile resolver) could pin a LAN or otherwise refused address. After the probes and before anything else runs in the guest, `rts` compares what mvm pinned with what `rts` validated. (The plan first said "before the probes"; Task 10 measured that mvm v0.22.0 writes its pins only in `host.flow.allowed`, and only on a successful flow, so the check has to follow the probes.)

**Files:**
- Modify: `src/network.rs` (a pure comparison), `src/session.rs` (call it after Task 7's probes, before anything else runs in the guest), `tests/contain/network.rs` (Task 10 measures the real event shape)
- Test: `src/network.rs` unit tests

**Interfaces:**
- Consumes: Task 2's resolved plan (name -> validated IPs), Task 8's audit reader (entries for `vm_name == rts-<id>`).
- Produces: `pub fn check_pinned(plan: &Plan, pinned: &BTreeMap<String, BTreeSet<IpAddr>>) -> Result<(), String>`; the session reads this VM's `dns.resolved` (or equivalent pinning) entries from mvm's audit log, waiting up to 10 s for an entry per name, and ends the session with stop reason `network-mismatch` (export `/out`, remove the VM) when a name has no pinning entry, when any pinned IP is in a refused range (Task 1's ranges), or when any pinned IP is not among the addresses `rts` resolved and validated for that name. `session.json` records the pinned IPs next to `rts`'s.

- [ ] **Step 1: Failing tests** for `check_pinned`: identical sets pass; a pinned IP missing from `rts`'s set fails naming the host and IP; a pinned `192.168.1.10` for a name `rts` resolved to a public IP fails; a name with no pinning entry fails; IP-literal entries (no DNS) pass trivially; a subset of `rts`'s IPs passes (mvm may pin fewer).
- [ ] **Step 2: Run, expect FAIL.** **Step 3: Implement** the pure check and the session call. The audit field names (`entry.labels.target`, `entry.labels.resolved_ips`, or the `dns.resolved` shape) are taken from the research notes and confirmed against a real run in Task 10; if the real shape differs, Task 10 fixes the parser and records the measurement.
- [ ] **Step 4: Run, expect PASS**, and the full gate.
- [ ] **Step 5: Commit** "Refuse a session when mvm pinned IPs rts did not validate".

Task 10 additionally checks, on real mvm: a session with one allowed host records matching pinned IPs in `session.json`; and the session limit by running a session with `sessionHours` overridden to a test-only minimum through an injected clock, not by waiting.

### Task 10: Containment against real mvm

**Files:**
- Create: `tests/contain/network.rs`
- Modify: `tests/contain/main.rs` (`mod network;`), `tests/contain/harness.rs` (`fresh_network_machine`, and a `proxy` argument on `bridge_options`)
- Modify (only on the measured outcome in Step 4): `src/network.rs` `PRESET_PACKAGES`, and the spec's Operator interface and Testing sections

**Interfaces:**
- Consumes: `network::{plan, SystemResolver, run_probes, probe_argv, extract_audit}`, `session::{mvm_root, network_children}`, `MvmSandbox::{attach_pid, network_lost}`.
- Produces:
  - `pub fn fresh_network_machine(h: &Harness, allow: &[&str]) -> (Machine, rts::network::Plan, PathBuf)`. It creates a temp dir holding `mvm-attach.log`, creates the machine with `egress`, and initializes guest storage.
  - `pub fn bridge_options_with(h: &Harness, machine: &str, state_dir: &Path, proxy: bool) -> Value`. The existing `bridge_options` calls it with `false`.

All tests are `#[ignore = "real mvm"]`. Run them with `T --test contain -- --ignored --test-threads=1 network::`. Each test's `Machine` removes its VM on drop, and each test ends by asserting that `list_machines` no longer lists its machine.

- [ ] **Step 1: Write the tests** (they fail until Tasks 1-9 are in, and those already are, so expect PASS. Any FAIL is a finding: stop and report it with the output):
  - `no_allowlist_reaches_nothing_and_the_deny_all_probe_passes`: `fresh_machine`. `run_probes` with an empty plan returns `[Probe { target: "1.1.1.1:443", result: "unreachable" }]`, and `probe_argv("pypi.org:443")` does not print `connected`. Keep the existing `exec::the_guest_has_no_network` as is.
  - `one_allowed_host_connects_and_everything_else_is_refused_and_logged`: allow `pypi.org`. The probes pass. Bind host listeners on `127.0.0.1:0` and on the host's LAN address, found with `ipconfig getifaddr en0`, then `en1`; the test panics, and does not skip, when neither has an address. None of these connects: `example.com:443`, `pypi.org:80`, `127.0.0.1:<listener>`, `<LAN>:<listener>` and `169.254.169.254:80`. Neither listener accepted a connection. Drop the machine, then run `extract_audit`. `network.jsonl` has a `host.flow.allowed` for `pypi.org:443` and a `host.flow.denied` naming each refused target (match on `entry.labels.target`), and every line's `vm_name` is this machine's.
  - `the_guest_cannot_reach_the_ironwire_or_forwarder_loopback_ports`: the leak check. Allow `pypi.org`. Start `fake_ironwire` (`tests/contain/harness.rs:155-175`), which gives its port, and a second `127.0.0.1:0` listener standing in for the attested forwarder. Also try `127.0.0.1:8463`, IronWire's default port (`src/config.rs:15`). From the guest, `127.0.0.1:<each>` and `localhost:<each>` through the proxy never print `connected`, and both listeners accepted nothing. `network.jsonl` shows those targets denied.
  - `the_packages_preset_installs_with_apk_and_pip`: allow `packages`. Through `rts_tool` with `bridge_options_with(.., true)`, run `shell` with `apk add --usermode --root /tmp/r --initdb --no-scripts --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories python3 py3-pip`. It succeeds (exit 0 in the tool text). Then `LD_LIBRARY_PATH=/tmp/r/usr/lib /tmp/r/usr/bin/python3 -m pip download --no-deps six -d /tmp/six && ls /tmp/six` lists `six-*.whl`. This test is also the HVF gate for mvm #3962.
  - `losing_the_attach_is_detected_and_teardown_leaves_no_network_process`: allow `pypi.org`. Record `network_children(&RealHost, attach_pid)`, then `kill -9` the attach pid. Within 2 s `network_lost()` is `Some`. `remove()` is `Ok`. Afterwards, no recorded pid has comm `mvm-network-endpoint` or `mvm-hvf-supervisor`, and no process has the attach pid.
  - `killing_the_attach_mid_session_ends_the_launcher_with_network_lost` (needs real opencode, `#[ignore = "real mvm and opencode"]`): model it on `sigint_to_the_launcher_exports_out_and_leaves_no_rts_machine` (`tests/contain/session.rs:205-258`), with `"network": { "allow": ["pypi.org"] }` added to the session file. After `plugin ready`, write `/out/hello.txt` through `rts_tool`. Find the attach with `pgrep -f "machine run --name <machine>"` and `kill -9` it. The launcher exits with code 1 within 15 s, and its stderr contains `network-lost` and `teardown: removed`. `/out/hello.txt` was exported, and `list_machines` no longer lists the machine. `sessions/<id>/mvm-attach.log` contains `exec request` while the launcher's stderr does not: the attach output never reached the terminal. The stderr also shows the startup line `network: 1 host allowed (pypi.org); TCP only; every connection is logged`.
- [ ] **Step 2: Run** `T --test contain -- --ignored --test-threads=1 network::` and paste the summary. Then run the full suite, `T --test contain -- --ignored --test-threads=1`, to confirm the existing containment tests (including `leak::the_sentinel_test_fails_when_shell_leaks_to_the_host`) are unchanged.
- [ ] **Step 3: Cleanup proof.** Paste the output of `mvmctl machine ps` (no `rts-` machine from this run) and of `ps -ax | grep -E 'mvm-(network-endpoint|hvf-supervisor)|machine run --name rts-' | grep -v grep`, which shows none from this run.
- [ ] **Step 4: The `apk` decision.** If `apk add` fails, stop and report with the tool output and the `dl-cdn.alpinelinux.org` lines of `network.jsonl`. Without apk the guest has no python, so the pip half cannot run, and dropping `dl-cdn.alpinelinux.org` from the preset (the spec's fallback) is Zaki's call. The spike measured apk working through the proxy, so this branch is not expected.
- [ ] **Step 5: Commit.** `git add tests/contain && git commit -m "Contain sandbox network access against real mvm"` (add `src/network.rs` and the spec if Step 4 changed them).

---

### Task 11: Documentation

**Files:**
- Modify: `README.md` (a new section "Network access" after Quick start, `README.md:19-27`; the intro line at `:11-14` stops saying networking is disabled without qualification)
- Modify: `src/main.rs` `USAGE` (`:143`). Task 4 added the flags; this task adds the examples.
- Modify: `docs/specs/2026-10-27-sandboxed-opencode-design.md` (the VM egress row, `:27`; remove `- VM egress allowlists.` from Out of scope, `:670`)
- Modify: `opencode/README.md` (the session file's `network.allow` key, next to the other config keys)

Decisions:
- The README covers:
  - the default (no network, and every launch proves it);
  - `network.allow` and the two flags;
  - three examples: `rts launch --allow-host packages`; `rts launch --allow-host api.example-target.com`; and `rts launch --allow-host 192.168.1.20:8080`, with why `127.0.0.1` cannot work (mvm always refuses the host's loopback, which also keeps the guest away from IronWire and the forwarder);
  - only proxy-aware tools get out, and `shell` calls get the proxy environment;
  - the exfiltration and CDN co-tenancy caveats (spec risks 2 and 3), with the measured Fastly and Cloudflare note;
  - the unsandboxed `mvm-network-endpoint` (risk 1);
  - TCP only, with no byte caps;
  - where the audit lands: `session.json`, `network.jsonl` and `mvm-attach.log`, the last never shown;
  - `network-lost`.
- `USAGE` gains three lines under the launch usage:
  - `rts launch --allow-host packages            # pip, npm, apk and cargo registries`
  - `rts launch --allow-host api.example-target.com   # one target, port 443`
  - `rts launch --allow-host 192.168.1.20:8080   # a service on this machine's LAN address`
- The sandbox spec row reads: `Per-session allowlist over mvm --allow-host, default none; see 2026-10-29-sandbox-network-access-design.md.`

- [ ] **Step 1: Write the failing test** in `src/main.rs`: `help_lists_the_network_flags_and_examples` asserts that `USAGE` contains `--allow-host ENTRY`, `--no-network`, `--allow-host packages` and `192.168.1.20:8080`.
- [ ] **Step 2: Run, expect FAIL** on the examples. Run `T --bin rts help_lists`.
- [ ] **Step 3: Write** the docs and the `USAGE` lines.
- [ ] **Step 4: Run, expect PASS.** `T --lib` shows the five baseline failures only, `T --bin rts` passes and `bun test tests/unit` passes.
- [ ] **Step 5: Commit.** `git add README.md src/main.rs docs/specs/2026-10-27-sandboxed-opencode-design.md opencode/README.md && git commit -m "Document sandbox network access"`

---

## Self-review against the spec

| Spec item | Task |
|---|---|
| Default none; allowlist only from operator before launch | 4, 9 |
| `--allow-host` only; never `--net`/`--peer`/`--gpu`/`--grants-file`/`--policy` | 5 (guard test), Global Constraints |
| Exact names/IPs, port 443 default, no wildcards, 22/0/>65535 refused | 1 |
| Preset `packages` | 1, 10 (apk gate) |
| Attached start, supervision, `network-lost`, teardown order, 0600 log, retry once, TTL | 5, 9, 10 |
| Validation ranges, 64 cap, dedupe | 1 |
| Host resolution, unresolvable and refused-only names | 2 |
| Default egress grant and proxy env refusal | 3 |
| Probes, deny-all on no-network sessions | 7, 9, 10 |
| Proxy env for tool calls (blocker 3) | 6 |
| `session.json` network record, `network.jsonl` audit | 2, 8, 9 |
| Startup line | 2, 9 |
| README, `--help`, sandbox spec update | 11 |
| Testing: every unit and containment item, including leak check and deny-all | 1-10 |
