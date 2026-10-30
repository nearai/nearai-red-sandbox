//! Sandbox network allowlist entries: parsing, preset expansion, validation,
//! host-side resolution and the resolved [`Plan`].
//!
//! Only [`plan`] looks a name up, and only through a [`Resolver`]. Every
//! check fails closed and names the entry as the operator wrote it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// The `packages` preset: package registries, all on port 443.
pub const PRESET_PACKAGES: &[&str] = &[
    "dl-cdn.alpinelinux.org",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "index.crates.io",
    "static.crates.io",
    "crates.io",
];

/// The most entries a session may allow, counted after expansion and deduplication.
pub const MAX_ENTRIES: usize = 64;

/// The port an entry gets when it names none.
pub const DEFAULT_PORT: u16 = 443;

const PRESET_PACKAGES_NAME: &str = "packages";

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Host {
    Name(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Entry {
    pub host: Host,
    pub port: u16,
}

impl Entry {
    /// `name:port`, `a.b.c.d:port` or `[v6]:port`.
    pub fn display(&self) -> String {
        match &self.host {
            Host::Name(n) => format!("{n}:{}", self.port),
            Host::Ip(IpAddr::V4(ip)) => format!("{ip}:{}", self.port),
            Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
        }
    }
}

/// Parse every entry as written, expand presets, deduplicate in first-seen
/// order, and refuse the list if any entry is invalid or more than
/// [`MAX_ENTRIES`] remain.
pub fn expand(written: &[String]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |e: Entry, out: &mut Vec<Entry>| {
        if seen.insert(e.clone()) {
            out.push(e);
        }
    };
    for w in written {
        if w.eq_ignore_ascii_case(PRESET_PACKAGES_NAME) {
            for h in PRESET_PACKAGES {
                push(
                    Entry {
                        host: Host::Name((*h).to_string()),
                        port: DEFAULT_PORT,
                    },
                    &mut out,
                );
            }
            continue;
        }
        let e = parse_entry(w).map_err(|why| format!("network entry {w:?}: {why}"))?;
        push(e, &mut out);
    }
    if out.len() > MAX_ENTRIES {
        return Err(format!(
            "the network allowlist has {} entries after expansion; at most {MAX_ENTRIES} are allowed",
            out.len()
        ));
    }
    Ok(out)
}

/// The name of the always-refused range `ip` falls in, if any. An
/// IPv4-mapped IPv6 address is judged by its IPv4 address.
pub fn refused_range(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => refused_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => refused_v4(v4),
            None => refused_v6(v6),
        },
    }
}

fn refused_v4(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    if o[0] == 127 {
        Some("loopback")
    } else if o == [169, 254, 169, 254] {
        Some("cloud metadata")
    } else if o[0] == 169 && o[1] == 254 {
        Some("link-local")
    } else if o[0] == 0 {
        Some("unspecified")
    } else if (224..=239).contains(&o[0]) {
        Some("multicast")
    } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
        Some("100.64.0.0/10")
    } else {
        None
    }
}

fn refused_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let seg = ip.segments();
    if ip == Ipv6Addr::LOCALHOST {
        Some("loopback")
    } else if ip == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254) {
        Some("cloud metadata")
    } else if (seg[0] & 0xffc0) == 0xfe80 {
        Some("link-local")
    } else if ip == Ipv6Addr::UNSPECIFIED {
        Some("unspecified")
    } else if (seg[0] & 0xff00) == 0xff00 {
        Some("multicast")
    } else {
        None
    }
}

fn parse_entry(w: &str) -> Result<Entry, String> {
    if w.is_empty() {
        return Err("the entry is empty".into());
    }
    if let Some(rest) = w.strip_prefix('[') {
        let Some((inside, after)) = rest.split_once(']') else {
            return Err("an IPv6 address must be written as [addr]:port".into());
        };
        let ip: Ipv6Addr = inside
            .parse()
            .map_err(|_| format!("{inside:?} is not an IPv6 address; write IPv6 as [addr]:port"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if after.is_empty() => {
                return Err("an IP address needs a port, as [addr]:port".into());
            }
            None => return Err("an IPv6 address must be written as [addr]:port".into()),
        };
        return ip_entry(IpAddr::V6(ip), port);
    }
    // Catch schemes, paths, wildcards and the like before the colon split,
    // so `https://a.example` is refused as a host name, not as a bad port.
    if !w
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return Err(
            "not a valid host name (only letters, digits, '-' and '.' are allowed; no wildcards, schemes or paths)"
                .into(),
        );
    }
    let (host, port) = match w.matches(':').count() {
        0 => (w, None),
        1 => {
            let (h, p) = w.split_once(':').unwrap_or((w, ""));
            (h, Some(p))
        }
        _ => {
            if w.parse::<Ipv6Addr>().is_ok() {
                return Err(
                    "an IPv6 address must be in brackets with a port, as [addr]:port".into(),
                );
            }
            return Err(
                "not a valid host name (an IPv6 address must be in brackets, as [addr]:port)"
                    .into(),
            );
        }
    };
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        let Some(p) = port else {
            return Err("an IP address needs a port, as a.b.c.d:port".into());
        };
        return ip_entry(IpAddr::V4(ip), parse_port(p)?);
    }
    let name = valid_host_name(host)?;
    let port = match port {
        Some(p) => parse_port(p)?,
        None => DEFAULT_PORT,
    };
    Ok(Entry {
        host: Host::Name(name),
        port,
    })
}

fn ip_entry(ip: IpAddr, port: u16) -> Result<Entry, String> {
    if let Some(range) = refused_range(ip) {
        return Err(format!("{range} addresses are always refused"));
    }
    Ok(Entry {
        host: Host::Ip(ip),
        port,
    })
}

fn parse_port(p: &str) -> Result<u16, String> {
    if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("port {p:?} is not a number from 1 to 65535"));
    }
    let n: u32 = p
        .parse()
        .map_err(|_| format!("port {p} is out of range (1 to 65535)"))?;
    match n {
        0 => Err("port 0 is refused".into()),
        22 => Err("port 22 (ssh) is always refused".into()),
        n if n > 65535 => Err(format!("port {n} is out of range (1 to 65535)")),
        n => Ok(n as u16),
    }
}

fn valid_host_name(h: &str) -> Result<String, String> {
    let name = h.to_ascii_lowercase();
    let bad = |why: &str| Err(format!("not a valid host name ({why})"));
    if name.is_empty() {
        return bad("the name is empty");
    }
    if name.len() > 253 {
        return bad("longer than 253 characters");
    }
    for label in name.split('.') {
        if label.is_empty() {
            return bad("empty label; no leading, trailing or doubled dots");
        }
        if label.len() > 63 {
            return bad("a label is longer than 63 characters");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return bad(
                "only letters, digits, '-' and '.' are allowed; no wildcards, schemes or paths",
            );
        }
        if label.starts_with('-') || label.ends_with('-') {
            return bad("a label starts or ends with '-'");
        }
    }
    // A resolver may read a name like `127.1` or `0x7f000001` as an IPv4
    // address. Real top-level labels are never numeric, so refuse these.
    let last = name.rsplit('.').next().unwrap_or("");
    let hex = last
        .strip_prefix("0x")
        .is_some_and(|d| d.bytes().all(|b| b.is_ascii_hexdigit()));
    if last.bytes().all(|b| b.is_ascii_digit()) || hex {
        return bad("it looks like a numeric IP address; write IPv4 as a.b.c.d:port");
    }
    Ok(name)
}

/// Looks a host name up on the host, before launch.
pub trait Resolver: Send + Sync {
    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>>;
}

/// The host's own resolver, through `ToSocketAddrs`.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        let mut out: Vec<IpAddr> = Vec::new();
        for addr in (name, DEFAULT_PORT).to_socket_addrs()? {
            if !out.contains(&addr.ip()) {
                out.push(addr.ip());
            }
        }
        Ok(out)
    }
}

/// One `--allow-host` value for `mvmctl machine create`. Only a [`Plan`]
/// makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowHost(String);

impl AllowHost {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The result of one guest-side probe of an entry (Task 7 produces these).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub target: String,
    pub result: String,
}

/// An allowlist that has been parsed, expanded, validated and resolved on
/// the host. An empty plan means no network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    written: Vec<String>,
    entries: Vec<Entry>,
    resolved: BTreeMap<String, Vec<IpAddr>>,
}

/// Expand and validate `written`, then resolve every host name once through
/// `resolver`. A name that does not resolve, or resolves only to refused
/// ranges, refuses the whole list.
pub fn plan(written: &[String], resolver: &dyn Resolver) -> Result<Plan, String> {
    let entries = expand(written)?;
    // Which entry as written first produced each name, for error messages.
    let mut source: HashMap<String, &str> = HashMap::new();
    for w in written {
        for e in expand(std::slice::from_ref(w))? {
            if let Host::Name(n) = e.host {
                source.entry(n).or_insert(w.as_str());
            }
        }
    }
    let mut resolved = BTreeMap::new();
    for e in &entries {
        let Host::Name(name) = &e.host else { continue };
        if resolved.contains_key(name) {
            continue;
        }
        let as_written = source.get(name).copied().unwrap_or(name.as_str());
        let ips = match resolver.resolve(name) {
            Ok(ips) if !ips.is_empty() => ips,
            Ok(_) => {
                return Err(format!(
                    "network entry {as_written:?}: {name} does not resolve on this host (no addresses)"
                ));
            }
            Err(err) => {
                return Err(format!(
                    "network entry {as_written:?}: {name} does not resolve on this host ({err})"
                ));
            }
        };
        if let Some(range) = ips
            .iter()
            .map(|ip| refused_range(*ip))
            .collect::<Option<Vec<_>>>()
            .and_then(|ranges| ranges.first().copied())
        {
            return Err(format!(
                "network entry {as_written:?}: {name} resolves only to refused addresses ({range} addresses are always refused)"
            ));
        }
        resolved.insert(name.clone(), ips);
    }
    Ok(Plan {
        written: written.to_vec(),
        entries,
        resolved,
    })
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// One value per entry, as mvm v0.22.0 parses them: it splits at the
    /// last `:` and keeps the host verbatim, so IPv6 goes unbracketed.
    pub fn allow_hosts(&self) -> Vec<AllowHost> {
        self.entries
            .iter()
            .map(|e| match &e.host {
                Host::Name(n) => AllowHost(format!("{n}:{}", e.port)),
                Host::Ip(ip) => AllowHost(format!("{ip}:{}", e.port)),
            })
            .collect()
    }

    pub fn startup_line(&self) -> String {
        if self.is_empty() {
            return "network: none".into();
        }
        let n = self.entries.len();
        let s = if n == 1 { "" } else { "s" };
        format!(
            "network: {n} host{s} allowed ({}); TCP only; every connection is logged",
            self.written.join(", ")
        )
    }

    pub fn record(&self, probes: &[Probe]) -> serde_json::Value {
        let resolved: serde_json::Map<String, serde_json::Value> = self
            .resolved
            .iter()
            .map(|(name, ips)| {
                let ips = ips.iter().map(|ip| ip.to_string().into()).collect();
                (name.clone(), serde_json::Value::Array(ips))
            })
            .collect();
        serde_json::json!({
            "allow": self.written,
            "expanded": self.entries.iter().map(Entry::display).collect::<Vec<_>>(),
            "resolved": resolved,
            "probes": probes
                .iter()
                .map(|p| serde_json::json!({"target": p.target, "result": p.result}))
                .collect::<Vec<_>>(),
        })
    }
}

/// The proxy variables mvm v0.22.0 reads from its own environment
/// (`network_endpoint_spawn.rs:871-875`). Allowed guest traffic would leave
/// through any of them.
pub const PROXY_VARS: [&str; 6] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"];

/// The guest proxy mvm's network endpoint listens on inside the VM.
const GUEST_PROXY: &str = "127.0.0.1:1080";

/// The environment a sandboxed `shell` call runs under in a network
/// session, as `KEY=value` strings for `env`: the same eight variables
/// mvm's guest agent sets (`guest_netd.rs:102-123`), upper case first.
/// `machine exec` inherits none of them, so `rts` sets them itself.
pub fn proxy_env() -> Vec<String> {
    let http = format!("http://{GUEST_PROXY}");
    let socks = format!("socks5h://{GUEST_PROXY}");
    let no_proxy = "localhost,127.0.0.1,::1";
    let upper = [("HTTPS_PROXY", http.as_str()), ("HTTP_PROXY", http.as_str()), ("ALL_PROXY", socks.as_str()), ("NO_PROXY", no_proxy)];
    let lower = upper.iter().map(|(k, v)| (k.to_lowercase(), *v));
    upper.iter().map(|(k, v)| format!("{k}={v}")).chain(lower.map(|(k, v)| format!("{k}={v}"))).collect()
}

/// Refuse an mvm host whose settings could grant guest egress outside
/// `rts`'s control: any proxy variable mvm reads (even if empty) in the
/// environment `rts` passes to `mvmctl`, or a host config at
/// `<mvm root>/config/config.toml` that mentions `egress` on a non-comment
/// line or that exists but cannot be read. A missing config passes, since
/// mvm then writes its defaults, which grant no egress in v0.22.0. Runs on
/// every launch, with or without an allowlist.
pub fn check_mvm_host(env: &[(String, String)], mvm_root: &std::path::Path) -> Result<(), String> {
    if let Some((var, _)) = env.iter().find(|(k, _)| PROXY_VARS.contains(&k.as_str())) {
        return Err(format!(
            "{var} is set in the environment rts passes to mvmctl; mvm would route allowed guest traffic through it. Unset it and launch again"
        ));
    }
    let cfg = mvm_root.join("config").join("config.toml");
    match std::fs::symlink_metadata(&cfg) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot check mvm host config {}: {e}", cfg.display())),
        Ok(_) => {}
    }
    let text = std::fs::read_to_string(&cfg)
        .map_err(|e| format!("cannot read mvm host config {}: {e}", cfg.display()))?;
    // A line scan, not a TOML parse: anything outside a whole-line comment
    // that mentions egress refuses, including a trailing comment.
    if let Some(line) = text
        .lines()
        .map(str::trim)
        .find(|l| !l.starts_with('#') && l.to_ascii_lowercase().contains("egress"))
    {
        return Err(format!(
            "mvm host config {} mentions egress ({line:?}); it could grant guest egress outside rts's control. Remove that setting and launch again",
            cfg.display()
        ));
    }
    Ok(())
}

/// The address the deny-all probe must not reach, directly or through the
/// guest proxy.
pub const DENY_ALL_TARGET: &str = "1.1.1.1:443";

/// One probe exec: the wrapper's limit, which bounds every `nc` below.
const PROBE_TIMEOUT_MS: u64 = 15_000;
const PROBE_MAX_OUTPUT: u64 = 4096;
/// The longest guest-written text an error string carries.
const PROBE_ERROR_CHARS: usize = 200;

/// Shared start of both probe scripts. With no `nc` it prints `no-nc`
/// before any other command runs. `first_line TARGET` sends an HTTP CONNECT
/// for TARGET to the guest proxy and sets `line` to the first response
/// line, without its CR. It reads through a FIFO and then kills `nc`,
/// because a CONNECT that succeeds leaves the tunnel open and `nc` would
/// otherwise outlive the exec. It returns non-zero only if it could not set
/// up, so a setup failure never reads as "no answer".
macro_rules! probe_prelude {
    () => {
        r#"command -v nc >/dev/null 2>&1 || { echo 'RTS_PROBE no-nc'; exit 0; }
first_line() {
  line=
  d=$(mktemp -d /tmp/rts-probe.XXXXXX) || return 1
  printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$1" "$1" >"$d/req" && mkfifo "$d/out" || { rm -rf "$d"; return 1; }
  nc -w 10 127.0.0.1 1080 <"$d/req" >"$d/out" 2>/dev/null &
  p=$!
  IFS= read -r line <"$d/out"
  kill "$p" 2>/dev/null
  wait "$p" 2>/dev/null
  rm -rf "$d"
  cr=$(printf '\r')
  line=${line%"$cr"}
  return 0
}
"#
    };
}

/// `$1` is `host:port` (IPv6 bracketed, as HTTP CONNECT takes it).
const PROBE_SCRIPT: &str = concat!(
    probe_prelude!(),
    r#"first_line "$1" || { echo 'RTS_PROBE error setup'; exit 0; }
case $line in
  'HTTP/1.'?' 200'*) echo 'RTS_PROBE connected' ;;
  *) printf 'RTS_PROBE refused %.200s\n' "$line" ;;
esac
"#
);

/// `$1` is an IPv4 `a.b.c.d:port`. A direct `nc` that exits 0 connected;
/// one that never exits runs into the exec limit, which fails the probe.
const DENY_ALL_SCRIPT: &str = concat!(
    probe_prelude!(),
    r#"if nc -w 5 "${1%:*}" "${1##*:}" </dev/null >/dev/null 2>&1; then
  echo 'RTS_PROBE reachable-direct'
  exit 0
fi
first_line "$1" || { echo 'RTS_PROBE error setup'; exit 0; }
case $line in
  'HTTP/1.'?' 200'*) echo 'RTS_PROBE reachable-proxy' ;;
  *) echo 'RTS_PROBE unreachable' ;;
esac
"#
);

/// Probe `target` (`name:port`, `a.b.c.d:port` or `[v6]:port`) from the
/// guest through the proxy on `127.0.0.1:1080`.
pub fn probe_argv(target: &str) -> Vec<String> {
    vec!["sh".into(), "-c".into(), PROBE_SCRIPT.into(), "sh".into(), target.into()]
}

/// Probe that [`DENY_ALL_TARGET`] is unreachable both directly and through
/// the guest proxy.
pub fn deny_all_argv() -> Vec<String> {
    vec!["sh".into(), "-c".into(), DENY_ALL_SCRIPT.into(), "sh".into(), DENY_ALL_TARGET.into()]
}

/// Probe every entry of `plan` from the guest, in order, or deny-all when
/// the plan is empty. The first probe that does not print exactly the
/// expected marker as its last line, or does not exit 0, ends the run.
pub fn run_probes(sb: &dyn crate::sandbox::Exec, plan: &Plan) -> Result<Vec<Probe>, String> {
    let jobs: Vec<(String, Vec<String>, &str)> = if plan.is_empty() {
        vec![(DENY_ALL_TARGET.to_string(), deny_all_argv(), "unreachable")]
    } else {
        plan.entries()
            .iter()
            .map(|e| {
                let target = e.display();
                let argv = probe_argv(&target);
                (target, argv, "connected")
            })
            .collect()
    };
    let opts = crate::sandbox::ExecOptions::new(PROBE_TIMEOUT_MS, PROBE_MAX_OUTPUT);
    let mut probes = Vec::with_capacity(jobs.len());
    for (target, argv, want) in jobs {
        let fail = |what: String| format!("network probe {target} failed: {what}");
        let r = sb.exec(&argv, &opts).map_err(|e| fail(e.to_string()))?;
        if r.timed_out {
            return Err(fail("timed out".into()));
        }
        if r.exit_code != 0 {
            return Err(fail(format!("exit {}", r.exit_code)));
        }
        if r.truncated {
            return Err(fail("output truncated".into()));
        }
        let out = r.stdout.strip_suffix(b"\n").unwrap_or(&r.stdout);
        let last = out.rsplit(|&b| b == b'\n').next().unwrap_or(b"");
        if last != format!("RTS_PROBE {want}").as_bytes() {
            let shown: String = String::from_utf8_lossy(last)
                .chars()
                .take(PROBE_ERROR_CHARS)
                .collect::<String>()
                .escape_debug()
                .collect();
            let shown = if shown.is_empty() { "no output".to_string() } else { shown };
            return Err(fail(shown));
        }
        probes.push(Probe { target, result: want.to_string() });
    }
    Ok(probes)
}

/// `--allow-host` values for tests in other modules. IP literals need no
/// lookup; a name resolves to a fixed public test address.
#[cfg(test)]
pub(crate) fn test_allow_hosts(entries: &[&str]) -> Vec<AllowHost> {
    struct Fixed;
    impl Resolver for Fixed {
        fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))])
        }
    }
    let written: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
    plan(&written, &Fixed).expect("test entries are valid").allow_hosts()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::io;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// Answers from a fixed table; a name not in the table is `NotFound`.
    /// Errors are stored by kind so the table can hand out fresh copies.
    struct FakeResolver(HashMap<&'static str, Result<Vec<IpAddr>, io::ErrorKind>>);

    impl Resolver for FakeResolver {
        fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
            match self.0.get(name) {
                Some(Ok(ips)) => Ok(ips.clone()),
                Some(Err(kind)) => Err(io::Error::new(*kind, format!("fake: {kind:?}"))),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "fake: not in table",
                )),
            }
        }
    }

    fn fake(answers: &[(&'static str, Result<Vec<IpAddr>, io::ErrorKind>)]) -> FakeResolver {
        FakeResolver(answers.iter().cloned().collect())
    }

    /// Give each `packages` host a public address.
    fn with_packages(mut r: FakeResolver) -> FakeResolver {
        for (i, h) in PRESET_PACKAGES.iter().enumerate() {
            r.0.insert(
                h,
                Ok(vec![format!("198.51.100.{}", 100 + i).parse().unwrap()]),
            );
        }
        r
    }

    #[test]
    fn a_name_that_does_not_resolve_refuses_the_session() {
        let e = plan(
            &s(&["nowhere.example"]),
            &fake(&[("nowhere.example", Err(io::ErrorKind::NotFound))]),
        )
        .unwrap_err();
        assert!(
            e.contains("\"nowhere.example\"") && e.contains("does not resolve"),
            "{e}"
        );
        let e = plan(
            &s(&["empty.example"]),
            &fake(&[("empty.example", Ok(vec![]))]),
        )
        .unwrap_err();
        assert!(e.contains("does not resolve"), "{e}");
    }

    #[test]
    fn a_preset_host_that_does_not_resolve_names_the_preset() {
        let mut r = with_packages(fake(&[]));
        r.0.insert("pypi.org", Err(io::ErrorKind::TimedOut));
        let e = plan(&s(&["packages"]), &r).unwrap_err();
        assert!(
            e.contains("\"packages\"") && e.contains("pypi.org does not resolve"),
            "{e}"
        );
    }

    #[test]
    fn a_name_resolving_only_to_refused_ranges_is_refused() {
        for (name, ip, why) in [
            ("localhost", "127.0.0.1", "loopback"),
            ("meta.example", "169.254.169.254", "metadata"),
            ("cgnat.example", "100.64.3.4", "100.64.0.0/10"),
            ("mapped.example", "::ffff:127.0.0.1", "loopback"),
        ] {
            let e = plan(&s(&[name]), &fake(&[(name, Ok(vec![ip.parse().unwrap()]))])).unwrap_err();
            assert!(
                e.contains(&format!("{name:?}")) && e.contains(why),
                "{name}: {e}"
            );
        }
        let mixed = plan(
            &s(&["mixed.example"]),
            &fake(&[(
                "mixed.example",
                Ok(vec![
                    "127.0.0.1".parse().unwrap(),
                    "198.51.100.9".parse().unwrap(),
                ]),
            )]),
        )
        .unwrap();
        assert_eq!(mixed.entries().len(), 1);
    }

    #[test]
    fn invalid_entries_are_refused_before_any_lookup() {
        struct Panics;
        impl Resolver for Panics {
            fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
                panic!("resolved {name} although the list is invalid")
            }
        }
        let e = plan(&s(&["a.example", "127.0.0.1:8463"]), &Panics).unwrap_err();
        assert!(e.contains("loopback"), "{e}");
    }

    #[test]
    fn each_name_is_resolved_once() {
        use std::sync::Mutex;
        struct Counting(Mutex<Vec<String>>);
        impl Resolver for Counting {
            fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
                self.0.lock().unwrap().push(name.to_string());
                Ok(vec!["198.51.100.1".parse().unwrap()])
            }
        }
        let r = Counting(Mutex::new(vec![]));
        let p = plan(
            &s(&["a.example", "a.example:8443", "198.51.100.7:8443"]),
            &r,
        )
        .unwrap();
        assert_eq!(p.entries().len(), 3);
        assert_eq!(*r.0.lock().unwrap(), ["a.example"]);
    }

    #[test]
    fn allow_hosts_render_for_mvm_and_ipv6_is_unbracketed() {
        let p = plan(
            &s(&["a.example", "198.51.100.7:8443", "[2001:db8::7]:443"]),
            &fake(&[("a.example", Ok(vec!["198.51.100.1".parse().unwrap()]))]),
        )
        .unwrap();
        let v: Vec<String> = p
            .allow_hosts()
            .iter()
            .map(|a| a.as_str().to_string())
            .collect();
        assert_eq!(v, ["a.example:443", "198.51.100.7:8443", "2001:db8::7:443"]);
    }

    #[test]
    fn an_empty_plan_allows_nothing() {
        let p = plan(&[], &fake(&[])).unwrap();
        assert!(p.is_empty());
        assert!(p.entries().is_empty());
        assert!(p.allow_hosts().is_empty());
    }

    #[test]
    fn the_startup_line_for_none_one_and_many() {
        let r = fake(&[(
            "api.example-target.com",
            Ok(vec!["198.51.100.2".parse().unwrap()]),
        )]);
        assert_eq!(plan(&[], &r).unwrap().startup_line(), "network: none");
        assert_eq!(
            plan(&s(&["198.51.100.7:8443"]), &r).unwrap().startup_line(),
            "network: 1 host allowed (198.51.100.7:8443); TCP only; every connection is logged"
        );
        // `packages` names resolve through the fake too: give each of the seven an address.
        let many = plan(
            &s(&[
                "packages",
                "api.example-target.com",
                "198.51.100.7:8443",
                "192.168.1.20:8080",
            ]),
            &with_packages(r),
        )
        .unwrap();
        assert_eq!(
            many.startup_line(),
            "network: 10 hosts allowed (packages, api.example-target.com, 198.51.100.7:8443, 192.168.1.20:8080); TCP only; every connection is logged"
        );
    }

    #[test]
    fn the_record_carries_written_expanded_resolved_and_probes() {
        let p = plan(
            &s(&["a.example"]),
            &fake(&[("a.example", Ok(vec!["198.51.100.1".parse().unwrap()]))]),
        )
        .unwrap();
        let r = p.record(&[Probe {
            target: "a.example:443".into(),
            result: "connected".into(),
        }]);
        assert_eq!(
            r,
            serde_json::json!({"allow": ["a.example"], "expanded": ["a.example:443"], "resolved": {"a.example": ["198.51.100.1"]}, "probes": [{"target": "a.example:443", "result": "connected"}]})
        );
    }

    #[test]
    fn presets_expand_and_duplicates_collapse_in_order() {
        let e = expand(&s(&[
            "packages",
            "pypi.org",
            "api.example-target.com",
            "PyPI.org:443",
        ]))
        .unwrap();
        let shown: Vec<String> = e.iter().map(Entry::display).collect();
        let mut want: Vec<String> = PRESET_PACKAGES.iter().map(|h| format!("{h}:443")).collect();
        want.push("api.example-target.com:443".into());
        assert_eq!(shown, want);
    }

    #[test]
    fn hosts_ips_and_ports_parse() {
        let e = expand(&s(&[
            "a.example:8443",
            "198.51.100.7:8443",
            "[2001:db8::7]:443",
            "192.168.1.20:8080",
        ]))
        .unwrap();
        assert_eq!(
            e[0],
            Entry {
                host: Host::Name("a.example".into()),
                port: 8443
            }
        );
        assert_eq!(e[2].display(), "[2001:db8::7]:443");
        assert_eq!(e[3].host, Host::Ip("192.168.1.20".parse().unwrap()));
    }

    #[test]
    fn each_refusal_names_the_entry_and_the_reason() {
        for (entry, why) in [
            ("a.example:22", "port 22"),
            ("a.example:0", "port"),
            ("a.example:65536", "port"),
            ("127.0.0.1:8463", "loopback"),
            ("[::1]:443", "loopback"),
            ("[::ffff:127.0.0.1]:443", "loopback"),
            ("169.254.169.254:80", "metadata"),
            ("[fd00:ec2::254]:80", "metadata"),
            ("169.254.1.1:80", "link-local"),
            ("[fe80::1]:443", "link-local"),
            ("0.0.0.0:443", "unspecified"),
            ("[::]:443", "unspecified"),
            ("224.0.0.1:443", "multicast"),
            ("[ff02::1]:443", "multicast"),
            ("100.64.0.1:443", "100.64.0.0/10"),
            ("198.51.100.7", "port"),
            ("2001:db8::7", "bracket"),
            ("*.example.com", "host name"),
            ("https://a.example", "host name"),
            ("a.example.", "host name"),
            ("under_score.example", "host name"),
            ("", "empty"),
        ] {
            let e = expand(&s(&[entry])).unwrap_err();
            assert!(
                e.contains(&format!("{entry:?}")) && e.to_lowercase().contains(why),
                "{entry}: {e}"
            );
        }
    }

    #[test]
    fn names_a_resolver_could_read_as_ipv4_are_refused() {
        for entry in [
            "127.1",
            "127.1:443",
            "0x7f000001",
            "2130706433:80",
            "a.0x7f",
        ] {
            let e = expand(&s(&[entry])).unwrap_err();
            assert!(
                e.contains(&format!("{entry:?}")) && e.contains("numeric IP"),
                "{entry}: {e}"
            );
        }
        assert!(expand(&s(&["1password.com", "x.0xide"])).is_ok());
    }

    #[test]
    fn more_than_64_entries_after_expansion_is_refused() {
        let at_cap: Vec<String> = (0..57)
            .map(|i| format!("h{i}.example"))
            .chain(["packages".into()])
            .collect();
        assert_eq!(expand(&at_cap).unwrap().len(), 64);
        let over: Vec<String> = at_cap
            .iter()
            .cloned()
            .chain(["one-more.example".into()])
            .collect();
        assert!(expand(&over).unwrap_err().contains("64"));
    }

    #[test]
    fn proxy_env_is_the_guest_proxy_in_both_cases_upper_first() {
        let e = proxy_env();
        assert_eq!(e.len(), 8);
        assert_eq!(e[..4], ["HTTPS_PROXY=http://127.0.0.1:1080", "HTTP_PROXY=http://127.0.0.1:1080", "ALL_PROXY=socks5h://127.0.0.1:1080", "NO_PROXY=localhost,127.0.0.1,::1"]);
        for (upper, lower) in e[..4].iter().zip(&e[4..]) {
            let (uk, uv) = upper.split_once('=').unwrap();
            let (lk, lv) = lower.split_once('=').unwrap();
            assert_eq!((uk.to_lowercase().as_str(), uv), (lk, lv));
        }
    }

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

    // ---- Task 7: post-boot probes ----

    use crate::testutil::{Recorder, reply, run_wrapped_locally};

    fn empty_plan() -> Plan {
        plan(&[], &fake(&[])).unwrap()
    }

    /// The script operand of a probe argv: `sh -c <script> sh <target>`.
    fn script_of(argv: &[String]) -> String {
        assert_eq!(&argv[..2], &["sh".to_string(), "-c".to_string()]);
        argv[2].clone()
    }

    /// A directory holding only a fake `nc` with this body.
    fn fake_nc(tag: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::testutil::tempdir(tag);
        let nc = d.join("nc");
        std::fs::write(&nc, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&nc, std::fs::Permissions::from_mode(0o755)).unwrap();
        d
    }

    /// Run `argv`'s script on the host under `PATH`, through the real guest
    /// wrapper with a 5-second limit, and return (exit code, stdout).
    fn run_script(argv: &[String], path: &str) -> (u32, String) {
        let mut cmd = s(&["env", &format!("PATH={path}"), "/bin/sh", "-c"]);
        cmd.push(script_of(argv));
        cmd.extend(argv[3..].iter().cloned());
        let r = run_wrapped_locally(&cmd, 5, 4096, None);
        (r.exit_code, String::from_utf8(r.stdout).unwrap())
    }

    #[test]
    fn the_deny_all_probe_fails_closed_without_nc_or_on_odd_output() {
        for (stdout, passes) in [
            ("RTS_PROBE unreachable\n", true),
            ("RTS_PROBE no-nc\n", false),
            ("", false),
            ("RTS_PROBE reachable-direct\n", false),
            ("RTS_PROBE reachable-proxy\n", false),
            ("RTS_PROBE unreachable\nRTS_PROBE connected\n", false),
            ("rts_probe unreachable\n", false),
            ("RTS_PROBE unreachable \n", false),
        ] {
            let rec = Recorder::new(move |_, _| reply(0, stdout.as_bytes(), b""));
            let r = run_probes(&rec, &empty_plan());
            assert_eq!(r.is_ok(), passes, "{stdout:?}: {r:?}");
            let execs = rec.execs.lock().unwrap();
            assert_eq!(execs.len(), 1);
            assert_eq!(execs[0].0, deny_all_argv());
            assert_eq!(execs[0].1.timeout_ms, 15_000);
            if passes {
                assert_eq!(
                    r.unwrap(),
                    vec![Probe { target: DENY_ALL_TARGET.into(), result: "unreachable".into() }]
                );
            } else {
                assert!(r.unwrap_err().starts_with("network probe 1.1.1.1:443 failed: "));
            }
        }
    }

    #[test]
    fn a_probe_that_exits_non_zero_or_times_out_fails_even_with_the_marker() {
        for code in [1, 137] {
            let rec = Recorder::new(move |_, _| reply(code, b"RTS_PROBE unreachable\n", b""));
            assert!(run_probes(&rec, &empty_plan()).is_err(), "exit {code}");
            let rec = Recorder::new(move |_, _| reply(code, b"RTS_PROBE connected\n", b""));
            let p = plan(&s(&["198.51.100.7:443"]), &fake(&[])).unwrap();
            assert!(run_probes(&rec, &p).is_err(), "exit {code}");
        }
    }

    #[test]
    fn each_allowed_entry_is_probed_in_order_and_the_first_failure_names_it() {
        let p = plan(
            &s(&["198.51.100.7:443", "198.51.100.8:8443", "198.51.100.9:443"]),
            &fake(&[]),
        )
        .unwrap();
        let rec = Recorder::new(|argv, _| {
            if argv[4] == "198.51.100.8:8443" {
                reply(0, b"RTS_PROBE refused HTTP/1.1 403 Forbidden\n", b"")
            } else {
                reply(0, b"RTS_PROBE connected\n", b"")
            }
        });
        let e = run_probes(&rec, &p).unwrap_err();
        assert!(e.contains("198.51.100.8:8443") && e.contains("refused"), "{e}");
        let execs = rec.execs.lock().unwrap();
        assert_eq!(execs.len(), 2, "stops at the first failure");
        for ((argv, o), target) in execs.iter().zip(["198.51.100.7:443", "198.51.100.8:8443"]) {
            assert_eq!(o.timeout_ms, 15_000);
            assert_eq!(o.max_output_bytes, 4096);
            assert_eq!(argv, &probe_argv(target));
            assert_eq!(argv[4], target);
        }
    }

    #[test]
    fn every_allowed_entry_that_connects_is_recorded_by_its_target() {
        let p = plan(
            &s(&["a.example", "198.51.100.7:8443", "[2001:db8::7]:443"]),
            &fake(&[("a.example", Ok(vec!["198.51.100.1".parse().unwrap()]))]),
        )
        .unwrap();
        let rec = Recorder::new(|_, _| reply(0, b"RTS_PROBE connected\n", b""));
        let probes = run_probes(&rec, &p).unwrap();
        let targets: Vec<&str> = probes.iter().map(|p| p.target.as_str()).collect();
        assert_eq!(targets, ["a.example:443", "198.51.100.7:8443", "[2001:db8::7]:443"]);
        assert!(probes.iter().all(|p| p.result == "connected"));
        assert_eq!(rec.argvs().iter().map(|a| a[4].clone()).collect::<Vec<_>>(), targets);
    }

    #[test]
    fn guest_output_in_a_probe_error_is_escaped_and_capped() {
        let p = plan(&s(&["198.51.100.7:443"]), &fake(&[])).unwrap();
        let long = format!("RTS_PROBE refused \x1b[2J{}\n", "x".repeat(5000));
        let rec = Recorder::new(move |_, _| reply(0, long.as_bytes(), b""));
        let e = run_probes(&rec, &p).unwrap_err();
        assert!(!e.contains('\x1b'), "{e:?}");
        assert!(e.len() < 400, "{}", e.len());
    }

    #[test]
    fn the_probe_script_reports_no_nc_when_nc_is_missing() {
        for argv in [probe_argv("a.example:443"), deny_all_argv()] {
            assert_eq!(run_script(&argv, "/nonexistent"), (0, "RTS_PROBE no-nc\n".into()));
        }
    }

    #[test]
    fn the_probe_takes_the_first_line_without_waiting_for_the_tunnel_to_close() {
        // The proxy answers 200 and then holds the tunnel open, as a real
        // CONNECT does. The probe must not wait for nc to exit.
        let d = fake_nc("probe-200", "printf 'HTTP/1.1 200 Connection established\\r\\n\\r\\n'\nexec sleep 60");
        let path = format!("{}:/usr/bin:/bin", d.display());
        assert_eq!(run_script(&probe_argv("a.example:443"), &path), (0, "RTS_PROBE connected\n".into()));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_probe_reports_a_refusal_with_its_status_line() {
        let d = fake_nc("probe-403", "cat >/dev/null; printf 'HTTP/1.1 403 Forbidden\\r\\n\\r\\n'");
        let path = format!("{}:/usr/bin:/bin", d.display());
        assert_eq!(
            run_script(&probe_argv("a.example:443"), &path),
            (0, "RTS_PROBE refused HTTP/1.1 403 Forbidden\n".into())
        );
        std::fs::remove_dir_all(d).unwrap();
        // Nothing answers at all.
        let d = fake_nc("probe-none", "exit 1");
        let path = format!("{}:/usr/bin:/bin", d.display());
        assert_eq!(run_script(&probe_argv("a.example:443"), &path), (0, "RTS_PROBE refused \n".into()));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_probe_sends_a_connect_for_its_target_to_the_guest_proxy() {
        let d = fake_nc(
            "probe-req",
            "[ \"$*\" = '-w 10 127.0.0.1 1080' ] || exit 1\nIFS= read -r l\n[ \"$l\" = \"$(printf 'CONNECT [2001:db8::7]:443 HTTP/1.1\\r')\" ] || exit 1\nprintf 'HTTP/1.0 200 OK\\r\\n'",
        );
        let path = format!("{}:/usr/bin:/bin", d.display());
        assert_eq!(run_script(&probe_argv("[2001:db8::7]:443"), &path), (0, "RTS_PROBE connected\n".into()));
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_deny_all_script_passes_only_when_neither_path_connects() {
        // $4 is the port: 443 for the direct try, 1080 for the proxy.
        for (body, want) in [
            ("[ \"$4\" = 443 ] && exit 1\nprintf 'HTTP/1.1 403 Forbidden\\r\\n'", "RTS_PROBE unreachable\n"),
            ("exit 1", "RTS_PROBE unreachable\n"),
            ("[ \"$4\" = 443 ] && exit 0\nprintf 'HTTP/1.1 403 Forbidden\\r\\n'", "RTS_PROBE reachable-direct\n"),
            ("[ \"$4\" = 443 ] && exit 1\nprintf 'HTTP/1.1 200 OK\\r\\n'\nexec sleep 60", "RTS_PROBE reachable-proxy\n"),
        ] {
            let d = fake_nc("deny-all", body);
            let path = format!("{}:/usr/bin:/bin", d.display());
            assert_eq!(run_script(&deny_all_argv(), &path), (0, want.into()), "{body}");
            std::fs::remove_dir_all(d).unwrap();
        }
        assert_eq!(deny_all_argv()[4], DENY_ALL_TARGET);
    }
}
