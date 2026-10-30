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
}
