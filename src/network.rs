//! Sandbox network allowlist entries: parsing, preset expansion and validation.
//!
//! This module is pure: nothing here resolves a name or touches the network.
//! Every check fails closed and names the entry as the operator wrote it.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
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
