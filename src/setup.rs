//! `rts setup` downloads: fetch over an exact GitHub host allowlist, check the
//! pinned digest, unpack into a temp directory beside the target, and rename
//! it into place. Nothing unverified or partially unpacked is ever left at
//! the target path.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};
use url::Url;

use crate::install::MVM_VERSION;
use crate::mvm::tail;
use crate::session::{Host, OPENCODE_VERSION};

pub const ALLOWED_HOSTS: [&str; 3] = ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];
pub const MAX_REDIRECTS: usize = 5;

const CHUNK: usize = 64 * 1024;
const UNPACK_TIMEOUT: Duration = Duration::from_secs(600);
const TEMP_PREFIX: &str = ".rts-setup-";

/// `url` parsed, when it is `https`, its host is exactly one of
/// `ALLOWED_HOSTS` (not a suffix match), it names no port other than 443 and
/// it carries no userinfo.
pub fn allowed_url(url: &str) -> Result<Url, String> {
    let u = Url::parse(url).map_err(|e| format!("{url}: not a valid URL: {e}"))?;
    if u.scheme() != "https" {
        return Err(format!("{url}: only https downloads are allowed"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(format!("{url}: a download URL may not carry a user name or password"));
    }
    // `Url` drops the scheme's default port, so `:443` reads as None here.
    if let Some(port) = u.port() {
        return Err(format!("{url}: port {port} is not allowed (only 443)"));
    }
    match u.host() {
        Some(url::Host::Domain(h)) if ALLOWED_HOSTS.contains(&h) => Ok(u),
        _ => Err(format!("{url}: host is not one of {}", ALLOWED_HOSTS.join(", "))),
    }
}

/// One fetch, no redirects followed: the caller checks each hop.
pub enum Hop {
    Redirect(String),
    Body(Box<dyn Read + Send>),
}

pub trait Fetch: Send + Sync {
    fn get(&self, url: &Url) -> Result<Hop, String>;
}

pub struct HttpsFetch {
    client: reqwest::blocking::Client,
}

impl HttpsFetch {
    /// No redirects followed (`download` checks each hop), https only,
    /// 30 s to connect, 600 s per request including the body.
    pub fn new() -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(600))
            .https_only(true)
            .build()
            .map_err(|e| format!("building the HTTPS client: {e}"))?;
        Ok(Self { client })
    }
}

impl Fetch for HttpsFetch {
    fn get(&self, url: &Url) -> Result<Hop, String> {
        let resp = self.client.get(url.clone()).send().map_err(|e| format!("GET {url}: {e}; check the network and re-run rts setup"))?;
        let status = resp.status();
        if status.is_redirection() {
            let location = resp.headers().get(reqwest::header::LOCATION).map(|v| v.to_str().map_err(|_| format!("GET {url}: {status} with a non-ASCII Location"))).transpose()?;
            return redirect_target(url, location).map(Hop::Redirect);
        }
        if status.is_success() {
            return Ok(Hop::Body(Box::new(resp)));
        }
        Err(format!("GET {url}: HTTP {status}; check the network and re-run rts setup"))
    }
}

/// A redirect's `Location`, resolved against the URL that returned it.
fn redirect_target(url: &Url, location: Option<&str>) -> Result<String, String> {
    let loc = location.ok_or_else(|| format!("GET {url}: redirect without a Location header"))?;
    url.join(loc).map(String::from).map_err(|e| format!("GET {url}: bad redirect Location {loc:?}: {e}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downloaded {
    pub sha256: String,
    pub bytes: u64,
}

/// Fetch `url`, following at most `MAX_REDIRECTS` redirects, each checked with
/// `allowed_url` before it is fetched, and stream the body into `out` and a
/// SHA-256, refusing more than `max_bytes`.
pub fn download(f: &dyn Fetch, url: &str, max_bytes: u64, out: &mut dyn Write) -> Result<Downloaded, String> {
    let mut current = allowed_url(url)?;
    let mut redirects = 0;
    let mut body = loop {
        match f.get(&current)? {
            Hop::Body(b) => break b,
            Hop::Redirect(to) => {
                redirects += 1;
                if redirects > MAX_REDIRECTS {
                    return Err(format!("{url}: more than {MAX_REDIRECTS} redirects"));
                }
                current = allowed_url(&to).map_err(|e| format!("{url} redirected to a URL that is not allowed: {e}"))?;
            }
        }
    };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total: u64 = 0;
    loop {
        let n = match body.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("reading {url}: {e}; re-run rts setup")),
        };
        total += n as u64;
        if total > max_bytes {
            return Err(format!("{url} exceeds {max_bytes} bytes"));
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(|e| format!("writing the download of {url}: {e}"))?;
    }
    Ok(Downloaded { sha256: hex(&hasher.finalize()), bytes: total })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unpack {
    TarGzStrip1,
    Zip,
}

#[derive(Debug, Clone)]
pub struct Component {
    pub name: &'static str,
    pub version: &'static str,
    pub url: String,
    pub sha256: String,
    pub max_bytes: u64,
    pub unpack: Unpack,
    pub binary: &'static str,
}

pub fn mvm() -> Component {
    Component {
        name: "mvm",
        version: MVM_VERSION,
        url: format!("https://github.com/tinylabscom/mvm/releases/download/v{MVM_VERSION}/mvmctl-aarch64-apple-darwin.tar.gz"),
        sha256: "1f2c80b253add28c3856080e3f3a10aa1163f1aef0a7d413ded15100bdcd0c69".into(),
        max_bytes: 64 << 20,
        unpack: Unpack::TarGzStrip1,
        binary: "mvmctl",
    }
}

pub fn opencode() -> Component {
    Component {
        name: "opencode",
        version: OPENCODE_VERSION,
        url: format!("https://github.com/anomalyco/opencode/releases/download/v{OPENCODE_VERSION}/opencode-darwin-arm64.zip"),
        sha256: "c1c901a6379d667b7a30a3eea5a8f6e93416dba43e889e834771f6fb174f35c9".into(),
        max_bytes: 256 << 20,
        unpack: Unpack::Zip,
        binary: "opencode",
    }
}

/// Download, check the digest, unpack into `<parent>/.rts-setup-XXXX/unpacked`,
/// check `binary`, rename to `target`.
/// Errs when `target` exists: the caller decides to skip or refuse it.
pub fn install_component(c: &Component, target: &Path, f: &dyn Fetch, host: &dyn Host) -> Result<(), String> {
    let label = format!("{} {}", c.name, c.version);
    let parent = target.parent().ok_or_else(|| format!("{label}: {} has no parent directory", target.display()))?;
    if parent.exists() {
        remove_stale_temp_dirs(parent).map_err(|e| format!("{label}: {e}"))?;
    } else {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().recursive(true).mode(0o700).create(parent).map_err(|e| format!("{label}: creating {}: {e}", parent.display()))?;
    }
    let exists = || fs::symlink_metadata(target).is_ok();
    if exists() {
        return Err(format!("{} already exists", target.display()));
    }
    let tmp = tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempdir_in(parent)
        .map_err(|e| format!("{label}: creating a temp directory in {}: {e}", parent.display()))?;
    let download_path = tmp.path().join("download");
    let unpacked = tmp.path().join("unpacked");

    let got = {
        let mut file = fs::File::create(&download_path).map_err(|e| format!("{label}: creating {}: {e}", download_path.display()))?;
        let d = download(f, &c.url, c.max_bytes, &mut file).map_err(|e| format!("{label}: {e}; nothing was installed"))?;
        file.sync_all().map_err(|e| format!("{label}: writing {}: {e}", download_path.display()))?;
        d
    };
    if !got.sha256.eq_ignore_ascii_case(&c.sha256) {
        let _ = fs::remove_file(&download_path);
        return Err(format!("{label}: sha256 mismatch for {}: expected {}, got {}; nothing was installed", c.url, c.sha256, got.sha256));
    }

    fs::create_dir(&unpacked).map_err(|e| format!("{label}: creating {}: {e}", unpacked.display()))?;
    let (dl, un) = (download_path.to_string_lossy().into_owned(), unpacked.to_string_lossy().into_owned());
    let argv: Vec<String> = match c.unpack {
        Unpack::TarGzStrip1 => vec!["/usr/bin/tar".into(), "-xzf".into(), dl, "-C".into(), un, "--strip-components".into(), "1".into()],
        Unpack::Zip => vec!["/usr/bin/ditto".into(), "-x".into(), "-k".into(), dl, un],
    };
    let tool = argv[0].clone();
    let out = host.run(&argv, UNPACK_TIMEOUT).map_err(|e| format!("{label}: running {tool}: {e}; nothing was installed"))?;
    if out.killed || out.code != Some(0) {
        let how = if out.killed { "was killed".to_string() } else { format!("exited with {:?}", out.code) };
        return Err(format!("{label}: {tool} {how} unpacking {}: {}; nothing was installed", c.url, tail(&out.stderr)));
    }

    let binary = unpacked.join(c.binary);
    if !fs::symlink_metadata(&binary).map(|m| m.is_file()).unwrap_or(false) {
        return Err(format!("{label}: {} does not contain a regular file {}; nothing was installed", c.url, c.binary));
    }
    if exists() {
        return Err(format!("{} already exists", target.display()));
    }
    fs::rename(&unpacked, target).map_err(|e| format!("{label}: moving {} to {}: {e}; nothing was installed", unpacked.display(), target.display()))?;
    // `tmp` drops here and removes the download.
    Ok(())
}

/// Remove `.rts-setup-*` directories (never files or symlinks) a killed run
/// left in `parent`.
fn remove_stale_temp_dirs(parent: &Path) -> Result<(), String> {
    let entries = fs::read_dir(parent).map_err(|e| format!("reading {}: {e}", parent.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading {}: {e}", parent.display()))?;
        if !entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            continue;
        }
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            let path = entry.path();
            fs::remove_dir_all(&path).map_err(|e| format!("removing the stale {}: {e}; remove it and re-run rts setup", path.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
enum FakeHop {
    Body(Vec<u8>),
    Redirect(String),
}

/// A `Fetch` that answers from a table and records every URL it was asked for.
#[cfg(test)]
#[derive(Default)]
pub struct FakeFetch {
    hops: std::sync::Mutex<std::collections::HashMap<String, FakeHop>>,
    calls: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl FakeFetch {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn body(&self, url: &str, bytes: Vec<u8>) {
        self.hops.lock().unwrap().insert(url.to_string(), FakeHop::Body(bytes));
    }
    pub fn redirect(&self, url: &str, to: &str) {
        self.hops.lock().unwrap().insert(url.to_string(), FakeHop::Redirect(to.to_string()));
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl Fetch for FakeFetch {
    fn get(&self, url: &Url) -> Result<Hop, String> {
        self.calls.lock().unwrap().push(url.as_str().to_string());
        match self.hops.lock().unwrap().get(url.as_str()) {
            Some(FakeHop::Body(b)) => Ok(Hop::Body(Box::new(io::Cursor::new(b.clone())))),
            Some(FakeHop::Redirect(to)) => Ok(Hop::Redirect(to.clone())),
            None => Err(format!("FakeFetch: no response for {url}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mvm::RunOutput;
    use crate::session::RealHost;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    fn sha256_hex(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }

    fn run(cmd: &mut Command) {
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "{cmd:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// A tar.gz of `top/<binary>` (a two-line shell script), built with the real tar.
    fn tarball(dir: &Path, binary: &str) -> Vec<u8> {
        let src = dir.join("src-tar");
        fs::create_dir_all(src.join("top")).unwrap();
        let bin = src.join("top").join(binary);
        fs::write(&bin, "#!/bin/sh\necho fixture\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let out = dir.join("fixture.tar.gz");
        run(Command::new("/usr/bin/tar").arg("-czf").arg(&out).arg("-C").arg(&src).arg("top"));
        fs::read(out).unwrap()
    }

    /// A zip holding one entry, `opencode`, built with the real ditto.
    fn zip(dir: &Path) -> Vec<u8> {
        let src = dir.join("src-zip");
        fs::create_dir_all(&src).unwrap();
        let bin = src.join("opencode");
        fs::write(&bin, "#!/bin/sh\necho fixture\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let out = dir.join("fixture.zip");
        run(Command::new("/usr/bin/ditto").args(["-c", "-k"]).arg(&bin).arg(&out));
        fs::read(out).unwrap()
    }

    struct Rig {
        _dir: tempfile::TempDir,
        parent: PathBuf,
        target: PathBuf,
        fetch: FakeFetch,
        c: Component,
        digest: String,
    }

    fn rig_with(archive: impl FnOnce(&Path) -> Vec<u8>, name: &'static str, unpack: Unpack, binary: &'static str) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let bytes = archive(dir.path());
        let digest = sha256_hex(&bytes);
        let url = format!("https://github.com/x/{name}");
        let fetch = FakeFetch::new();
        fetch.body(&url, bytes);
        let parent = dir.path().join("home/.local/mvm");
        let target = parent.join("v0.22.0");
        let c = Component { name, version: "0.0.1", url, sha256: digest.clone(), max_bytes: 1 << 20, unpack, binary };
        Rig { _dir: dir, parent, target, fetch, c, digest }
    }

    fn tar_rig() -> Rig {
        rig_with(|d| tarball(d, "mvmctl"), "mvm", Unpack::TarGzStrip1, "mvmctl")
    }

    fn leftovers(parent: &Path) -> Vec<String> {
        let Ok(rd) = fs::read_dir(parent) else { return Vec::new() };
        rd.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with(TEMP_PREFIX)).collect()
    }

    #[test]
    fn allowed_urls_are_exact() {
        for ok in ["https://github.com/a/b", "https://objects.githubusercontent.com/x", "https://release-assets.githubusercontent.com/x?sig=1", "https://github.com:443/a"] {
            assert!(allowed_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://github.com/a",
            "https://evil.example/a",
            "https://github.com.evil.example/a",
            "https://evilgithub.com/a",
            "https://sub.github.com/a",
            "https://github.com:8443/a",
            "https://u:p@github.com/a",
            "https://u@github.com/a",
            "https://github.com./a",
            "https://140.82.112.3/a",
            "file:///etc/passwd",
            "not a url",
        ] {
            let e = allowed_url(bad).unwrap_err();
            assert!(e.contains(bad), "{bad}: {e}");
        }
    }

    #[test]
    fn the_first_url_is_checked_before_it_is_fetched() {
        let f = FakeFetch::new();
        f.body("http://github.com/x/mvm", b"x".to_vec());
        assert!(download(&f, "http://github.com/x/mvm", 1 << 20, &mut Vec::new()).is_err());
        assert!(f.calls().is_empty());
    }

    #[test]
    fn a_redirect_to_an_unlisted_host_fails_before_it_is_fetched() {
        let f = FakeFetch::new();
        f.redirect("https://github.com/x/mvm", "https://evil.example/m");
        f.body("https://evil.example/m", b"x".to_vec());
        let e = download(&f, "https://github.com/x/mvm", 1 << 20, &mut Vec::new()).unwrap_err();
        assert!(e.contains("evil.example"), "{e}");
        assert_eq!(f.calls(), ["https://github.com/x/mvm"]);
    }

    #[test]
    fn redirects_within_the_allowlist_are_followed_up_to_five() {
        let f = FakeFetch::new();
        // r0 -> r1 -> ... -> r5 alternate between two allowed hosts; r5 is the body.
        for i in 0..MAX_REDIRECTS {
            let host = |j: usize| if j.is_multiple_of(2) { "github.com" } else { "release-assets.githubusercontent.com" };
            f.redirect(&format!("https://{}/r{i}", host(i)), &format!("https://{}/r{}", host(i + 1), i + 1));
        }
        f.body("https://release-assets.githubusercontent.com/r5", b"hello".to_vec());
        let mut out = Vec::new();
        let d = download(&f, "https://github.com/r0", 1 << 20, &mut out).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(d, Downloaded { sha256: sha256_hex(b"hello"), bytes: 5 });
        assert_eq!(f.calls().len(), 6);

        let f = FakeFetch::new();
        for i in 0..=MAX_REDIRECTS {
            f.redirect(&format!("https://github.com/r{i}"), &format!("https://github.com/r{}", i + 1));
        }
        f.body("https://github.com/r6", b"hello".to_vec());
        let e = download(&f, "https://github.com/r0", 1 << 20, &mut Vec::new()).unwrap_err();
        assert!(e.contains("redirects"), "{e}");
        assert!(!f.calls().contains(&"https://github.com/r6".to_string()), "{:?}", f.calls());
    }

    #[test]
    fn an_oversized_body_fails() {
        let f = FakeFetch::new();
        f.body("https://github.com/x/big", vec![7; 1025]);
        let mut out = Vec::new();
        let e = download(&f, "https://github.com/x/big", 1024, &mut out).unwrap_err();
        assert!(e.contains("exceeds 1024 bytes") && e.contains("https://github.com/x/big"), "{e}");
        assert!(out.len() <= 1024);

        f.body("https://github.com/x/fits", vec![7; 1024]);
        assert_eq!(download(&f, "https://github.com/x/fits", 1024, &mut Vec::new()).unwrap().bytes, 1024);
    }

    #[test]
    fn a_large_body_is_hashed_across_chunks() {
        let body: Vec<u8> = (0..(3 * CHUNK + 17)).map(|i| (i % 251) as u8).collect();
        let f = FakeFetch::new();
        f.body("https://github.com/x/large", body.clone());
        let mut out = Vec::new();
        let d = download(&f, "https://github.com/x/large", 1 << 20, &mut out).unwrap();
        assert_eq!(out, body);
        assert_eq!(d.sha256, sha256_hex(&body));
    }

    #[test]
    fn a_relative_location_is_resolved_against_the_url() {
        let u = Url::parse("https://github.com/a/b/c").unwrap();
        assert_eq!(redirect_target(&u, Some("/x/y")).unwrap(), "https://github.com/x/y");
        assert_eq!(redirect_target(&u, Some("https://objects.githubusercontent.com/z?s=1")).unwrap(), "https://objects.githubusercontent.com/z?s=1");
        let e = redirect_target(&u, None).unwrap_err();
        assert!(e.contains("https://github.com/a/b/c") && e.contains("Location"), "{e}");
    }

    #[test]
    fn the_https_client_builds() {
        assert!(HttpsFetch::new().is_ok());
    }

    #[test]
    fn a_digest_mismatch_deletes_the_download_and_installs_nothing() {
        let mut r = tar_rig();
        r.c.sha256 = "00".repeat(32);
        let e = install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap_err();
        assert!(e.contains(&"00".repeat(32)) && e.contains(&r.digest) && e.contains("sha256 mismatch") && e.contains(&r.c.url), "{e}");
        assert!(e.contains("nothing was installed"), "{e}");
        assert!(!r.target.exists());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
    }

    #[test]
    fn a_tarball_is_unpacked_flat_and_renamed_into_place() {
        let r = tar_rig();
        install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap();
        let bin = r.target.join("mvmctl");
        let meta = fs::symlink_metadata(&bin).unwrap();
        assert!(meta.is_file());
        assert_ne!(meta.permissions().mode() & 0o111, 0, "not executable");
        assert!(!r.target.join("top").exists());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
        assert_eq!(fs::metadata(&r.parent).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn a_zip_is_unpacked_with_ditto() {
        let r = rig_with(zip, "opencode", Unpack::Zip, "opencode");
        install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap();
        assert!(fs::symlink_metadata(r.target.join("opencode")).unwrap().is_file());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
    }

    /// tar writes a partial file into the unpack directory, then is killed.
    struct KillingHost;
    impl Host for KillingHost {
        fn run(&self, argv: &[String], _timeout: Duration) -> io::Result<RunOutput> {
            assert_eq!(argv[0], "/usr/bin/tar");
            assert_eq!(argv[3], "-C");
            fs::write(Path::new(&argv[4]).join("partial"), b"half").unwrap();
            Ok(RunOutput { code: None, stdout: Vec::new(), stderr: b"tar: interrupted".to_vec(), killed: true })
        }
    }

    #[test]
    fn an_interrupted_unpack_leaves_no_partial_version() {
        let r = tar_rig();
        let e = install_component(&r.c, &r.target, &r.fetch, &KillingHost).unwrap_err();
        assert!(e.contains("tar: interrupted"), "{e}");
        assert!(!r.target.exists());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
    }

    #[test]
    fn a_failing_unpack_reports_the_tools_stderr() {
        let r = tar_rig();
        let f = FakeFetch::new();
        let mut c = r.c.clone();
        f.body(&c.url, b"not a tarball".to_vec());
        c.sha256 = sha256_hex(b"not a tarball");
        let e = install_component(&c, &r.target, &f, &RealHost).unwrap_err();
        assert!(e.contains("/usr/bin/tar") && e.contains("nothing was installed"), "{e}");
        assert!(!r.target.exists());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
    }

    #[test]
    fn a_stale_temp_dir_from_a_killed_run_is_removed() {
        let r = tar_rig();
        fs::create_dir_all(r.parent.join(".rts-setup-old/unpacked")).unwrap();
        fs::write(r.parent.join(".rts-setup-old/unpacked/mvmctl"), b"stale").unwrap();
        fs::write(r.parent.join("keep-me"), b"keep").unwrap();
        fs::write(r.parent.join(".rts-setup-a-file"), b"not a directory").unwrap();
        install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap();
        assert!(!r.parent.join(".rts-setup-old").exists());
        assert!(r.parent.join("keep-me").exists());
        assert!(r.parent.join(".rts-setup-a-file").exists());
        assert!(r.target.join("mvmctl").is_file());
    }

    #[test]
    fn an_archive_without_the_binary_is_refused() {
        let r = rig_with(|d| tarball(d, "other"), "mvm", Unpack::TarGzStrip1, "mvmctl");
        let e = install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap_err();
        assert!(e.contains("mvmctl") && e.contains(&r.c.url), "{e}");
        assert!(!r.target.exists());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
    }

    #[test]
    fn an_existing_target_is_not_replaced() {
        let r = tar_rig();
        fs::create_dir_all(&r.target).unwrap();
        fs::write(r.target.join("mine"), b"x").unwrap();
        let e = install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap_err();
        assert!(e.contains(&format!("{} already exists", r.target.display())), "{e}");
        assert!(r.target.join("mine").exists());
        assert!(r.fetch.calls().is_empty(), "downloaded anyway");
    }

    #[test]
    fn the_pinned_components_match_the_spec() {
        let (m, o) = (mvm(), opencode());
        assert_eq!(m.url, "https://github.com/tinylabscom/mvm/releases/download/v0.22.0/mvmctl-aarch64-apple-darwin.tar.gz");
        assert_eq!(o.url, "https://github.com/anomalyco/opencode/releases/download/v2.2.2/opencode-darwin-arm64.zip");
        assert_eq!(m.sha256, "1f2c80b253add28c3856080e3f3a10aa1163f1aef0a7d413ded15100bdcd0c69");
        assert_eq!(o.sha256, "c1c901a6379d667b7a30a3eea5a8f6e93416dba43e889e834771f6fb174f35c9");
        assert!(allowed_url(&m.url).is_ok() && allowed_url(&o.url).is_ok());
        assert_eq!((m.max_bytes, o.max_bytes), (64 << 20, 256 << 20));
        assert_eq!((m.name, m.version, m.unpack, m.binary), ("mvm", "0.22.0", Unpack::TarGzStrip1, "mvmctl"));
        assert_eq!((o.name, o.version, o.unpack, o.binary), ("opencode", "2.2.2", Unpack::Zip, "opencode"));
    }
}
