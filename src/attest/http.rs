//! The HTTP and clock seams for attestation. Everything that reaches Intel
//! PCS or NEAR AI for attestation goes through [`Http`], and every time check
//! reads [`Clock`], so tests run offline at a fixed time.

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ironwire_proxy::embed::HostSecret;
use secrecy::ExposeSecret;

/// Largest response body read from an attestation endpoint.
const BODY_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first header with this name, compared ASCII case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub trait Http: Send + Sync {
    fn get(&self, url: &str, bearer: Option<&HostSecret>) -> Result<HttpResponse, String>;
    fn post_json(&self, url: &str, body: &[u8]) -> Result<HttpResponse, String>;
}

/// Blocking client: 30 s timeout, no redirects, no proxy, 16 MiB body cap.
pub struct BlockingHttp {
    client: reqwest::blocking::Client,
}

impl BlockingHttp {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("attestation HTTP client: {e}"))?;
        Ok(Self { client })
    }

    fn send(
        &self,
        url: &str,
        req: reqwest::blocking::RequestBuilder,
    ) -> Result<HttpResponse, String> {
        // reqwest's error text names the URL, never request headers, so a
        // bearer cannot leak through it.
        let resp = req.send().map_err(|e| format!("{url}: {e}"))?;
        let status = resp.status().as_u16();
        // A header value that is not visible ASCII is dropped; a check that
        // needs it then fails as missing.
        let headers = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
            .collect();
        let mut body = Vec::new();
        resp.take(BODY_LIMIT + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("{url}: reading body: {e}"))?;
        if body.len() as u64 > BODY_LIMIT {
            return Err(format!("{url}: response body exceeds {BODY_LIMIT} bytes"));
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

impl Http for BlockingHttp {
    fn get(&self, url: &str, bearer: Option<&HostSecret>) -> Result<HttpResponse, String> {
        let mut req = self.client.get(url);
        if let Some(secret) = bearer {
            req = req.bearer_auth(secret.expose_secret());
        }
        self.send(url, req)
    }

    fn post_json(&self, url: &str, body: &[u8]) -> Result<HttpResponse, String> {
        let req = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec());
        self.send(url, req)
    }
}

pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        // A clock before 1970 reads as 0, which every validity window refuses.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[cfg(test)]
pub use fake::{FakeHttp, FixedClock};

#[cfg(test)]
mod fake {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Canned responses keyed by "GET <url>" / "POST <url>"; records calls.
    #[derive(Default)]
    pub struct FakeHttp {
        routes: Mutex<HashMap<String, HttpResponse>>,
        calls: Mutex<Vec<String>>,
        bodies: Mutex<Vec<Vec<u8>>>,
        bearers: Mutex<Vec<bool>>,
    }

    impl FakeHttp {
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        pub fn route(&self, method: &str, url: &str, r: HttpResponse) {
            self.routes
                .lock()
                .unwrap()
                .insert(format!("{method} {url}"), r);
        }

        /// "GET <url>" in call order.
        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        /// POST bodies in call order.
        pub fn bodies(&self) -> Vec<Vec<u8>> {
            self.bodies.lock().unwrap().clone()
        }

        /// Whether each call carried a bearer.
        pub fn bearers(&self) -> Vec<bool> {
            self.bearers.lock().unwrap().clone()
        }

        fn answer(&self, key: String, bearer: bool) -> Result<HttpResponse, String> {
            self.calls.lock().unwrap().push(key.clone());
            self.bearers.lock().unwrap().push(bearer);
            self.routes
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("no route: {key}"))
        }
    }

    impl Http for FakeHttp {
        fn get(&self, url: &str, bearer: Option<&HostSecret>) -> Result<HttpResponse, String> {
            self.answer(format!("GET {url}"), bearer.is_some())
        }

        fn post_json(&self, url: &str, body: &[u8]) -> Result<HttpResponse, String> {
            self.bodies.lock().unwrap().push(body.to_vec());
            self.answer(format!("POST {url}"), false)
        }
    }

    pub struct FixedClock(pub u64);

    impl Clock for FixedClock {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }
}
