use super::*;
use secrecy::ExposeSecret;
use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn credential() -> InferenceCredential {
    InferenceCredential {
        key: "sk-test-inference-only".to_string().into(),
        organization_id: "org-one".into(),
        workspace_id: "workspace-one".into(),
        key_id: "key-one".into(),
    }
}

#[derive(Default)]
struct MemoryStore(RefCell<Option<String>>);

impl CredentialStore for MemoryStore {
    fn load(&self) -> Result<Option<InferenceCredential>, String> {
        self.0
            .borrow()
            .as_ref()
            .map(|document| storage::decode(document.as_bytes()))
            .transpose()
    }
    fn save(&self, credential: &InferenceCredential) -> Result<(), String> {
        *self.0.borrow_mut() = Some(storage::encode(credential)?.to_string());
        Ok(())
    }
}

struct UnavailableStore;

impl CredentialStore for UnavailableStore {
    fn load(&self) -> Result<Option<InferenceCredential>, String> {
        Err("NEAR AI credential storage unavailable".into())
    }
    fn save(&self, _: &InferenceCredential) -> Result<(), String> {
        Err("NEAR AI credential storage unavailable".into())
    }
}

// Regression: automatic launch must load the existing inference credential,
// never silently start a browser ceremony when OS storage is inaccessible.
#[test]
fn saved_key_launch_fails_closed_on_storage_error_without_opening_browser() {
    let options = LoginOptions::default();
    let result = load_with(&UnavailableStore, &options, || {
        Err("browser must not open".into())
    });
    assert_eq!(
        result.unwrap_err(),
        "NEAR AI credential storage unavailable"
    );
}

#[test]
fn callback_requires_code_and_matching_state_without_legacy_tokens() {
    assert!(decode_callback("state=expected&code=one-time-code", "expected").is_ok());
    for query in [
        "state=wrong&code=code",
        "code=code",
        "state=expected&code=",
        "state=expected&state=expected&code=code",
        "state=expected&code=a&code=b",
        "state=expected&token=legacy",
        "state=expected&code=a&refresh_token=legacy",
        "state=expected&code=a&error=denied",
        "state=expected&code=a&extra=b",
        "state=expected&code=a#token=legacy",
        "state=expected&code=a&error=denied&error=denied",
    ] {
        assert!(
            decode_callback(query, "expected").is_err(),
            "accepted malformed callback"
        );
    }
    assert!(
        decode_callback(
            &format!("state=expected&code={}", "a".repeat(8192)),
            "expected"
        )
        .is_err()
    );
    assert_eq!(
        decode_callback("state=expected&error=access_denied", "expected").unwrap_err(),
        "NEAR AI sign-in failed"
    );
    assert!(decode_callback("error=access_denied", "expected").is_err());
}

#[test]
fn account_selection_refuses_ambiguity_and_unknown_explicit_ids() {
    assert_eq!(
        choose(&["org-one".into()], None, "organization").unwrap(),
        "org-one"
    );
    let ids = ["org-one".into(), "org-two".into()];
    assert!(choose(&ids, None, "organization").is_err());
    assert_eq!(
        choose(&ids, Some("org-two"), "organization").unwrap(),
        "org-two"
    );
    assert!(choose(&ids, Some("unknown"), "organization").is_err());
    assert!(choose(&[], None, "workspace").is_err());
}

#[test]
fn stored_key_round_trip_contains_only_narrow_key_and_launch_does_not_reauthenticate() {
    let store = MemoryStore::default();
    store.save(&credential()).unwrap();
    let loaded = load_with(&store, &LoginOptions::default(), || {
        panic!("browser unexpectedly opened")
    })
    .unwrap();
    assert_eq!(loaded.key.expose_secret(), "sk-test-inference-only");
    assert!(!format!("{loaded:?}").contains("sk-test"));
    let document: serde_json::Value =
        serde_json::from_str(store.0.borrow().as_ref().unwrap()).unwrap();
    let mut keys: Vec<_> = document
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "key",
            "key_id",
            "organization_id",
            "version",
            "workspace_id"
        ]
    );
    assert!(storage::decode(br#"{"version":1,"key":"key","key_id":"k","organization_id":"o","workspace_id":"w","refresh_token":"broader"}"#).is_err());
    assert!(
        storage::decode(
            br#"{"version":1,"key":"","key_id":"k","organization_id":"o","workspace_id":"w"}"#
        )
        .is_err()
    );
    assert!(
        storage::decode(
            br#"{"version":2,"key":"key","key_id":"k","organization_id":"o","workspace_id":"w"}"#
        )
        .is_err()
    );
}

#[test]
fn explicit_account_mismatch_never_silently_uses_saved_key() {
    let store = MemoryStore::default();
    store.save(&credential()).unwrap();
    let options = LoginOptions {
        organization: Some("other-org".into()),
        ..LoginOptions::default()
    };
    assert!(load_with(&store, &options, || panic!("unexpected browser")).is_err());
    assert!(
        validate_options(&LoginOptions {
            organization: Some("../other".into()),
            ..LoginOptions::default()
        })
        .is_err()
    );
}

#[test]
fn native_store_is_unavailable_to_automated_unit_tests() {
    assert!(storage::NativeStore::new().is_err());
}

#[test]
fn callback_timeout_and_cancellation_release_the_listener() {
    let callback = browser::Callback::bind().unwrap();
    let address = url::Url::parse(&callback.url()).unwrap();
    // Keep a server-accepted connection alive through the assertion. Its
    // closing TCP state reserves this local port, so another parallel test
    // cannot recycle it between listener drop and the reconnect check.
    let mut existing = TcpStream::connect(("127.0.0.1", address.port().unwrap())).unwrap();
    write!(
        existing,
        "GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        address.path(),
        address.port().unwrap()
    )
    .unwrap();
    let start = Instant::now();
    assert_eq!(
        callback
            .receive(
                start + Duration::from_millis(50),
                &|| false,
                "expected",
                |_| panic!("no callback expected")
            )
            .unwrap_err(),
        "NEAR AI sign-in timed out"
    );
    // Generous bounds: a loaded CI runner (the 2026-10-30 release dry run)
    // can miss tight ones. The test proves release, not speed.
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(2), "timeout took {elapsed:?}");
    // Parallel tests can be between fork and exec with a transient inherited
    // descriptor. CLOEXEC closes that copy at exec; require bounded release
    // instead of assuming the scheduler has already completed every spawn.
    let endpoint = format!("127.0.0.1:{}", address.port().unwrap())
        .parse()
        .unwrap();
    let released = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect_timeout(&endpoint, Duration::from_millis(10)) {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => break,
            _ if Instant::now() >= released => {
                panic!("callback listener stayed reachable after timeout")
            }
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let mut response = String::new();
    existing.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    let callback = browser::Callback::bind().unwrap();
    assert_eq!(
        callback
            .receive(
                Instant::now() + Duration::from_secs(5),
                &|| true,
                "expected",
                |_| panic!("cancelled")
            )
            .unwrap_err(),
        "NEAR AI sign-in interrupted"
    );
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap()
}

#[test]
fn real_loopback_callback_ignores_spoofs_and_acknowledges_only_after_storage() {
    let callback = browser::Callback::bind().unwrap();
    let url = callback.url();
    let receiver = std::thread::spawn(move || {
        callback.receive(
            Instant::now() + Duration::from_secs(4),
            &|| false,
            "app-state",
            |code| {
                assert_eq!(code.expose_secret(), "one-time-code");
                UnavailableStore.save(&credential())?;
                Ok(credential())
            },
        )
    });
    let client = client();
    for (path, host, expected) in [
        (format!("{url}-wrong?state=app-state&code=code"), None, 404),
        (format!("{url}?state=wrong&code=code"), None, 400),
        (format!("{url}?state=app-state&code=a&code=b"), None, 400),
        (format!("{url}?state=app-state&token=legacy"), None, 400),
        (
            format!("{url}?state=app-state&code=code"),
            Some("attacker.invalid"),
            400,
        ),
    ] {
        let mut request = client.get(path);
        if let Some(host) = host {
            request = request.header("host", host);
        }
        assert_eq!(request.send().unwrap().status(), expected);
    }
    assert_eq!(
        client
            .post(&url)
            .body("state=app-state&token=legacy")
            .send()
            .unwrap()
            .status(),
        400
    );
    let response = client
        .get(format!("{url}?state=app-state&code=one-time-code"))
        .send()
        .unwrap();
    assert_eq!(response.status(), 500);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        receiver.join().unwrap().unwrap_err(),
        "NEAR AI credential storage unavailable"
    );
}

#[test]
fn stalled_callback_connections_cannot_extend_total_deadline() {
    let callback = browser::Callback::bind().unwrap();
    let url = url::Url::parse(&callback.url()).unwrap();
    let mut stream = TcpStream::connect(("127.0.0.1", url.port().unwrap())).unwrap();
    stream.write_all(b"POST /incomplete HTTP/1.1\r\n").unwrap();
    let start = Instant::now();
    assert_eq!(
        callback
            .receive(
                start + Duration::from_millis(60),
                &|| false,
                "expected",
                |_| panic!("no tokens")
            )
            .unwrap_err(),
        "NEAR AI sign-in timed out"
    );
    assert!(start.elapsed() < Duration::from_millis(500));
}

#[test]
fn signal_consumed_during_a_partial_request_still_interrupts_the_ceremony() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let callback = browser::Callback::bind().unwrap();
    let url = url::Url::parse(&callback.url()).unwrap();
    let mut stream = TcpStream::connect(("127.0.0.1", url.port().unwrap())).unwrap();
    stream.write_all(b"POST /partial HTTP/1.1\r\n").unwrap();
    let checks = AtomicUsize::new(0);
    let result = callback.receive(
        Instant::now() + Duration::from_millis(100),
        &|| checks.fetch_add(1, Ordering::SeqCst) == 4,
        "expected",
        |_| panic!("no complete request"),
    );
    assert_eq!(result.unwrap_err(), "NEAR AI sign-in interrupted");
}

struct ApiRequest {
    method: String,
    path: String,
    authorization: String,
    user_agent: String,
    body: serde_json::Value,
}

fn read_api_request(stream: &mut TcpStream) -> ApiRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    let mut bytes = Vec::new();
    let end = loop {
        let mut chunk = [0u8; 4096];
        let count = stream.read(&mut chunk).unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(position) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..end]).unwrap().to_string();
    let mut length = 0;
    let mut authorization = String::new();
    let mut user_agent = String::new();
    for line in headers.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap();
            }
            if key.eq_ignore_ascii_case("user-agent") {
                user_agent = value.trim().into();
            }
            if key.eq_ignore_ascii_case("authorization") {
                authorization = value.trim().into();
            }
        }
    }
    while bytes.len() < end + length {
        let mut chunk = [0u8; 4096];
        let count = stream.read(&mut chunk).unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
    }
    let mut first = headers.lines().next().unwrap().split_whitespace();
    ApiRequest {
        method: first.next().unwrap().into(),
        path: first.next().unwrap().into(),
        authorization,
        user_agent,
        body: if length == 0 {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes[end..end + length]).unwrap()
        },
    }
}

fn mock_api(
    responses: Vec<(&'static str, &'static str)>,
) -> (String, std::thread::JoinHandle<Vec<ApiRequest>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let receiver = std::thread::spawn(move || {
        responses.into_iter().map(|(status, body)| {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_api_request(&mut stream);
        write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        request
    }).collect()
    });
    (origin, receiver)
}

#[test]
fn cloud_mints_only_after_explicit_selected_active_account_and_never_persists_session() {
    let (origin, requests) = mock_api(vec![
        (
            "200 OK",
            r#"{"organizations":[{"id":"org-one","is_active":true},{"id":"org-two","is_active":true}],"total":2,"limit":100,"offset":0}"#,
        ),
        (
            "200 OK",
            r#"{"workspaces":[{"id":"workspace-one","is_active":true}],"total":1,"limit":100,"offset":0}"#,
        ),
        (
            "200 OK",
            r#"{"id":"key-one","workspace_id":"workspace-one","key":"sk-test-inference-only","key_prefix":"sk-test"}"#,
        ),
    ]);
    let api = cloud::CloudApi::for_test(&origin, Instant::now() + Duration::from_secs(4));
    let session: HostSecret = "browser-session-only".to_string().into();
    let result = api
        .mint(
            &session,
            &LoginOptions {
                organization: Some("org-two".into()),
                ..LoginOptions::default()
            },
        )
        .unwrap();
    assert_eq!(result.organization_id, "org-two");
    let store = MemoryStore::default();
    store.save(&result).unwrap();
    assert!(
        !store
            .0
            .borrow()
            .as_ref()
            .unwrap()
            .contains("browser-session-only")
    );
    let requests = requests.join().unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|r| (r.method.as_str(), r.path.as_str()))
            .collect::<Vec<_>>(),
        [
            ("GET", "/v1/organizations?limit=100&offset=0"),
            (
                "GET",
                "/v1/organizations/org-two/workspaces?limit=100&offset=0"
            ),
            ("POST", "/v1/workspaces/workspace-one/api-keys"),
        ]
    );
    assert!(
        requests
            .iter()
            .all(|r| r.authorization == "Bearer browser-session-only")
    );
    assert!(
        requests[2].body["name"]
            .as_str()
            .unwrap()
            .starts_with("nearai-red-sandbox-")
    );
    assert_eq!(requests[2].body.as_object().unwrap().len(), 1);
}

#[test]
fn account_ambiguity_on_later_pages_does_not_mint_a_key() {
    let (origin, requests) = mock_api(vec![
        (
            "200 OK",
            r#"{"organizations":[{"id":"org-one","is_active":true}],"total":2,"limit":1,"offset":0}"#,
        ),
        (
            "200 OK",
            r#"{"organizations":[{"id":"org-two","is_active":true}],"total":2,"limit":1,"offset":1}"#,
        ),
    ]);
    let api = cloud::CloudApi::for_test(&origin, Instant::now() + Duration::from_secs(4));
    assert!(
        api.mint(&"session".to_string().into(), &LoginOptions::default())
            .unwrap_err()
            .contains("--organization")
    );
    assert_eq!(requests.join().unwrap().len(), 2);
}

#[test]
fn cloud_errors_are_redacted_and_redirects_are_not_followed() {
    for status in ["401 Unauthorized", "302 Found", "500 Internal Server Error"] {
        let (origin, requests) =
            mock_api(vec![(status, r#"{"detail":"do-not-leak-provider-body"}"#)]);
        let api = cloud::CloudApi::for_test(&origin, Instant::now() + Duration::from_secs(4));
        let error = api
            .mint(
                &"session-secret".to_string().into(),
                &LoginOptions::default(),
            )
            .unwrap_err();
        assert!(!error.contains("do-not-leak-provider-body"));
        assert!(!error.contains("session-secret"));
        assert_eq!(requests.join().unwrap().len(), 1);
    }
}

#[test]
fn authorization_uses_exact_cloud_origin_and_escaped_bare_callback() {
    let api = cloud::CloudApi::live(Instant::now() + Duration::from_secs(1)).unwrap();
    let callback = "http://127.0.0.1:43210/rts/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/callback";
    let proof = pkce::Pkce::generate().unwrap();
    for (provider, path) in [
        (Provider::Github, "/v1/auth/github"),
        (Provider::Google, "/v1/auth/google"),
    ] {
        let url = url::Url::parse(&api.authorize_url(provider, callback, &proof).unwrap()).unwrap();
        assert_eq!(
            url.origin().ascii_serialization(),
            "https://cloud-platform.near.ai"
        );
        assert_eq!(url.path(), path);
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            [
                ("frontend_callback".into(), callback.into()),
                ("client_id".into(), "red-sandbox".into()),
                ("code_challenge".into(), proof.challenge().into()),
                ("code_challenge_method".into(), "S256".into()),
                ("state".into(), proof.state.clone().into()),
            ]
        );
    }
    for callback in [
        "http://127.0.0.1:9123/callback?state=a",
        "https://127.0.0.1:9123/callback",
        "http://attacker.invalid:9123/callback",
        "http://127.0.0.1:9123/callback#frag",
        "http://127.0.0.1:9123/rts/short/callback",
        "http://127.0.0.1:9123/rts/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/callback/",
        "http://127.0.0.1:9123/rts/%300123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/callback",
    ] {
        assert!(
            api.authorize_url(Provider::Github, callback, &proof)
                .is_err()
        );
    }
}

#[test]
fn native_redemption_sends_only_the_bound_proof_and_receives_session_over_http() {
    let (origin, requests) = mock_api(vec![(
        "200 OK",
        r#"{"access_token":"session-only","refresh_token":"discard-refresh","refresh_token_expiration":"later","user":{}}"#,
    )]);
    let api = cloud::CloudApi::for_test(&origin, Instant::now() + Duration::from_secs(4));
    let proof = pkce::Pkce::generate().unwrap();
    let redirect = "http://127.0.0.1:1234/rts/test/callback";
    let session = api
        .redeem(&"one-time-code".to_string().into(), &proof, redirect)
        .unwrap();
    assert_eq!(session.expose_secret(), "session-only");
    let requests = requests.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/v1/auth/native/token");
    assert!(requests[0].authorization.is_empty());
    assert_eq!(requests[0].user_agent, "nearai-red-sandbox/0.1");
    assert_eq!(
        requests[0].body,
        serde_json::json!({"grant_type":"authorization_code", "client_id":"red-sandbox", "code":"one-time-code", "code_verifier":proof.verifier(), "redirect_uri":redirect})
    );
}

#[test]
fn redemption_errors_and_legacy_responses_never_fall_back_or_leak() {
    for (status, body) in [
        (
            "400 Bad Request",
            r#"{"error":"invalid_grant","detail":"secret"}"#,
        ),
        ("404 Not Found", "secret"),
        ("302 Found", "secret"),
        (
            "200 OK",
            r#"{"token":"legacy-token","refresh_token":"secret"}"#,
        ),
        ("200 OK", r#"{"access_token":"","refresh_token":"secret"}"#),
    ] {
        let (origin, requests) = mock_api(vec![(status, body)]);
        let api = cloud::CloudApi::for_test(&origin, Instant::now() + Duration::from_secs(4));
        let proof = pkce::Pkce::generate().unwrap();
        let error = api
            .redeem(
                &"code-secret".to_string().into(),
                &proof,
                "http://127.0.0.1:1234/rts/test/callback",
            )
            .unwrap_err();
        for secret in ["code-secret", "legacy-token", "secret", proof.verifier()] {
            assert!(!error.contains(secret));
        }
        assert_eq!(requests.join().unwrap().len(), 1);
    }
}

#[test]
fn a_successful_callback_completes_only_once_and_legacy_fragment_cannot_complete() {
    let callback = browser::Callback::bind().unwrap();
    let url = callback.url();
    let receiver = std::thread::spawn(move || {
        callback.receive(
            Instant::now() + Duration::from_secs(4),
            &|| false,
            "expected",
            |code| {
                assert_eq!(code.expose_secret(), "only-code");
                Ok(credential())
            },
        )
    });
    let client = client();
    // A browser never transmits fragments: an old server's bearer-token
    // redirect reaches only the bare callback and is refused there.
    assert_eq!(
        client
            .get(format!("{url}#token=legacy&refresh_token=legacy"))
            .send()
            .unwrap()
            .status(),
        400
    );
    let response = client
        .get(format!("{url}?code=only-code&state=expected"))
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(receiver.join().unwrap().unwrap().key_id, "key-one");
    assert!(
        client
            .get(format!("{url}?code=only-code&state=expected"))
            .send()
            .is_err()
    );
}
