//! NEAR AI's attestation report and the pure checks on its entries: the
//! report URL, report_data binding, the compose hash, and the model signing
//! key. Shape from `nearai-cloud-verifier` `ts/model_verifier.ts`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ComposePolicy, Match, Policy, Role};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReportResponse {
    pub gateway_attestation: Option<Evidence>,
    pub model_attestations: Option<Vec<Evidence>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Evidence {
    pub intel_quote: String,
    pub signing_address: String,
    pub signing_algo: String,
    pub tls_cert_fingerprint: Option<String>,
    pub nvidia_payload: Option<String>,
    pub info: Option<serde_json::Value>,
    pub model_name: Option<String>,
}

/// `{base}/attestation/report?model=..&nonce=..&signing_algo=ed25519&provider=near&include_tls_fingerprint=true`.
pub fn report_url(base: &str, model: &str, nonce: &[u8; 32]) -> String {
    let model: String = url::form_urlencoded::byte_serialize(model.as_bytes()).collect();
    format!(
        "{}/attestation/report?model={model}&nonce={}&signing_algo=ed25519&provider=near&include_tls_fingerprint=true",
        base.trim_end_matches('/'),
        hex::encode(nonce)
    )
}

/// Exactly 64 hex digits as 32 bytes.
pub fn hex32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|_| "expected 64 hex digits".to_string())?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("expected 32 bytes, got {}", bytes.len()))
}

/// ed25519 only for model entries: `signing_algo == "ed25519"` and a 32-byte hex key.
pub fn ed25519_key(e: &Evidence) -> Result<[u8; 32], String> {
    if e.signing_algo != "ed25519" {
        return Err(format!(
            "signing_algo is {:?}; model entries must be ed25519",
            e.signing_algo
        ));
    }
    hex32(&e.signing_address).map_err(|err| format!("ed25519 signing_address: {err}"))
}

/// `signing_address` as bytes; a leading `0x` is stripped for ecdsa only.
fn address_bytes(e: &Evidence) -> Result<Vec<u8>, String> {
    let addr = if e.signing_algo == "ecdsa" {
        e.signing_address
            .strip_prefix("0x")
            .unwrap_or(&e.signing_address)
    } else {
        &e.signing_address
    };
    if addr.is_empty() {
        return Err("signing_address is empty".into());
    }
    hex::decode(addr).map_err(|_| "signing_address is not hex".to_string())
}

/// [32..64] == nonce. With a fingerprint: [0..32] == sha256(addr_bytes || fp_bytes), where addr_bytes is
/// `signing_address` hex-decoded (a leading 0x stripped for ecdsa). Without: [0..32] == the 32-byte address.
pub fn check_report_data(
    report_data: &[u8; 64],
    e: &Evidence,
    nonce: &[u8; 32],
) -> Result<(), String> {
    if report_data[32..64] != nonce[..] {
        return Err("report_data does not embed the request nonce".into());
    }
    let addr = address_bytes(e)?;
    let expected: [u8; 32] = match &e.tls_cert_fingerprint {
        Some(fp) => {
            let fp = hex32(fp).map_err(|err| format!("tls_cert_fingerprint: {err}"))?;
            let mut h = Sha256::new();
            h.update(&addr);
            h.update(fp);
            h.finalize().into()
        }
        None => <[u8; 32]>::try_from(addr.as_slice()).map_err(|_| {
            "report_data does not bind the signing key: no tls_cert_fingerprint and the address is not 32 bytes".to_string()
        })?,
    };
    if report_data[0..32] != expected {
        return Err(
            "report_data does not bind the signing address and TLS certificate fingerprint".into(),
        );
    }
    Ok(())
}

/// `info.tcb_info` as a JSON string or object; returns its `app_compose` string.
pub fn app_compose(info: Option<&serde_json::Value>) -> Result<String, String> {
    let info = info.ok_or("entry has no info (app_compose)")?;
    let tcb = info
        .get("tcb_info")
        .ok_or("info has no tcb_info (app_compose)")?;
    let parsed;
    let tcb = match tcb {
        serde_json::Value::String(s) => {
            parsed = serde_json::from_str::<serde_json::Value>(s)
                .map_err(|e| format!("info.tcb_info is not JSON: {e}"))?;
            &parsed
        }
        other => other,
    };
    tcb.get("app_compose")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "info.tcb_info has no app_compose string".to_string())
}

/// Why a compose was accepted; recorded as `compose_acceptance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposeAcceptance {
    /// Listed in `opencode/attestation-policy.json`.
    Pinned,
    /// Endorsed for its role by the signed attestation policy feed.
    Endorsed,
    /// `--compose-policy mr-config-only`: `mr_config_id` vouches for it.
    MrConfigOnly,
    /// Not pinned, but the entry's quote binds a signing key this session
    /// already attested (a NEAR redeploy mid-session, issue #25).
    KeyContinuity,
}

impl ComposeAcceptance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::Endorsed => "endorsed",
            Self::MrConfigOnly => "mr-config-only",
            Self::KeyContinuity => "key-continuity",
        }
    }
}

/// mr_config_id[0] == 0x01 and [1..33] == sha256(app_compose), then the
/// policy in the spec's order: refused if the feed revokes the exact hash
/// (whatever the mode or continuity); `Pinned` if pinned for `role`;
/// `Endorsed` if the feed endorses it for `role` by exact hash, then by its
/// `instance-label-v1` hash; then `--compose-policy`, and under Pinned key
/// continuity: the entry's quote-bound signing key was already attested this
/// session. Returns the hash, why it was accepted, and the endorsement's match.
pub fn check_compose(
    mr_config_id: &[u8; 48],
    app_compose: &str,
    policy: &Policy,
    role: Role,
    mode: ComposePolicy,
    continued: bool,
) -> Result<([u8; 32], ComposeAcceptance, Option<Match>), String> {
    if mr_config_id[0] != 0x01 {
        return Err(format!(
            "mr_config_id starts with {:02x}, not 01 (compose hash)",
            mr_config_id[0]
        ));
    }
    let hash: [u8; 32] = Sha256::digest(app_compose.as_bytes()).into();
    if mr_config_id[1..33] != hash {
        return Err("mr_config_id does not match sha256(app_compose)".into());
    }
    if policy.revoked.contains(&hash) {
        return Err(format!(
            "{} compose hash {} is revoked by the attestation policy feed{}",
            role.as_str(),
            hex::encode(hash),
            policy
                .feed_version
                .map(|v| format!(" (v{v})"))
                .unwrap_or_default()
        ));
    }
    if policy.pinned.get(&hash) == Some(&role) {
        return Ok((hash, ComposeAcceptance::Pinned, None));
    }
    let endorsed = |m: Match, h: [u8; 32]| policy.endorsed.get(&(m, h)) == Some(&role);
    if endorsed(Match::Exact, hash) {
        return Ok((hash, ComposeAcceptance::Endorsed, Some(Match::Exact)));
    }
    // Normalize only when the feed endorses something that way.
    if policy
        .endorsed
        .keys()
        .any(|(m, _)| *m == Match::InstanceLabelV1)
        && super::normalize::instance_label_v1(app_compose)
            .is_some_and(|n| endorsed(Match::InstanceLabelV1, n))
    {
        return Ok((
            hash,
            ComposeAcceptance::Endorsed,
            Some(Match::InstanceLabelV1),
        ));
    }
    let acceptance = if mode == ComposePolicy::MrConfigOnly {
        ComposeAcceptance::MrConfigOnly
    } else if continued {
        ComposeAcceptance::KeyContinuity
    } else {
        return Err(format!(
            "{} compose hash {} is not pinned in this NEAR AI environment's policy, opencode/attestation-policy.json or opencode/attestation-policy-staging.json, nor endorsed for that role by the attestation policy feed (pass --compose-policy mr-config-only to accept it, or see scripts/refresh-attestation-policy.py)",
            role.as_str(),
            hex::encode(hash)
        ));
    };
    Ok((hash, acceptance, None))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::attest::Role;
    use std::collections::BTreeMap;

    pub fn sha(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    pub fn evidence(addr: &str, algo: &str, fp: Option<&str>) -> Evidence {
        Evidence {
            intel_quote: String::new(),
            signing_address: addr.into(),
            signing_algo: algo.into(),
            tls_cert_fingerprint: fp.map(str::to_string),
            nvidia_payload: None,
            info: None,
            model_name: None,
        }
    }

    fn rd(first: [u8; 32], nonce: [u8; 32]) -> [u8; 64] {
        let mut r = [0u8; 64];
        r[..32].copy_from_slice(&first);
        r[32..].copy_from_slice(&nonce);
        r
    }

    #[test]
    fn report_url_asks_for_ed25519_near_and_the_tls_fingerprint() {
        assert_eq!(
            report_url("https://near.test/v1", "org/m 1", &[0xab; 32]),
            format!(
                "https://near.test/v1/attestation/report?model=org%2Fm+1&nonce={}&signing_algo=ed25519&provider=near&include_tls_fingerprint=true",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn report_data_must_bind_key_fingerprint_and_nonce() {
        let key = [7u8; 32];
        let fp = [9u8; 32];
        let nonce = [3u8; 32];
        let e = evidence(&hex::encode(key), "ed25519", Some(&hex::encode(fp)));
        let good = rd(sha(&[&key, &fp]), nonce);
        assert!(check_report_data(&good, &e, &nonce).is_ok());

        for bit in [0usize, 31, 32, 63] {
            let mut bad = good;
            bad[bit] ^= 1;
            assert!(
                check_report_data(&bad, &e, &nonce).is_err(),
                "bit flip at {bit}"
            );
        }
        let other_fp = evidence(&hex::encode(key), "ed25519", Some(&hex::encode([8u8; 32])));
        let err = check_report_data(&good, &other_fp, &nonce).unwrap_err();
        assert!(err.contains("does not bind"), "{err}");
        let err = check_report_data(&rd(sha(&[&key, &fp]), [4u8; 32]), &e, &nonce).unwrap_err();
        assert!(err.contains("nonce"), "{err}");

        let bare = evidence(&hex::encode(key), "ed25519", None);
        assert!(check_report_data(&rd(key, nonce), &bare, &nonce).is_ok());
        let err = check_report_data(&good, &bare, &nonce).unwrap_err();
        assert!(err.contains("does not bind"), "{err}");

        let addr = [0x5au8; 20];
        let gw = evidence(
            &format!("0x{}", hex::encode(addr)),
            "ecdsa",
            Some(&hex::encode(fp)),
        );
        assert!(check_report_data(&rd(sha(&[&addr, &fp]), nonce), &gw, &nonce).is_ok());
        // A 20-byte address cannot use the bare-key mode.
        let gw_bare = evidence(&format!("0x{}", hex::encode(addr)), "ecdsa", None);
        assert!(check_report_data(&rd([0; 32], nonce), &gw_bare, &nonce).is_err());
        // 0x is stripped for ecdsa only.
        let ed_0x = evidence(
            &format!("0x{}", hex::encode(key)),
            "ed25519",
            Some(&hex::encode(fp)),
        );
        assert!(check_report_data(&good, &ed_0x, &nonce).is_err());
        // A malformed fingerprint refuses.
        let short_fp = evidence(&hex::encode(key), "ed25519", Some(&hex::encode([9u8; 31])));
        assert!(check_report_data(&good, &short_fp, &nonce).is_err());
    }

    #[test]
    fn compose_must_match_mr_config_and_the_pinned_list() {
        let compose = "services: {}";
        let hash = sha(&[compose.as_bytes()]);
        let mut mr = [0u8; 48];
        mr[0] = 1;
        mr[1..33].copy_from_slice(&hash);
        let pinned = Policy {
            pinned: BTreeMap::from([(hash, Role::Model)]),
            ..Policy::default()
        };
        let empty = Policy::default();
        let m = Role::Model;

        use ComposeAcceptance as A;
        for continued in [false, true] {
            assert_eq!(
                check_compose(&mr, compose, &pinned, m, ComposePolicy::Pinned, continued),
                Ok((hash, A::Pinned, None))
            );
            assert_eq!(
                check_compose(
                    &mr,
                    compose,
                    &empty,
                    m,
                    ComposePolicy::MrConfigOnly,
                    continued
                ),
                Ok((hash, A::MrConfigOnly, None))
            );
        }
        let err = check_compose(&mr, compose, &empty, m, ComposePolicy::Pinned, false).unwrap_err();
        assert!(err.contains("attestation-policy.json"), "{err}");
        assert_eq!(
            check_compose(&mr, compose, &empty, m, ComposePolicy::Pinned, true),
            Ok((hash, A::KeyContinuity, None))
        );

        // Continuity never excuses a compose that mr_config_id does not commit to.
        let mut mr2 = mr;
        mr2[0] = 2;
        for mode in [ComposePolicy::Pinned, ComposePolicy::MrConfigOnly] {
            for continued in [false, true] {
                let err = check_compose(&mr2, compose, &pinned, m, mode, continued).unwrap_err();
                assert!(err.contains("mr_config_id"), "{err}");
                assert!(
                    check_compose(&mr, "services: {x: 1}", &pinned, m, mode, continued).is_err()
                );
            }
        }
    }

    // ---- Revocation, pins and feed endorsements ----

    use crate::attest::Match;
    use std::collections::BTreeSet;

    const GPU04: &str = include_str!(
        "../../tests/fixtures/compose-history/e3902667a26282dd8b4015a901848c521b20243a155a457148f88acf48a45959.json"
    );
    const GPU02: &str = include_str!(
        "../../tests/fixtures/compose-history/edabf8039210336d90fe966dfc4e48216551dfd8b05d54e96d3f3f0e0da850d4.json"
    );

    /// The raw app_compose a compose-history fixture wraps as a JSON string.
    fn raw(fixture: &str) -> String {
        serde_json::from_str(fixture).unwrap()
    }

    /// The mr_config_id that commits to `compose`, and its hash.
    fn committed(compose: &str) -> ([u8; 48], [u8; 32]) {
        let hash = sha(&[compose.as_bytes()]);
        let mut mr = [0u8; 48];
        mr[0] = 1;
        mr[1..33].copy_from_slice(&hash);
        (mr, hash)
    }

    fn endorsing(m: Match, hash: [u8; 32], role: Role) -> Policy {
        Policy {
            endorsed: BTreeMap::from([((m, hash), role)]),
            feed_version: Some(7),
            ..Policy::default()
        }
    }

    const MODES: [ComposePolicy; 2] = [ComposePolicy::Pinned, ComposePolicy::MrConfigOnly];

    #[test]
    fn revoked_beats_pinned() {
        let compose = "services: {}";
        let (mr, hash) = committed(compose);
        let policy = Policy {
            pinned: BTreeMap::from([(hash, Role::Model)]),
            revoked: BTreeSet::from([hash]),
            feed_version: Some(7),
            ..Policy::default()
        };
        for mode in MODES {
            for continued in [false, true] {
                let err =
                    check_compose(&mr, compose, &policy, Role::Model, mode, continued).unwrap_err();
                assert!(err.contains("revoked"), "{err}");
                assert!(err.contains(&hex::encode(hash)), "{err}");
            }
        }
    }

    #[test]
    fn revoked_beats_endorsed_and_mr_config_only() {
        let compose = raw(GPU02);
        let (mr, hash) = committed(&compose);
        let normalized = crate::attest::normalize::instance_label_v1(&compose).unwrap();
        for (m, h) in [(Match::Exact, hash), (Match::InstanceLabelV1, normalized)] {
            let mut policy = endorsing(m, h, Role::Model);
            policy.revoked.insert(hash);
            for mode in MODES {
                for continued in [false, true] {
                    let err = check_compose(&mr, &compose, &policy, Role::Model, mode, continued)
                        .unwrap_err();
                    assert!(err.contains("revoked"), "{err}");
                }
            }
        }
        // Revocation is by exact hash: revoking the normalized hash alone
        // does not refuse a compose that is endorsed exactly.
        let mut policy = endorsing(Match::Exact, hash, Role::Model);
        policy.revoked.insert(normalized);
        assert_eq!(
            check_compose(
                &mr,
                &compose,
                &policy,
                Role::Model,
                ComposePolicy::Pinned,
                false
            ),
            Ok((hash, ComposeAcceptance::Endorsed, Some(Match::Exact)))
        );
    }

    #[test]
    fn exact_endorsement_admits_as_endorsed() {
        let compose = "services: {}";
        let (mr, hash) = committed(compose);
        for role in [Role::Gateway, Role::Model] {
            let policy = endorsing(Match::Exact, hash, role);
            for mode in MODES {
                for continued in [false, true] {
                    assert_eq!(
                        check_compose(&mr, compose, &policy, role, mode, continued),
                        Ok((hash, ComposeAcceptance::Endorsed, Some(Match::Exact)))
                    );
                }
            }
        }
        assert_eq!(ComposeAcceptance::Endorsed.as_str(), "endorsed");
        // A pin wins over an endorsement of the same hash.
        let mut policy = endorsing(Match::Exact, hash, Role::Model);
        policy.pinned.insert(hash, Role::Model);
        assert_eq!(
            check_compose(
                &mr,
                compose,
                &policy,
                Role::Model,
                ComposePolicy::Pinned,
                false
            ),
            Ok((hash, ComposeAcceptance::Pinned, None))
        );
    }

    #[test]
    fn instance_label_endorsement_admits_the_other_host() {
        let gpu04 = raw(GPU04);
        let gpu02 = raw(GPU02);
        let (mr, hash) = committed(&gpu02);
        let normalized = crate::attest::normalize::instance_label_v1(&gpu04).unwrap();
        let policy = endorsing(Match::InstanceLabelV1, normalized, Role::Model);
        assert_eq!(
            check_compose(
                &mr,
                &gpu02,
                &policy,
                Role::Model,
                ComposePolicy::Pinned,
                false
            ),
            Ok((
                hash,
                ComposeAcceptance::Endorsed,
                Some(Match::InstanceLabelV1)
            ))
        );
        // An exact endorsement of gpu04's raw hash does not admit gpu02.
        let exact = endorsing(Match::Exact, committed(&gpu04).1, Role::Model);
        let err = check_compose(
            &mr,
            &gpu02,
            &exact,
            Role::Model,
            ComposePolicy::Pinned,
            false,
        )
        .unwrap_err();
        assert!(err.contains("not pinned"), "{err}");
        // The normalized hash endorsed as exact does not admit it either.
        let wrong = endorsing(Match::Exact, normalized, Role::Model);
        assert!(
            check_compose(
                &mr,
                &gpu02,
                &wrong,
                Role::Model,
                ComposePolicy::Pinned,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn a_gateway_endorsement_does_not_admit_a_model_and_the_reverse() {
        let compose = raw(GPU02);
        let (mr, hash) = committed(&compose);
        let normalized = crate::attest::normalize::instance_label_v1(&compose).unwrap();
        for (endorsed_as, checked_as) in
            [(Role::Gateway, Role::Model), (Role::Model, Role::Gateway)]
        {
            for (m, h) in [(Match::Exact, hash), (Match::InstanceLabelV1, normalized)] {
                let policy = endorsing(m, h, endorsed_as);
                let err = check_compose(
                    &mr,
                    &compose,
                    &policy,
                    checked_as,
                    ComposePolicy::Pinned,
                    false,
                )
                .unwrap_err();
                assert!(err.contains("not pinned"), "{err}");
                assert!(err.contains(checked_as.as_str()), "{err}");
                assert_eq!(
                    check_compose(
                        &mr,
                        &compose,
                        &policy,
                        endorsed_as,
                        ComposePolicy::Pinned,
                        false
                    )
                    .map(|r| r.1),
                    Ok(ComposeAcceptance::Endorsed)
                );
            }
        }
    }

    #[test]
    fn a_gateway_pin_does_not_admit_a_model() {
        let compose = "services: {}";
        let (mr, hash) = committed(compose);
        let policy = Policy {
            pinned: BTreeMap::from([(hash, Role::Gateway)]),
            ..Policy::default()
        };
        let err = check_compose(
            &mr,
            compose,
            &policy,
            Role::Model,
            ComposePolicy::Pinned,
            false,
        )
        .unwrap_err();
        assert!(err.contains("not pinned"), "{err}");
        assert_eq!(
            check_compose(
                &mr,
                compose,
                &policy,
                Role::Gateway,
                ComposePolicy::Pinned,
                false
            ),
            Ok((hash, ComposeAcceptance::Pinned, None))
        );
        // A model pin does not admit a gateway.
        let policy = Policy {
            pinned: BTreeMap::from([(hash, Role::Model)]),
            ..Policy::default()
        };
        assert!(
            check_compose(
                &mr,
                compose,
                &policy,
                Role::Gateway,
                ComposePolicy::Pinned,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn unendorsed_still_falls_through_to_key_continuity() {
        let compose = raw(GPU02);
        let (mr, hash) = committed(&compose);
        // The feed endorses something else, for this role and the other.
        let mut policy = endorsing(Match::Exact, [0xee; 32], Role::Model);
        policy
            .endorsed
            .insert((Match::InstanceLabelV1, [0xef; 32]), Role::Model);
        policy.endorsed.insert((Match::Exact, hash), Role::Gateway);
        assert_eq!(
            check_compose(
                &mr,
                &compose,
                &policy,
                Role::Model,
                ComposePolicy::Pinned,
                true
            ),
            Ok((hash, ComposeAcceptance::KeyContinuity, None))
        );
        assert_eq!(
            check_compose(
                &mr,
                &compose,
                &policy,
                Role::Model,
                ComposePolicy::MrConfigOnly,
                false
            ),
            Ok((hash, ComposeAcceptance::MrConfigOnly, None))
        );
        assert!(
            check_compose(
                &mr,
                &compose,
                &policy,
                Role::Model,
                ComposePolicy::Pinned,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn app_compose_reads_tcb_info_as_string_or_object() {
        let obj = serde_json::json!({"tcb_info": {"app_compose": "c1"}});
        assert_eq!(app_compose(Some(&obj)), Ok("c1".to_string()));
        let s = serde_json::json!({"tcb_info": "{\"app_compose\":\"c2\\n\"}"});
        assert_eq!(app_compose(Some(&s)), Ok("c2\n".to_string()));
        assert!(app_compose(None).is_err());
        assert!(app_compose(Some(&serde_json::json!({}))).is_err());
        assert!(app_compose(Some(&serde_json::json!({"tcb_info": {}}))).is_err());
        assert!(app_compose(Some(&serde_json::json!({"tcb_info": {"app_compose": 1}}))).is_err());
        assert!(app_compose(Some(&serde_json::json!({"tcb_info": "not json"}))).is_err());
    }

    #[test]
    fn model_entries_must_be_ed25519_with_a_32_byte_key() {
        let key = [7u8; 32];
        assert_eq!(
            ed25519_key(&evidence(&hex::encode(key), "ed25519", None)),
            Ok(key)
        );
        let err = ed25519_key(&evidence(&hex::encode(key), "ecdsa", None)).unwrap_err();
        assert!(err.contains("ed25519"), "{err}");
        assert!(ed25519_key(&evidence(&hex::encode([7u8; 31]), "ed25519", None)).is_err());
        assert!(ed25519_key(&evidence(&"zz".repeat(32), "ed25519", None)).is_err());
    }
}
