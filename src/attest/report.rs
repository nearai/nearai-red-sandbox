//! NEAR AI's attestation report and the pure checks on its entries: the
//! report URL, report_data binding, the compose hash, and the model signing
//! key. Shape from `nearai-cloud-verifier` `ts/model_verifier.ts`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ComposePolicy, Policy};

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

/// mr_config_id[0] == 0x01 and [1..33] == sha256(app_compose); under Pinned the hash must be in the policy.
pub fn check_compose(
    mr_config_id: &[u8; 48],
    app_compose: &str,
    policy: &Policy,
    mode: ComposePolicy,
) -> Result<[u8; 32], String> {
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
    if mode == ComposePolicy::Pinned && !policy.compose_hashes.contains(&hash) {
        return Err(format!(
            "compose hash {} is not pinned in opencode/attestation-policy.json (pass --compose-policy mr-config-only to accept it)",
            hex::encode(hash)
        ));
    }
    Ok(hash)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
            compose_hashes: BTreeSet::from([hash]),
        };
        let empty = Policy {
            compose_hashes: BTreeSet::new(),
        };

        assert_eq!(
            check_compose(&mr, compose, &pinned, ComposePolicy::Pinned),
            Ok(hash)
        );
        let err = check_compose(&mr, compose, &empty, ComposePolicy::Pinned).unwrap_err();
        assert!(err.contains("attestation-policy.json"), "{err}");
        assert_eq!(
            check_compose(&mr, compose, &empty, ComposePolicy::MrConfigOnly),
            Ok(hash)
        );

        let mut mr2 = mr;
        mr2[0] = 2;
        for mode in [ComposePolicy::Pinned, ComposePolicy::MrConfigOnly] {
            let err = check_compose(&mr2, compose, &pinned, mode).unwrap_err();
            assert!(err.contains("mr_config_id"), "{err}");
            assert!(check_compose(&mr, "services: {x: 1}", &pinned, mode).is_err());
        }
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
